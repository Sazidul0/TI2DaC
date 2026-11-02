"""Command-line interface: `ti2dac --help`."""
from __future__ import annotations

import getpass
import json
import sys
from pathlib import Path
from typing import Optional

import typer

from . import attack, obs
from . import sigma_tools as st
from .config import Settings, load_settings
from .feedback import ARTIFACTS, CATEGORIES, REVIEW_STATES, SEVERITIES, TEST_RESULTS, Store
from .ingest import IngestError, load_report
from .llm import LLM, LLMError, estimate_cost
from .render import load_record, render, rule_filename, usage_summary
from .targets import LLM_TARGET_LABELS, TARGETS

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Threat Intelligence -> Sigma -> multi-SIEM queries + safe simulation guides.")
fb_app = typer.Typer(no_args_is_help=True, help="Reviewer feedback on generated artifacts.")
test_app = typer.Typer(no_args_is_help=True, help="Record lab test results / alert dispositions.")
app.add_typer(fb_app, name="feedback")
app.add_typer(test_app, name="test")

_state: dict = {}


@app.callback()
def _main(ctx: typer.Context, config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to ti2dac.yaml"),
          verbose: bool = typer.Option(False, "--verbose", "-v")):
    _state["settings"] = load_settings(config)
    # The web server and CLI commands log to separate files (see obs.setup); terminal output is unchanged.
    obs.setup(_state["settings"], component="web" if ctx.invoked_subcommand == "serve" else "cli", verbose=verbose)
    if ctx.invoked_subcommand not in (None, "serve"):
        obs.event("cli.command", command=ctx.invoked_subcommand, user=getpass.getuser())


def S() -> Settings:
    return _state["settings"]


def _store() -> Store:
    return Store(S().db_path)


def _progress(msg: str) -> None:
    typer.echo(f"  · {msg}", err=True)


def _fail(msg: str, code: int = 1):
    typer.secho(f"error: {msg}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _run_dir(run_id: str) -> Path:
    p = _store().run_path(run_id)
    path = Path(p) if p else Path(S().output_dir) / run_id
    if not (path / "run.json").is_file():
        _fail(f"unknown run {run_id!r} (see `ti2dac runs`)")
    return path


def _actor() -> str:
    """CLI identity = the logged-in OS account. Not a free-text option: an author must not be able to
    approve their own rule by typing someone else's name. (Strong identity comes from the web UI / SSO.)"""
    return getpass.getuser()


def _llm(record) -> LLM | None:
    return LLM(S(), record.usage, tlp=record.report.tlp_effective) if S().ai.enabled else None


def _rerender(record, path: Path) -> None:
    store = _store()
    render(record, path, test_results=store.test_results(record.run_id))
    store.register_run(record, str(path))


def _print_behaviours(record) -> None:
    typer.echo(f"\n{'ID':4} {'SEL':3} {'RANK':>5}  {'TECHNIQUE':11} {'TACTIC':20} {'EVID':5} BEHAVIOUR")
    for b in record.behaviours:
        ev = f"{sum(b.evidence_verified)}/{len(b.evidence)}"
        flag = "" if b.attack_valid else "  [ATT&CK?]"
        typer.echo(f"{b.id:4} {'*' if b.selected else '':3} {b.rank_score:>5}  {b.technique_id:11} {b.tactic:20} {ev:5} {b.name}{flag}")


def _print_usage(record) -> None:
    u = record.usage
    if u.calls or u.cached_calls:
        u.estimated_cost_usd = estimate_cost(u, S().ai.prices)
        typer.echo(f"\nAI usage: {usage_summary(u)}", err=True)


# --------------------------------------------------------------------------- main flows
@app.command()
def run(source: str = typer.Argument(..., help="Report file (HTML/PDF/MD/TXT) or URL"),
        count: int = typer.Option(None, "--count", "-n", help="Behaviours to turn into rules (default 3)"),
        select: str = typer.Option("", "--select", "-s", help="Explicit behaviour IDs, e.g. B1,B4 (re-run uses cached analysis)"),
        no_ai: bool = typer.Option(False, "--no-ai", help="Deterministic mode, no API calls"),
        incident: Optional[bool] = typer.Option(None, "--incident/--threat-intel",
                                                help="Document type (default: auto-detect). Incident reports are "
                                                     "treated as TLP:AMBER unless marked"),
        tlp_override: str = typer.Option("", help="Reason for sending a report above the provider's TLP policy (audited)"),
        events: Optional[Path] = typer.Option(None, "--events", "-e",
                                              help="Incident evidence logs (.evtx/.json/.jsonl) to replay against every "
                                                   "generated rule. Stays local; never sent to the AI"),
        out: Optional[Path] = typer.Option(None, "--out", "-o", help="Output directory (default output/<run-id>)")):
    """Full pipeline: ingest -> analyze -> generate -> validate -> convert -> render package.

    Works for public threat-intel reports and internal incident reports (DOCX/PDF/EML/MD/TXT/CSV). Sensitive data
    is redacted before any AI call and the TLP policy is enforced.
    """
    from .pipeline import run as run_pipeline
    from .replay import ReplayError, load_events

    s = S()
    if no_ai:
        s.ai.enabled = False
    store = _store()
    try:
        evidence = load_events(events) if events else None
        record, loaded = run_pipeline(source, s, count=count, explicit=[x for x in select.split(",") if x] or None,
                                      store=store, progress=_progress, actor=getpass.getuser(), incident=incident,
                                      tlp_override=tlp_override, evidence_events=evidence)
    except (IngestError, LLMError, ReplayError, ValueError, OSError) as e:
        _fail(str(e))
    path = out or Path(s.output_dir) / record.run_id
    render(record, path, raw=loaded.raw, filename=loaded.filename, test_results=store.test_results(record.run_id),
           redaction_map=loaded.redaction_map, embedded_events=loaded.embedded_events)
    store.register_run(record, str(path))
    _print_behaviours(record)
    for p in record.packages:
        ok = sum(1 for q in p.queries if q.query)
        ev = f" incident-evidence={p.evidence_matches}/{p.evidence_total}" if p.evidence_matches >= 0 else ""
        typer.echo(f"  {p.slug}  {p.behaviour.technique_id:10} sigma={p.sigma_status:17} self-test={p.selftest:4}{ev} "
                   f"queries={ok}/{len(p.queries)} sim={'BLOCKED' if p.sim_blocked else 'ok'}  {p.draft.sigma.title}")
        for w in p.quality_warnings + [f"self-test: {d}" for d in p.selftest_details if p.selftest == "fail"] \
                + [f"similar existing rule: {x}" for x in p.similar_rules]:
            typer.secho(f"      ! {w}", fg=typer.colors.YELLOW, err=True)
    for w in record.warnings:
        typer.secho(f"  ! {w}", fg=typer.colors.YELLOW, err=True)
    _print_usage(record)
    typer.echo(f"\nPackage: {path}/report-summary.md\nRun id:  {record.run_id}")


@app.command()
def analyze(source: str, no_ai: bool = typer.Option(False, "--no-ai"),
            incident: Optional[bool] = typer.Option(None, "--incident/--threat-intel",
                                                help="Document type (default: auto-detect). Incident reports are "
                                                     "treated as TLP:AMBER unless marked"),
        tlp_override: str = typer.Option("", help="Reason for sending a report above the provider's TLP policy (audited)"),
            ):
    """Stage 1 only: extract and rank behaviours, then pick with `ti2dac generate RUN --select`."""
    from .llm import LLM
    from .pipeline import analyze as analyze_report, prepare_report, select as select_behaviours

    s = S()
    if no_ai:
        s.ai.enabled = False
    attack.set_override_dir(s.state_dir)
    try:
        loaded = load_report(source, s.fetch)
        prepare_report(loaded, s, incident=incident, tlp_override=tlp_override, progress=_progress)  # redaction + TLP
        record, _ = analyze_report(loaded, s, LLM(s, tlp=loaded.meta.tlp_effective) if s.ai.enabled else None, _progress)
    except (IngestError, LLMError, ValueError) as e:
        _fail(str(e))
    record.created_by = getpass.getuser()
    if tlp_override:
        record.warnings.append(f"TLP policy overridden by {record.created_by}: {tlp_override}")
        _store().audit(record.created_by, "tlp.override", {"run_id": record.run_id, "reason": tlp_override})
    select_behaviours(record.behaviours, s.select_count)
    path = Path(s.output_dir) / record.run_id
    store = _store()
    render(record, path, raw=loaded.raw, filename=loaded.filename, redaction_map=loaded.redaction_map,
           embedded_events=loaded.embedded_events)
    store.register_run(record, str(path))
    _print_behaviours(record)
    for w in record.warnings:
        typer.secho(f"  ! {w}", fg=typer.colors.YELLOW, err=True)
    _print_usage(record)
    typer.echo(f"\nRun id: {record.run_id}\nNext:   ti2dac generate {record.run_id} --select "
               + ",".join(b.id for b in record.behaviours if b.selected))


@app.command()
def generate(run_id: str, select: str = typer.Option(..., "--select", "-s", help="Behaviour IDs, e.g. B1,B3")):
    """Stage 2 for chosen behaviours of an analysed run (adds rules; existing ones are kept)."""
    from .pipeline import generate as gen

    s = S()
    if not s.ai.enabled:
        _fail("generation needs AI; write rules by hand and use `ti2dac convert`")
    from .pipeline import check_tlp_for_run

    path = _run_dir(run_id)
    record = load_record(path)
    try:
        check_tlp_for_run(record, s)
    except ValueError as e:
        _fail(str(e))
    ids = [x.strip().upper() for x in select.split(",") if x.strip()]
    unknown = set(ids) - {b.id for b in record.behaviours}
    if unknown:
        _fail(f"unknown behaviour id(s): {', '.join(sorted(unknown))}")
    for b in record.behaviours:
        b.selected = b.selected or b.id in ids
    llm = LLM(s, record.usage, tlp=record.report.tlp_effective)
    try:
        gen(record, s, llm, _store(), _progress, behaviour_ids=ids, actor=getpass.getuser())
    except LLMError as e:
        _fail(str(e))
    _rerender(record, path)
    for p in record.packages:
        typer.echo(f"  {p.slug}  {p.behaviour.technique_id:10} sigma={p.sigma_status} {p.draft.sigma.title}")
    _print_usage(record)


# --------------------------------------------------------------------------- deterministic tools
@app.command()
def convert(rules: list[Path], targets: str = typer.Option("", "--targets", "-t", help="Comma list; default from config"),
            out: Optional[Path] = typer.Option(None, "--out", "-o")):
    """Convert existing Sigma rule files to all configured SIEMs (no AI)."""
    tids = [t for t in targets.split(",") if t] or S().targets
    for rule in rules:
        text = rule.read_text()
        ok, issues = st.validate_rule(text)
        typer.secho(f"# {rule}  ({'valid' if ok else 'INVALID'})", bold=True)
        for i in issues:
            typer.echo(f"  {i}")
        if not ok:
            continue
        for q in st.convert(text, tids, S().index_overrides):
            if out:
                d = out / rule.stem
                d.mkdir(parents=True, exist_ok=True)
                if q.query:
                    (d / f"{q.target}.{TARGETS[q.target].ext.rsplit('.', 1)[-1]}").write_text(q.query + "\n")
            typer.echo(f"\n## {q.label}\n{q.query or 'ERROR: ' + str(q.error)}")
        typer.echo("")


@app.command()
def check(rules: list[Path]):
    """Validate Sigma rules (same validators as `sigma check`)."""
    bad = 0
    for rule in rules:
        ok, issues = st.validate_rule(rule.read_text())
        bad += not ok
        typer.echo(f"{'OK  ' if ok and not issues else 'WARN' if ok else 'FAIL'} {rule}")
        for i in issues:
            typer.echo(f"     {i}")
    raise typer.Exit(1 if bad else 0)


@app.command("lint-sim")
def lint_sim(script: Path, cleanup: Optional[Path] = typer.Option(None, "--cleanup")):
    """Run the simulation safety linter on a script."""
    from .safety import lint_script

    findings = lint_script(script.read_text(), cleanup.read_text() if cleanup else "")
    for f in findings:
        typer.echo(f"{f.severity.upper():5} {f.rule:22} line {f.line}: {f.text}")
    if not findings:
        typer.echo("no findings")
    raise typer.Exit(1 if any(f.severity == "block" for f in findings) else 0)


@app.command("targets")
def list_targets():
    """List SIEM targets (deterministic pySigma backends and AI-only targets)."""
    for t in TARGETS.values():
        typer.echo(f"{t.id:24} {t.language:7} {t.label}")
    typer.echo("\nAI-translated (opt-in via llm_targets, flagged unverified):")
    for k, (label, lang) in LLM_TARGET_LABELS.items():
        typer.echo(f"{k:24} {lang:7} {label}")


@app.command()
def runs():
    """List generated runs."""
    for r in _store().list_runs():
        typer.echo(f"{r['run_id']:70} {r['created_at']}  {r['title'][:60]}")


@app.command("render")
def rerender(run_id: str, recheck: bool = typer.Option(
        False, "--recheck", help="Also re-run validation, conversion, field mapping, self-tests and the safety lint "
                                 "with the current ti2dac version (no AI calls, no tokens)")):
    """Re-render a run's package (after tests/feedback, or after upgrading ti2dac). No AI."""
    from .pipeline import finalize_package

    path = _run_dir(run_id)
    record = load_record(path)
    if recheck:
        for p in record.packages:
            ai_queries = [q for q in p.queries if q.method == "llm"]     # keep earlier AI translations
            finalize_package(p, record, S(), None, allow_repair=False)
            have = {q.target for q in p.queries}
            p.queries += [q for q in ai_queries if q.target not in have]
            typer.echo(f"  {p.slug}: sigma={p.sigma_status} self-test={p.selftest} "
                       f"queries={sum(1 for q in p.queries if q.query)}/{len(p.queries)} sim={'BLOCKED' if p.sim_blocked else 'ok'}")
    _rerender(record, path)
    typer.echo(f"re-rendered {path}")


@app.command("attack-update")
def attack_update(source: Optional[str] = typer.Option(None, help="Local enterprise-attack.json or URL")):
    """Refresh the local MITRE ATT&CK index from the official STIX data."""
    p = attack.update_index(S().state_dir, source)
    attack.set_override_dir(S().state_dir)
    idx = attack.load_index()
    typer.echo(f"ATT&CK {idx['attack_version']}: {len(idx['techniques'])} techniques -> {p}")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000):
    """Start the web UI (add users with `ti2dac user add` to require login and enable roles)."""
    import os

    import uvicorn

    from .web.app import create_app

    from .users import Users

    if host not in ("127.0.0.1", "localhost", "::1") and not (Users(S().state_dir).any() or os.environ.get("TI2DAC_WEB_PASSWORD")):
        _fail("refusing to listen on a non-loopback address without users (`ti2dac user add`) or "
              "TI2DAC_WEB_USER/TI2DAC_WEB_PASSWORD")
    uvicorn.run(create_app(S()), host=host, port=port)


# --------------------------------------------------------------------------- feedback
@fb_app.command("add")
def feedback_add(run_id: str, slug: str,
                 artifact: str = typer.Option(..., help="|".join(ARTIFACTS)),
                 category: str = typer.Option(..., help="|".join(CATEGORIES)),
                 severity: str = typer.Option("medium", help="|".join(SEVERITIES)),
                 comment: str = typer.Option("", help="What is wrong and why"),
                 target: str = typer.Option("", help="SIEM target id when artifact=query"),
                 correction_file: Optional[Path] = typer.Option(None, help="Corrected artifact (Sigma YAML for sigma_rule)")):
    """Record feedback. A corrected Sigma rule is validated and becomes the next rule version."""
    reviewer = _actor()
    from .pipeline import apply_correction

    path = _run_dir(run_id)
    record = load_record(path)
    pkg = next((p for p in record.packages if p.slug == slug), None)
    if pkg is None:
        _fail(f"{slug} not in run {run_id}")
    store = _store()
    correction = correction_file.read_text() if correction_file else ""
    try:
        fid = store.add_feedback(reviewer=reviewer, run_id=run_id, slug=slug, rule_id=pkg.rule_id, rule_version=pkg.version,
                                 artifact=artifact, category=category, severity=severity, comment=comment,
                                 correction=correction, target=target)
    except ValueError as e:
        _fail(str(e))
    typer.echo(f"feedback #{fid} recorded")
    if correction and artifact == "sigma_rule":
        try:
            new = apply_correction(record, slug, S(), corrected_yaml=correction, llm=_llm(record), progress=_progress,
                                   actor=reviewer)
        except ValueError as e:
            store.resolve_feedback(fid, "open", f"correction rejected: {e}", reviewer)
            _fail(f"correction not applied: {e}")
        fb = store.get_feedback(fid)
        store.resolve_feedback(fid, "applied", f"rule {slug} -> v{new.version}", reviewer)
        store.add_lesson(fb, new.behaviour.technique_id, new.draft.sigma.logsource.product,
                         new.draft.sigma.logsource.category or new.draft.sigma.logsource.service)
        _rerender(record, path)
        typer.echo(f"applied: {slug} is now v{new.version} (review status reset to draft)")


@fb_app.command("list")
def feedback_list(run_id: str = typer.Option(None, "--run"), status: str = typer.Option(None)):
    for f in _store().list_feedback(run_id, None, status):
        typer.echo(f"#{f['id']:<4} {f['status']:8} {f['severity']:8} {f['run_id'][:40]:40} {f['slug']} v{f['rule_version']} "
                   f"{f['artifact']}/{f['category']}: {f['comment'][:80]}")


@fb_app.command("apply")
def feedback_apply(fid: int, ai: bool = typer.Option(False, "--ai", help="Let the model rewrite the rule from the comment"),
                   correction_file: Optional[Path] = typer.Option(None)):
    """Apply open feedback: from a corrected file, or with --ai from the comment (result is a new draft version)."""
    reviewer = _actor()
    from .pipeline import apply_correction

    store = _store()
    fb = store.get_feedback(fid)
    if not fb:
        _fail(f"no feedback #{fid}")
    if fb["status"] != "open":
        _fail(f"feedback #{fid} is already {fb['status']}")
    path = _run_dir(fb["run_id"])
    record = load_record(path)
    correction = correction_file.read_text() if correction_file else (fb["correction"] or "")
    try:
        if correction:
            new = apply_correction(record, fb["slug"], S(), corrected_yaml=correction, llm=_llm(record), progress=_progress,
                                   actor=reviewer)
        elif ai:
            llm = LLM(S(), record.usage, tlp=record.report.tlp_effective)
            text = f"[{fb['category']}] {fb['comment']}" + (f" (SIEM: {fb['target']})" if fb["target"] else "")
            new = apply_correction(record, fb["slug"], S(), feedback_text=text, llm=llm, progress=_progress, actor=reviewer)
        else:
            _fail("provide --correction-file or --ai")
    except (ValueError, LLMError) as e:
        _fail(str(e))
    store.resolve_feedback(fid, "applied", f"{fb['slug']} -> v{new.version}{' (AI)' if ai and not correction else ''}", reviewer)
    store.add_lesson(fb, new.behaviour.technique_id, new.draft.sigma.logsource.product,
                     new.draft.sigma.logsource.category or new.draft.sigma.logsource.service)
    _rerender(record, path)
    typer.echo(f"applied #{fid}: {fb['slug']} is now v{new.version}; review it before approving.\n")
    typer.echo(new.rule_yaml)


@fb_app.command("resolve")
def feedback_resolve(fid: int, status: str = typer.Option(..., help="applied|rejected|wontfix"),
                     note: str = typer.Option(""), lesson: bool = typer.Option(False, help="Also store as a lesson")):
    """Close feedback manually (e.g. fixed outside the tool, or not a real problem)."""
    reviewer = _actor()
    store = _store()
    fb = store.get_feedback(fid)
    if not fb:
        _fail(f"no feedback #{fid}")
    store.resolve_feedback(fid, status, note, reviewer)
    if lesson:
        record = load_record(_run_dir(fb["run_id"]))
        p = next(p for p in record.packages if p.slug == fb["slug"])
        store.add_lesson(fb, p.behaviour.technique_id, p.draft.sigma.logsource.product, p.draft.sigma.logsource.category)
    typer.echo(f"#{fid} -> {status}")


@fb_app.command("export")
def feedback_export(out: Path = typer.Argument(Path("feedback.jsonl"))):
    """Export all feedback (with current artifacts) as JSONL for evaluation datasets."""
    n = _store().export_jsonl(out)
    typer.echo(f"wrote {n} records to {out}")


@app.command()
def lessons(disable: int = typer.Option(None), enable: int = typer.Option(None)):
    """List the lessons fed back into generation prompts; enable/disable individual ones."""
    store = _store()
    if disable is not None:
        store.set_lesson_active(disable, False, getpass.getuser())
    if enable is not None:
        store.set_lesson_active(enable, True, getpass.getuser())
    for l in store.list_lessons():
        typer.echo(f"#{l['id']:<4} {'on ' if l['active'] else 'off'} {l['technique_id']:10} {l['product']}/{l['category']}: {l['text']}")


# --------------------------------------------------------------------------- tests / review
@test_app.command("record")
def test_record(run_id: str, slug: str, target: str = typer.Option(..., help="SIEM target id, or 'all'"),
                result: str = typer.Option(..., help="|".join(TEST_RESULTS)),
                fp_count: int = typer.Option(0), evidence: str = typer.Option(""), environment: str = typer.Option("")):
    """Record a positive/negative test result or a production alert disposition."""
    tester = _actor()
    path = _run_dir(run_id)
    record = load_record(path)
    pkg = next((p for p in record.packages if p.slug == slug), None)
    if pkg is None:
        _fail(f"{slug} not in run {run_id}")
    valid_targets = {q.target for q in pkg.queries} | {"all", "sigma_replay"}
    if target not in valid_targets:
        _fail(f"target must be one of {sorted(valid_targets)}")
    try:
        _store().add_test_result(tester=tester, run_id=run_id, slug=slug, rule_version=pkg.version, target=target,
                                 result=result, fp_count=fp_count, evidence=evidence, environment=environment)
    except ValueError as e:
        _fail(str(e))
    _rerender(record, path)
    typer.echo(f"recorded; see {path}/validation/validation-matrix.md")


@app.command()
def review(run_id: str, slug: str, status: str = typer.Option(..., help="|".join(REVIEW_STATES)), note: str = typer.Option("")):
    """Set the human review status of a rule (approved rules move Sigma status experimental -> test)."""
    reviewer = _actor()
    from .pipeline import review_problem

    path = _run_dir(run_id)
    record = load_record(path)
    pkg = next((p for p in record.packages if p.slug == slug), None)
    if pkg is None:
        _fail(f"{slug} not in run {run_id}")
    if status not in REVIEW_STATES:
        _fail(f"status must be one of {REVIEW_STATES}")
    from .users import Users

    roles = Users(S().state_dir).list()
    if status == "approved" and roles and roles.get(reviewer) not in ("approver", "admin"):
        _fail(f"{reviewer} is not an approver (configured users: `ti2dac user list`)")
    problem = review_problem(pkg, status, reviewer)
    if problem:
        _fail(problem)
    pkg.review_status = status  # type: ignore[assignment]
    sigma_status = "test" if status == "approved" else "experimental"
    pkg.rule_yaml = st.set_status(pkg.rule_yaml, sigma_status)
    _store().set_review(run_id, slug, status, reviewer, note)
    _rerender(record, path)
    typer.echo(f"{slug}: review={status}, sigma status={sigma_status} ({path}/rules/{rule_filename(pkg)})")


@app.command("model")
def model_cmd(model: str = typer.Argument("", help="Model id to use, e.g. claude-sonnet-5-5. Omit to list the choices"),
              provider: str = typer.Option("", "--provider", "-p", help="anthropic or gemini (default: the active provider)"),
              stage: list[str] = typer.Option([], "--stage", help="Only these stages (analyze, generate, repair, translate); "
                                                                  "repeat the option for several. Default: every stage"),
              refresh: bool = typer.Option(False, "--refresh", help="Fetch the models your key can use first (no tokens)")):
    """Show or choose the AI model. Same setting as the web AI page; TI2DAC_PROVIDER / TI2DAC_MODEL still win."""
    from . import modelchoice
    from .config import STAGES

    s = S()
    prov = provider or s.ai.provider
    if prov not in modelchoice.PROVIDER_LABELS:
        _fail(f"unknown provider {prov!r} (anthropic or gemini)")
    if refresh:
        ok, msg = modelchoice.refresh(s, prov)
        (typer.echo if ok else lambda m: typer.secho(m, fg=typer.colors.YELLOW, err=True))(msg)
    if not model:
        cur = modelchoice.current(s, prov)
        typer.echo(f"{modelchoice.PROVIDER_LABELS[prov]}{'  (active provider)' if prov == s.ai.provider else ''}")
        typer.echo("in use: " + ", ".join(f"{k}={v}" for k, v in cur.items()))
        for m in modelchoice.available(s, prov):
            mark = "*" if m["id"] in cur.values() else " "
            typer.echo(f" {mark} {m['id']:28} {m['price']:28} {m['note']}")
        if modelchoice.env_locks():
            typer.secho(f"note: {', '.join(modelchoice.env_locks())} set in the environment override the saved choice",
                        fg=typer.colors.YELLOW, err=True)
        return
    bad = [x for x in stage if x not in STAGES]
    if bad:
        _fail(f"unknown stage(s): {', '.join(bad)} (use {', '.join(STAGES)})")
    models = modelchoice.current(s, prov)
    models.update({k: model for k in (stage or STAGES)})
    try:
        new = modelchoice.choose(s, prov, models, _actor())
    except ValueError as e:
        _fail(str(e))
    _store().audit(_actor(), "ai.models.set", {"provider": prov, "models": models})
    _state["settings"] = new
    typer.echo(f"{modelchoice.PROVIDER_LABELS[prov]} is the active provider: "
               + ", ".join(f"{k}={getattr(new.ai, k).model}" for k in STAGES))
    if modelchoice.env_locks():
        typer.secho(f"note: {', '.join(modelchoice.env_locks())} set in the environment still override this",
                    fg=typer.colors.YELLOW, err=True)


@app.command("health")
def health_cmd(as_json: bool = typer.Option(False, "--json", help="Machine-readable output")):
    """Database, disk space, AI provider and stuck jobs (same checks as /healthz). Exit code 1 when a check fails."""
    from . import health

    result = health.check(S(), _store())
    if as_json:
        typer.echo(json.dumps(result, indent=1))
    else:
        for name, c in result["checks"].items():
            detail = c.get("message") or ", ".join(f"{k}={v}" for k, v in c.items() if k != "status")
            typer.secho(f"{c['status']:5} {name:12} {detail}",
                        fg={"ok": typer.colors.GREEN, "warn": typer.colors.YELLOW}.get(c["status"], typer.colors.RED))
        typer.echo(f"overall: {result['status']}")
    if result["status"] == "fail":
        raise typer.Exit(1)


@app.command("ai-status")
def ai_status(reset: bool = typer.Option(False, "--reset", help="Clear a pause after fixing the cause (new key, quota reset)")):
    """Show the AI provider's health: key configured?, limits hit, requests today. Never prints the key."""
    from . import aistatus

    s = S()
    prov = s.ai.provider
    if reset:
        aistatus.reset(s.state_dir, prov)
        _store().audit(_actor(), "ai.reset", {"provider": prov})
        typer.echo(f"{prov}: pause cleared")
    st = aistatus.provider_status(s.state_dir, prov)
    blocked = aistatus.block_reason(s.state_dir, prov, s.ai.daily_request_limit)
    cap = f"/{s.ai.daily_request_limit}" if s.ai.daily_request_limit else " (no cap)"
    typer.echo(f"provider       : {prov}  (AI {'enabled' if s.ai.enabled else 'disabled'})")
    typer.echo(f"models         : " + ", ".join(f"{k}={getattr(s.ai, k).model}" for k in ("analyze", "generate", "repair", "translate")))
    typer.echo(f"credentials    : {aistatus.key_status(prov)}")
    typer.echo(f"state          : {st.get('state', 'ok')}" + (f"  (resets in {aistatus.human_wait(st['retry_at'])})" if st.get("retry_at") else ""))
    typer.echo(f"requests today : {st.get('requests_today', 0)}{cap}")
    typer.echo(f"tokens today   : in {st.get('input_tokens_today', 0):,} / out {st.get('output_tokens_today', 0):,}"
               f"  (est. ${st.get('cost_today_usd', 0):.4f})")
    typer.echo(f"tokens total   : in {st.get('input_tokens_total', 0):,} / out {st.get('output_tokens_total', 0):,}"
               f"  (est. ${st.get('cost_total_usd', 0):.4f})")
    if st.get("last_success"):
        typer.echo(f"last success   : {st['last_success']}")
    if st.get("message"):
        typer.echo(f"last error     : {st['message'][:300]}")
    if blocked:
        typer.secho(f"\nAI calls are PAUSED (no requests will be sent): {blocked}", fg=typer.colors.YELLOW)
    if aistatus.key_status(prov) == "not configured":
        typer.echo("\nSet up a key: see README 'Setting up an AI provider' or put it in a .env file (git-ignored).")


# --------------------------------------------------------------------------- validation against real logs
@app.command()
def replay(events: Path = typer.Option(..., "--events", "-e", help="Lab telemetry: .json, .jsonl or .evtx"),
           run_id: str = typer.Option("", "--run", help="Run id (with --rule-slug)"),
           slug: str = typer.Option("", "--rule-slug", help="e.g. rule-001"),
           rule: Optional[Path] = typer.Option(None, "--rule", help="Or a Sigma rule file"),
           expect: str = typer.Option("", help="'match' (positive test) or 'nomatch' (negative test)"),
           record_result: bool = typer.Option(False, "--record", help="Record the outcome in the validation matrix")):
    """Evaluate a rule locally against exported lab events (fired / not fired) before any SIEM is involved."""
    tester = _actor()
    from .replay import ReplayError, evaluate, load_events

    pkg = record = path = None
    if rule:
        rule_yaml = rule.read_text()
    elif run_id and slug:
        path = _run_dir(run_id)
        record = load_record(path)
        pkg = next((p for p in record.packages if p.slug == slug), None)
        if pkg is None:
            _fail(f"{slug} not in run {run_id}")
        rule_yaml = pkg.rule_yaml
    else:
        _fail("give --rule FILE or --run RUN --rule-slug SLUG")
    try:
        evs = load_events(events)
        hits = evaluate(rule_yaml, evs)
    except (ReplayError, ValueError, OSError) as e:
        _fail(str(e))
    typer.echo(f"{len(hits)} of {len(evs)} events matched")
    for i in hits[:20]:
        e = evs[i]
        typer.echo(f"  #{i}: " + ", ".join(f"{k}={str(v)[:80]}" for k, v in list(e.items())[:6]))
    ok = True
    if expect == "match":
        ok = bool(hits)
    elif expect == "nomatch":
        ok = not hits
    if record_result and pkg is not None and expect:
        result = ("fired" if hits else "not_fired") if expect == "match" else ("quiet" if not hits else "false_positive")
        _store().add_test_result(tester=tester, run_id=run_id, slug=slug, rule_version=pkg.version, target="sigma_replay",
                                 result=result, fp_count=len(hits) if expect == "nomatch" else 0,
                                 evidence=f"local replay of {events.name}: {len(hits)}/{len(evs)} matched",
                                 environment="ti2dac replay")
        _rerender(record, path)
        typer.echo(f"recorded {result} (target sigma_replay)")
    raise typer.Exit(0 if ok else 1)


@app.command("rule-test")
def rule_test(rules_dir: Path, tests_dir: Path):
    """CI unit test: every rules/**/<name>.yml with tests/<name>.json must match its positive and ignore its
    negative test events (format written by `ti2dac export`)."""
    from .models import TestEvent
    from .replay import selftest

    failures = tested = 0
    for rule in sorted(rules_dir.rglob("*.yml")):
        tf = tests_dir / f"{rule.stem}.json"
        if not tf.is_file():
            typer.echo(f"SKIP {rule} (no {tf.name})")
            continue
        events = [TestEvent.model_validate(e) for e in json.loads(tf.read_text())]
        status, problems = selftest(rule.read_text(), events)
        tested += 1
        failures += status != "pass"
        typer.echo(f"{status.upper():4} {rule}")
        for pr in problems:
            typer.echo(f"     {pr}")
    typer.echo(f"{tested} rule(s) tested, {failures} failure(s)")
    raise typer.Exit(1 if failures else 0)


# --------------------------------------------------------------------------- detection-as-code export
@app.command()
def export(run_id: str, repo: Path = typer.Option(..., "--repo", help="Detection-as-code repository root"),
           include_drafts: bool = typer.Option(False, help="Also export rules not yet approved")):
    """Copy approved rules, queries, tests, simulations and ADS docs into a Git detection repository."""
    import shutil

    from .render import _kebab

    path = _run_dir(run_id)
    record = load_record(path)
    exported = 0
    for p in record.packages:
        if p.review_status != "approved" and not include_drafts:
            typer.echo(f"skip {p.slug} (review status {p.review_status}; approve it or pass --include-drafts)")
            continue
        ls = st.first_doc(p.rule_yaml).get("logsource") or {}
        name = _kebab(p.draft.sigma.title, 80)
        rule_dir = repo / "rules" / (ls.get("product") or "generic") / (ls.get("category") or ls.get("service") or "misc")
        rule_dir.mkdir(parents=True, exist_ok=True)
        (rule_dir / f"{name}.yml").write_text(p.rule_yaml)
        tests = repo / "tests"
        tests.mkdir(parents=True, exist_ok=True)
        (tests / f"{name}.json").write_text(json.dumps([e.model_dump() for e in p.draft.test_events], indent=1))
        for q in p.queries:
            if q.query:
                qd = repo / "queries" / q.target
                qd.mkdir(parents=True, exist_ok=True)
                ext = TARGETS[q.target].ext.rsplit(".", 1)[-1] if q.target in TARGETS else "txt"
                (qd / f"{name}.{ext}").write_text(q.query + "\n")
        sim_src = path / "simulations" / p.slug
        if sim_src.is_dir():
            shutil.copytree(sim_src, repo / "simulations" / name, dirs_exist_ok=True)
        ads = path / "documentation" / f"{p.slug}-ads.md"
        if ads.is_file():
            (repo / "docs").mkdir(parents=True, exist_ok=True)
            shutil.copy(ads, repo / "docs" / f"{name}-ads.md")
        exported += 1
        typer.echo(f"exported {p.slug} -> {rule_dir / (name + '.yml')}")
    ci = repo / ".github" / "workflows" / "detections.yml"
    if exported and not ci.exists():
        ci.parent.mkdir(parents=True, exist_ok=True)
        ci.write_text((Path(__file__).parent / "data" / "detections-ci.yml").read_text())
        typer.echo(f"wrote CI workflow {ci}")
    typer.echo(f"{exported} rule(s) exported. Commit on a branch and open a pull request for review.")


@app.command("sigmahq-sync")
def sigmahq_sync():
    """Download the SigmaHQ rule pack index used to flag duplicates of existing public rules."""
    from .duplicates import sync_sigmahq

    out, n = sync_sigmahq(S().state_dir)
    typer.echo(f"indexed {n} SigmaHQ rules -> {out}")


# --------------------------------------------------------------------------- users (web UI)
user_app = typer.Typer(no_args_is_help=True, help="Web UI users and roles (analyst, approver, admin).")
app.add_typer(user_app, name="user")


@user_app.command("add")
def user_add(name: str, role: str = typer.Option("analyst", help="analyst | approver | admin")):
    from .users import Users

    pw = typer.prompt("password (min 12 chars)", hide_input=True, confirmation_prompt=True)
    try:
        Users(S().state_dir).add(name, pw, role)
    except ValueError as e:
        _fail(str(e))
    _store().audit(getpass.getuser(), "user.add", {"name": name, "role": role})
    typer.echo(f"user {name} ({role}) saved")


@user_app.command("list")
def user_list():
    from .users import Users

    for n, r in Users(S().state_dir).list().items():
        typer.echo(f"{n:24} {r}")


@user_app.command("remove")
def user_remove(name: str):
    from .users import Users

    if not Users(S().state_dir).remove(name):
        _fail(f"no user {name}")
    _store().audit(getpass.getuser(), "user.remove", {"name": name})
    typer.echo(f"removed {name}")


if __name__ == "__main__":
    app()
