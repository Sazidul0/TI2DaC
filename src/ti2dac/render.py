"""Write the detection package to disk (layout from IMPLEMENTATION_PLAN.md section 2).

Everything here is deterministic templating over the RunRecord + test results, so the
package can be re-rendered at any time (after feedback, tests, reviews) at zero token cost.
"""
from __future__ import annotations

import json
import re
import shutil
import uuid
from pathlib import Path

import yaml

from . import attack, safety
from . import sigma_tools as st
from .feedback import CATEGORIES, TEST_RESULTS, target_status
from .models import ChainPackage, DetectionPackage, QueryResult, RunRecord, Usage
from .targets import TARGETS

LAB_BANNER = ("> **LAB ONLY.** Run only in an isolated, snapshotted lab VM that does not forward to a production "
              "SIEM. Never run against production systems or with real customer data. The scripts refuse to run "
              "unless `TI2DAC_LAB=1` is set.")


def _cell(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _kebab(s: str, n: int = 50) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:n] or "rule"


def rule_filename(p: DetectionPackage) -> str:
    return f"{p.slug}-{_kebab(p.draft.sigma.title)}.yml"


def save_record(record: RunRecord, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / "run.json"
    path.write_text(record.model_dump_json(indent=1))
    return path


def load_record(out: Path) -> RunRecord:
    from .llm import price

    record = RunRecord.model_validate_json((Path(out) / "run.json").read_text())
    u = record.usage
    if not u.unpriced_models:   # runs recorded before unpriced models were tracked showed them as $0
        u.unpriced_models = sorted({str(s.get("model_price_key")) for s in u.by_stage.values()
                                    if s.get("calls") and "cost_usd" not in s and price(str(s.get("model_price_key", ""))) is None})
    return record


def _status_label(p: DetectionPackage, results: list[dict]) -> dict[str, str]:
    labels = {}
    for q in p.queries:
        tested, fp, _ = target_status(results, q.target, p.version)
        if tested:
            labels[q.target] = tested
        elif q.error:
            err = q.error.lower()
            labels[q.target] = ("unsupported logsource" if "does not support logsource" in err
                                else "unsupported field" if "field" in err or "support" in err else "conversion-failed")
        elif q.method == "llm":
            labels[q.target] = "ai-translated (unverified)"
        elif "Backend warning" in q.notes:
            labels[q.target] = "converted, check backend warning"
        elif "not mapped" in q.notes:
            labels[q.target] = "converted, verify field names"
        else:
            labels[q.target] = "converted, not-tested"
    replay_status = target_status(results, "sigma_replay", p.version)[0]
    if replay_status:
        labels["sigma_replay"] = replay_status
    return labels


# --------------------------------------------------------------------------- top level
def render(record: RunRecord, out: Path, *, raw: bytes | None = None, filename: str | None = None,
           test_results: list[dict] | None = None, redaction_map: dict | None = None,
           embedded_events: list[dict] | None = None) -> Path:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    results = test_results or []
    for sub in ("rules", "queries", "simulations", "validation", "documentation", "attack-navigator", "tests", "chains"):
        if (out / sub).exists():
            shutil.rmtree(out / sub)
        (out / sub).mkdir(parents=True)

    if raw is not None:
        src = out / "source"
        src.mkdir(exist_ok=True)
        (src / (filename or "report.bin")).write_bytes(raw)
        (src / "SHA256SUMS").write_text(f"{record.report.sha256}  {filename or 'report.bin'}\n")
    if redaction_map:
        src = out / "source"
        src.mkdir(exist_ok=True)
        (src / "redaction-map.json").write_text(json.dumps(redaction_map, indent=1, ensure_ascii=False))
        (src / "README-SENSITIVE.txt").write_text(
            "This folder holds the ORIGINAL report and the redaction map (placeholder -> real host/user/IP/org).\n"
            "Treat it at the report's TLP marking. Do not share it with the detection package; `ti2dac export`\n"
            "and the web download leave it out.\n")
    if embedded_events:
        ev = out / "evidence"
        ev.mkdir(exist_ok=True)
        (ev / "embedded-events.jsonl").write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in embedded_events) + "\n")

    for p in record.packages:      # re-apply the CURRENT safety rules, so linter fixes reach existing runs
        sim = p.draft.simulation
        p.sim_lint = safety.lint_script(sim.simulate, sim.cleanup) + [
            f for f in safety.lint_script(sim.cleanup) if f.rule != "missing-cleanup"]
        p.sim_blocked = any(f.severity == "block" for f in p.sim_lint)
    save_record(record, out)
    (out / "iocs.json").write_text(record.iocs.model_dump_json(indent=1))
    _write_behaviours(record, out)
    _write_telemetry(record, out)
    for p in record.packages:
        _write_rule(p, out)
        (out / "tests" / f"{p.slug}.json").write_text(
            json.dumps([e.model_dump() for e in p.draft.test_events], indent=1))
        _write_queries(p, out)
        _write_simulation(record, p, out)
        _write_ads(record, p, out, results)
    for c in record.chains:
        _write_chain(c, out)
    _write_validation(record, out, results)
    _write_navigator(record, out, results)
    _write_summary(record, out, results)
    _write_feedback_howto(record, out)
    return out


# --------------------------------------------------------------------------- pieces
def _write_behaviours(record: RunRecord, out: Path) -> None:
    a = record.analysis
    doc = {
        "report_id": record.run_id,
        "report": {"title": record.report.title, "source": record.report.source, "sha256": record.report.sha256,
                   "retrieved_at": record.report.retrieved_at, "published": record.report.published},
        "actors": a.actors if a else [], "malware_tools": a.malware_tools if a else [],
        "victimology": a.victimology if a else "", "summary": a.summary if a else "",
        "timeline": [t.model_dump() for t in (a.timeline if a else [])],
        "behaviours": [],
    }
    for b in record.behaviours:
        pkg = next((p for p in record.packages if p.behaviour.id == b.id), None)
        doc["behaviours"].append({
            "behaviour_id": b.id, "name": b.name, "description": b.description, "selected": b.selected,
            "rank_score": b.rank_score, "rule": pkg.slug if pkg else None,
            "attack": {"technique_id": b.technique_id, "technique_name": b.technique_name, "tactic": b.tactic,
                       "verified_against_attack": b.attack_valid, "note": b.attack_note},
            "platform": b.platform,
            "evidence": [{"source": "report", "excerpt": q, "verified_in_source": ok}
                         for q, ok in zip(b.evidence, b.evidence_verified)],
            "observables": {k: v for k, v in b.observables.model_dump().items() if v},
            "log_sources": b.log_sources, "scores": b.scores.model_dump(),
        })
    (out / "behaviour-analysis.yaml").write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120))


def _write_telemetry(record: RunRecord, out: Path) -> None:
    rows = []
    for p in record.packages:
        t, ls = p.draft.telemetry, p.draft.sigma.logsource
        rows.append({
            "rule": p.slug, "behaviour": p.behaviour.name, "attack_id": p.behaviour.technique_id,
            "log_source": t.log_source, "sigma_logsource": {k: v for k, v in ls.model_dump().items() if v},
            "event_ids": t.event_ids, "key_fields": t.required_fields,
            "config_requirements": t.config_requirements, "blind_spots": t.blind_spots,
        })
    (out / "telemetry-requirements.yaml").write_text(yaml.safe_dump({"requirements": rows}, sort_keys=False, allow_unicode=True))


def _write_rule(p: DetectionPackage, out: Path) -> None:
    (out / "rules" / rule_filename(p)).write_text(p.rule_yaml)
    if p.history:
        h = out / "rules" / "history"
        h.mkdir(exist_ok=True)
        for old in p.history:
            (h / f"{p.slug}.v{old['version']}.yml").write_text(
                f"# superseded {old['replaced_at']}: {old['reason']}\n" + old["rule_yaml"])


def _query_ext(q: QueryResult) -> str:
    return TARGETS[q.target].ext.rsplit(".", 1)[-1] if q.target in TARGETS else "txt"


def _query_sections(qs: list[QueryResult], d: Path) -> list[str]:
    lines = []
    for q in qs:
        lines += [f"## {q.label}", ""]
        if q.query:
            (d / f"{q.target}.{_query_ext(q)}").write_text(q.query + "\n")
            lines += [f"```{q.language.lower().replace('|', '').replace(' ', '')}", q.query, "```"]
        else:
            lines += [f"Not available: `{q.error}`"]
        if q.notes:
            lines += ["", f"_Note: {q.notes}_"]
        lines.append("")
    return lines


def _write_queries(p: DetectionPackage, out: Path) -> None:
    d = out / "queries" / p.slug
    d.mkdir(parents=True, exist_ok=True)
    lines = [f"# {p.slug}: {p.draft.sigma.title} — SIEM queries (rule v{p.version})", "",
             "Generated from the Sigma rule with pySigma backends or ti2dac templates (deterministic) unless marked "
             "AI-translated. A query is **not tested** until a test result is recorded for it.", ""]
    for client in dict.fromkeys(q.client for q in p.queries):
        qs = [q for q in p.queries if q.client == client]
        cd = d / "clients" / client if client else d
        cd.mkdir(parents=True, exist_ok=True)
        if client:
            lines += [f"# Client: {client}", "", f"Queries in {client}'s own field names (`clients/{client}/`).", ""]
        lines += _query_sections(qs, cd)
        fms = [fm for fm in p.field_mappings if fm.client == client]
        if fms:
            tids = [q.target for q in qs if q.method != "llm"]
            lines += [f"## Field mapping{' for ' + client if client else ''}", "",
                      "| Sigma field | " + " | ".join(tids) + " |", "|---|" + "---|" * len(tids)]
            lines += [f"| `{fm.sigma_field}` | " + " | ".join(_cell(fm.targets.get(t, "")) for t in tids) + " |" for fm in fms]
            lines.append("")
    (d / "README.md").write_text("\n".join(lines))


def _write_chain(c: ChainPackage, out: Path) -> None:
    d = out / "chains" / c.slug
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{c.slug}.yml").write_text(c.rule_yaml)
    lines = [f"# {c.slug}: {c.name}", "",
             f"Steps ({'in order' if c.ordered else 'any order'}, same {c.join_on.replace('_', ' ')}, within {c.within}): "
             + " → ".join(c.steps), "",
             "Each step is a separately generated and validated single-event rule. The join was built by ti2dac "
             f"(Sigma correlation `{c.slug}.yml` plus fixed per-language templates), never written by the AI. "
             + ("Proposed by the report analysis." if c.source == "analysis" else "Defined by an analyst."), ""]
    if c.evidence:
        lines += [f"> {c.evidence}", ""]
    lines += [f"- {w}" for w in c.warnings] + ([""] if c.warnings else [])
    for client in dict.fromkeys(q.client for q in c.queries):
        cd = d / "clients" / client if client else d
        cd.mkdir(parents=True, exist_ok=True)
        if client:
            lines += [f"# Client: {client}", ""]
        lines += _query_sections([q for q in c.queries if q.client == client], cd)
    (d / "README.md").write_text("\n".join(lines))


def _atomic_yaml(p: DetectionPackage) -> str | None:
    sim = p.draft.simulation
    executor = {"powershell": "powershell", "bash": "bash"}.get(sim.language)
    if not executor or p.sim_blocked or sim.platform == "cloud":
        return None
    test = {
        "attack_technique": p.behaviour.technique_id,
        "display_name": p.behaviour.technique_name,
        "atomic_tests": [{
            "name": f"ti2dac {p.slug} - {p.draft.sigma.title}",
            "auto_generated_guid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"ti2dac:{p.rule_id}:{p.version}")),
            "description": f"Benign simulation for Sigma rule {p.rule_id}. {p.behaviour.description}",
            "supported_platforms": [sim.platform],
            "executor": {
                "name": executor,
                "elevation_required": sim.privileges == "admin",
                "command": sim.simulate.strip() + "\n",
                "cleanup_command": sim.cleanup.strip() + "\n",
            },
        }],
    }
    return yaml.safe_dump(test, sort_keys=False, allow_unicode=True, width=200)


def _write_simulation(record: RunRecord, p: DetectionPackage, out: Path) -> None:
    d = out / "simulations" / p.slug
    d.mkdir(parents=True, exist_ok=True)
    sim, tel, b = p.draft.simulation, p.draft.telemetry, p.behaviour
    ext = {"powershell": "ps1", "bash": "sh", "python": "py"}[sim.language]
    guard = safety.lab_guard(sim.language)
    header = (f"# ti2dac {p.slug} | ATT&CK {b.technique_id} {b.technique_name} | rule {p.rule_id} v{p.version}\n"
              f"# Expected telemetry: {'; '.join(f'{e.source} {e.event_id}' for e in sim.expected_events)}\n")
    if p.sim_blocked:
        body = safety.blocked_stub(sim.language, p.sim_lint)
        cleanup = body
    else:
        body, cleanup = sim.simulate.strip() + "\n", sim.cleanup.strip() + "\n"
    shebang = "#!/usr/bin/env bash\n" if sim.language == "bash" else "#!/usr/bin/env python3\n" if sim.language == "python" else ""
    (d / f"simulate.{ext}").write_text(shebang + header + guard + body)
    (d / f"cleanup.{ext}").write_text(shebang + header.replace("Expected telemetry", "Cleanup for") + guard + cleanup)
    atomic = _atomic_yaml(p)
    if atomic:
        (d / "atomic-test.yaml").write_text(atomic)

    run_cmd = (f"$env:TI2DAC_LAB='1'; powershell -ExecutionPolicy Bypass -File .\\simulate.{ext}"
               if sim.language == "powershell" else f"TI2DAC_LAB=1 {'bash' if ext == 'sh' else 'python3'} ./simulate.{ext}")
    clean_cmd = run_cmd.replace("simulate", "cleanup")
    baseline = ("Get-Date -Format o" if sim.platform == "windows" else "date -u +%Y-%m-%dT%H:%M:%SZ")
    lint_rows = [f"| {f.severity} | {f.rule} | {f.line or '-'} | `{_cell(f.text)}` |" for f in p.sim_lint]
    queries = [q for q in p.queries if q.query]
    L = [
        f"# Simulation & test guide — {p.slug}: {p.draft.sigma.title}", "", LAB_BANNER, "",
        "## 1. What this simulates", "",
        f"- **Behaviour:** {b.name} — {b.description}",
        f"- **ATT&CK:** [{b.technique_id} {b.technique_name}](https://attack.mitre.org/techniques/{b.technique_id.replace('.', '/')}/) ({b.tactic})",
        f"- **Rule:** `rules/{rule_filename(p)}` (id `{p.rule_id}`, v{p.version})",
        "- **Report evidence:**",
        *[f"  - \"{q}\"{'' if ok else ' _(not found verbatim in source — verify)_'}" for q, ok in zip(b.evidence, b.evidence_verified)],
        "",
        "## 2. Lab requirements", "",
        f"- Platform: **{sim.platform}**, privileges: **{sim.privileges}**",
        f"- Telemetry: **{tel.log_source}** — event IDs {', '.join(tel.event_ids) or 'n/a'}",
        *[f"- Config: {c}" for c in tel.config_requirements],
        "- A VM snapshot taken before the test (revert = guaranteed rollback).",
        "- Logs forwarded only to the lab SIEM.", "",
        "## 3. Preconditions", "", *[f"- {c}" for c in sim.preconditions or ["None"]], "",
        "## 4. Safety review", "",
        *[f"- {n}" for n in sim.safety_notes],
        f"- Safety linter: **{'BLOCKED — script replaced with a stub' if p.sim_blocked else 'passed' if not p.sim_lint else 'passed with warnings'}**",
        "",
    ]
    if lint_rows:
        L += ["| Severity | Rule | Line | Text |", "|---|---|---|---|", *lint_rows, ""]
    L += [
        "## 5. Option A — Atomic Red Team", "",
        f"Reference tests: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/{b.technique_id}/{b.technique_id}.md", "",
    ]
    if sim.atomic_tests:
        L += ["Suggested tests (verify they exist in your ART version):", *[f"- {t}" for t in sim.atomic_tests], ""]
    L += ["```powershell", "Import-Module invoke-atomicredteam", f"Invoke-AtomicTest {b.technique_id} -ShowDetailsBrief",
          f"Invoke-AtomicTest {b.technique_id} -TestNumbers <n> -CheckPrereqs", f"Invoke-AtomicTest {b.technique_id} -TestNumbers <n>",
          f"Invoke-AtomicTest {b.technique_id} -TestNumbers <n> -Cleanup", "```", ""]
    if atomic:
        L += ["`atomic-test.yaml` packages the ti2dac script in Atomic Red Team format. To run it with Invoke-AtomicRedTeam, "
              f"copy it to `<folder>\\{b.technique_id}\\{b.technique_id}.yaml` and run "
              f"`Invoke-AtomicTest {b.technique_id} -PathToAtomicsFolder <folder>` (add `-Cleanup` afterwards).", ""]
    L += [
        "## 6. Option B — ti2dac script", "",
        f"1. Revert the VM to a clean snapshot and confirm telemetry flows ({tel.log_source}).",
        f"2. Record the baseline time: `{baseline}`",
        f"3. Run the simulation: `{run_cmd}`",
        "4. Wait for ingestion (typically 1–5 minutes; check the newest event time in the SIEM).", "",
        "Expected events:", "", "| Source | Event ID | Rule will match on |", "|---|---|---|",
        *[f"| {_cell(e.source)} | {_cell(e.event_id)} | `{_cell(e.matching_fields)}` |" for e in sim.expected_events], "",
        "## 7. Positive test", "",
        f"Automatic pre-check: the rule was evaluated against the expected event(s) in `tests/{p.slug}.json` "
        f"— self-test **{p.selftest}**{': ' + '; '.join(p.selftest_details) if p.selftest == 'fail' else ''}.", "",
        "Fastest real check (no SIEM needed): export the lab events after the simulation (Sysmon/Security EVTX, or a "
        "JSON export from your SIEM) and replay them locally:", "",
        "```bash",
        f"ti2dac replay --run {record.run_id} --rule-slug {p.slug} --events lab-export.evtx --expect match --record",
        "```", "",
        "Run the query for your SIEM from `queries/" + p.slug + "/` over the window starting at the baseline time.", "",
        "- [ ] Query returns the simulated event(s)",
        "- [ ] Matched fields are the ones listed above (not an unrelated event)",
        "- [ ] Save the result (screenshot/export) and the event IDs/record IDs as evidence",
        "",
        "Available queries: " + ", ".join(f"`{q.target}`" for q in queries), "",
        "## 8. Negative (false-positive) test", "",
        "Run the query over a window of normal lab activity (at least one working day, or a replay of a benign dataset such as OTRF Security-Datasets / BOTS). Also perform these look-alike benign actions:", "",
        *[f"- {a}" for a in p.draft.negative_test.benign_activities], "",
        f"- [ ] Replay a normal-activity export: `ti2dac replay --run {record.run_id} --rule-slug {p.slug} --events baseline.jsonl --expect nomatch --record`",
        "- [ ] Record the number of matches and the cause of each",
        "- [ ] Tune only if the tuning does not hide the simulated behaviour; then repeat the positive test", "",
        "## 9. Cleanup and rollback", "",
        f"1. Run `{clean_cmd}`",
        "2. Verify the artefacts listed in the script are gone.",
        "3. Revert the VM snapshot (authoritative rollback).", "",
        "## 10. Record the results", "",
        "```bash",
        f"ti2dac test record {record.run_id} {p.slug} --target <target> --result fired --evidence \"<event id / screenshot path>\"",
        f"ti2dac test record {record.run_id} {p.slug} --target <target> --result quiet --evidence \"24h normal activity, 0 hits\"",
        f"ti2dac test record {record.run_id} {p.slug} --target <target> --result false_positive --fp-count 3 --evidence \"SCCM client\"",
        "```", "",
        "Something wrong in this guide or script? See `FEEDBACK.md`.", "",
    ]
    (d / "README.md").write_text("\n".join(L))


def _write_ads(record: RunRecord, p: DetectionPackage, out: Path, results: list[dict]) -> None:
    a, b, t, s = p.draft.ads, p.behaviour, p.draft.telemetry, p.draft.sigma
    status = _status_label(p, results)
    L = [
        f"# ADS: {s.title}", "",
        f"_Palantir Alerting & Detection Strategy framework · rule `{p.rule_id}` v{p.version} · review status: {p.review_status}_", "",
        "## Goal", "", a.goal, "",
        "## Categorization", "",
        f"- MITRE ATT&CK: {b.tactic} / {b.technique_id} {b.technique_name}",
        f"- Platform: {b.platform}", "",
        "## Strategy Abstract", "", a.strategy_abstract, "",
        *([f"Threshold: alert when {s.correlation[0].type.replace('_', ' ')} >= {s.correlation[0].gte} per "
           f"{', '.join(s.correlation[0].group_by) or 'host'} within {s.correlation[0].timespan} "
           "(Sigma correlation rule in the same file).", ""] if s.correlation else []),
        "## Technical Context", "", a.technical_context, "",
        "## Blind Spots and Assumptions", "", *[f"- {x}" for x in t.blind_spots],
        *[f"- **Quality warning:** {x}" for x in p.quality_warnings],
        "- Assumes Sigma taxonomy fields are normalized as shown in the field-mapping table (`queries/" + p.slug + "/README.md`).", "",
        "## False Positives", "", *[f"- {x}" for x in s.falsepositives], "",
        "## Validation", "",
        f"Simulation: `simulations/{p.slug}/README.md`. Current status per SIEM:", "",
        *[f"- {k}: {v}" for k, v in status.items()], "",
        "## Priority", "",
        f"- Sigma level **{s.level}**. Raise/lower after measuring the false-positive rate in your environment.", "",
        "## Response", "", "Triage:", *[f"{i}. {x}" for i, x in enumerate(a.triage_steps, 1)], "",
        "Response actions:", *[f"- {x}" for x in a.response_actions], "",
        "## Additional Resources", "",
        *[f"- {r}" for r in st.first_doc(p.rule_yaml).get("references", [])],
        f"- https://attack.mitre.org/techniques/{b.technique_id.replace('.', '/')}/", "",
    ]
    (out / "documentation" / f"{p.slug}-ads.md").write_text("\n".join(L))


def _write_validation(record: RunRecord, out: Path, results: list[dict]) -> None:
    tids = list(dict.fromkeys(q.target for p in record.packages for q in p.queries))
    if any(r["target"] == "sigma_replay" for r in results):
        tids.insert(0, "sigma_replay")
    L = ["# Validation matrix", "",
         f"Report: {record.report.title} · run `{record.run_id}`", "",
         "Status vocabulary: `not-tested`, `syntax-validated`, `desk-checked`, `tested-positive`, `tested-negative`, "
         "`tested-positive-and-negative`, `failed`. Converted queries stay `not-tested` until a result is recorded "
         "with `ti2dac test record`. *Self-test* = rule evaluated locally against the events its simulation "
         "should produce and benign look-alikes (`tests/<rule>.json`); *sigma_replay* = `ti2dac replay` on real lab logs.", "",
         "| Rule | Ver | ATT&CK | Sigma | Self-test | Review | " + " | ".join(tids) + " | FP on normal data |",
         "|---|---|---|---|---|---|" + "---|" * len(tids) + "---|"]
    for p in record.packages:
        st = _status_label(p, results)
        fp_total = sum(target_status(results, t, p.version)[1] for t in tids)
        causes = sorted({c for t in tids for c in target_status(results, t, p.version)[2]})
        L.append(f"| {p.slug} | v{p.version} | {p.behaviour.technique_id} | {p.sigma_status} | {p.selftest} | {p.review_status} | "
                 + " | ".join(_cell(st.get(t, "-")) for t in tids)
                 + f" | {fp_total}{' (' + _cell('; '.join(causes)) + ')' if causes else ''} |")
    L += ["", "## Recorded test evidence", ""]
    if results:
        L += ["| When | Rule | Ver | Target | Result | FP | Evidence | By |", "|---|---|---|---|---|---|---|---|"]
        L += [f"| {r['created_at']} | {r['slug']} | v{r['rule_version']} | {r['target']} | {r['result']} | {r['fp_count']} | "
              f"{_cell(r['evidence'])} | {_cell(r['tester'])} |" for r in results]
    else:
        L.append("No test results recorded yet.")
    (out / "validation" / "validation-matrix.md").write_text("\n".join(L) + "\n")


def _write_navigator(record: RunRecord, out: Path, results: list[dict]) -> None:
    techs = []
    for p in record.packages:
        tested = any(target_status(results, q.target, p.version)[0].startswith("tested-positive") for q in p.queries)
        techs.append({"id": p.behaviour.technique_id, "tactic": p.behaviour.tactic, "score": 3 if tested else 1,
                      "comment": f"{p.slug}: {p.draft.sigma.title} ({'validated' if tested else 'draft'})"})
    layer = attack.navigator_layer(f"ti2dac: {record.report.title}", f"Detections generated from {record.report.source}", techs)
    (out / "attack-navigator" / "layer.json").write_text(json.dumps(layer, indent=1))


def _write_summary(record: RunRecord, out: Path, results: list[dict]) -> None:
    a, r, u = record.analysis, record.report, record.usage
    L = [f"# Detection package: {r.title}", "",
         "| | |", "|---|---|",
         f"| Source | {_cell(r.source)} |", f"| SHA-256 | `{r.sha256}` |", f"| Retrieved | {r.retrieved_at} |",
         f"| Published / authors | {_cell(r.published or '-')} / {_cell(r.authors or '-')} |",
         f"| Run | `{record.run_id}` (ti2dac {record.tool_version}, prompts {record.prompt_version}) |",
         f"| AI | {_ai_line(record)} |",
         f"| Run by | {_cell(record.created_by or '-')} |",
         f"| Document | {r.kind} · TLP:{(r.tlp_effective or 'clear').upper()}{' (marked)' if r.tlp else ' (assumed)'}"
         f"{' · policy overridden: ' + _cell(r.tlp_override) if r.tlp_override else ''} |",
         f"| Redacted before AI | {', '.join(f'{v} {k.lower()}' for k, v in sorted(r.redactions.items())) or 'nothing found'} |", ""]
    if a:
        L += ["## Executive summary", "", a.summary, "",
              f"- **Actors:** {', '.join(a.actors) or 'not stated'}",
              f"- **Malware/tools:** {', '.join(a.malware_tools) or 'not stated'}",
              f"- **Victimology:** {a.victimology or 'not stated'}", ""]
    L += ["## Provenance of every output", "",
          "| Output | Produced by | Human-reviewed | Lab-tested |", "|---|---|---|---|"]
    for p in record.packages:
        tested = [t for t, v in _status_label(p, results).items() if v.startswith("tested")]
        L.append(f"| {p.slug} Sigma v{p.version} | {'AI draft + pySigma validation' if p.version == 1 else 'corrected from feedback'} | "
                 f"{p.review_status} | {', '.join(tested) or 'no'} |")
    L += ["| SIEM queries | pySigma backends (deterministic); AI only where marked | follows rule | see validation matrix |",
          "| Simulations | AI draft + safety linter; never executed by the tool | follows rule | see validation matrix |", ""]
    L += ["## Behaviours", "", "| ID | Sel | Rank | Tactic | Technique | Behaviour | Evidence verified | Rule |",
          "|---|---|---|---|---|---|---|---|"]
    for b in record.behaviours:
        pkg = next((p.slug for p in record.packages if p.behaviour.id == b.id), "")
        L.append(f"| {b.id} | {'✔' if b.selected else ''} | {b.rank_score} | {b.tactic} | {b.technique_id} {_cell(b.technique_name)}"
                 f"{'' if b.attack_valid else ' ⚠'} | {_cell(b.name)} | {sum(b.evidence_verified)}/{len(b.evidence)} | {pkg} |")
    L += ["", "## Detections", "", "| Rule | Title | Level | Type | Sigma | Self-test | Incident evidence | Queries OK | Simulation |",
          "|---|---|---|---|---|---|---|---|---|"]
    for p in record.packages:
        kind = f"threshold ({p.draft.sigma.correlation[0].type})" if p.draft.sigma.correlation else "single event"
        mine = [q for q in p.queries if not q.client]
        ok = sum(1 for q in mine if q.query)
        L.append(f"| [{p.slug}](rules/{rule_filename(p)}) | {_cell(p.draft.sigma.title)} | {p.draft.sigma.level} | {kind} | "
                 f"{p.sigma_status} | {p.selftest} | {_evidence(p)} | {ok}/{len(mine)} | {'BLOCKED' if p.sim_blocked else 'ok'}"
                 f"{' (' + str(len(p.sim_lint)) + ' lint)' if p.sim_lint else ''} |")
    if record.chains:
        L += ["", "## Multi-event chains (joined by code, not AI)", "",
              "| Chain | Steps | Join | Window | Queries |", "|---|---|---|---|---|"]
        for c in record.chains:
            mine = [q for q in c.queries if not q.client]
            L.append(f"| [{c.slug}](chains/{c.slug}/README.md) {_cell(c.name)} | {' → '.join(c.steps)}"
                     f"{'' if c.ordered else ' (any order)'} | {c.join_on} | {c.within} | "
                     f"{sum(1 for q in mine if q.query)}/{len(mine)} |")
    clients_used = sorted({q.client for p in record.packages for q in p.queries if q.client})
    if clients_used:
        L += ["", "## Client queries", "", "| Client | Queries produced | AI-translated |", "|---|---|---|"]
        for cl in clients_used:
            qs = [q for p in record.packages for q in p.queries if q.client == cl]
            L.append(f"| {cl} | {sum(1 for q in qs if q.query)}/{len(qs)} | {sum(1 for q in qs if q.method == 'llm' and q.query)} |")
    L += ["", "## Telemetry requirements", "", "| Rule | ATT&CK | Log source | Event IDs | Key fields |", "|---|---|---|---|---|"]
    for p in record.packages:
        t = p.draft.telemetry
        L.append(f"| {p.slug} | {p.behaviour.technique_id} | {_cell(t.log_source)} | {_cell(', '.join(t.event_ids))} | "
                 f"{_cell(', '.join(t.required_fields))} |")
    i = record.iocs
    L += ["", "## IOCs (enrichment only, see iocs.json)", "",
          f"{len(i.ipv4)} IPv4 · {len(i.domains)} domains · {len(i.urls)} URLs · {len(i.md5) + len(i.sha1) + len(i.sha256)} hashes · "
          f"{len(i.cves)} CVEs ({', '.join(i.cves[:8])})", ""]
    items = [f"- {w}" for w in record.warnings]
    for p in record.packages:
        items += [f"- **{p.slug} quality:** {x}" for x in p.quality_warnings]
        items += [f"- **{p.slug} self-test failed:** {x}" for x in p.selftest_details if p.selftest == "fail"]
        items += [f"- **{p.slug} possible duplicate:** {x}" for x in p.similar_rules]
        items += [f"- {p.slug}: {x}" for x in p.sigma_issues]
    if items:
        L += ["## Warnings and unverified assumptions", "", *items, ""]
    if u.calls or u.cached_calls:
        L += ["## AI usage", "", usage_summary(u), ""]
        if len(u.by_stage) > 1 or u.unpriced_models:
            L += ["| Stage | Model | Calls | Cached | Input | Output | Cache read | Cache write | Est. cost |",
                  "|---|---|--:|--:|--:|--:|--:|--:|--:|"]
            L += [f"| {name} | `{s.get('model_price_key', '')}` | {s.get('calls', 0)} | {s.get('cached_calls', 0)} | "
                  f"{s.get('input_tokens', 0):,} | {s.get('output_tokens', 0):,} | {s.get('cache_read_tokens', 0):,} | "
                  f"{s.get('cache_write_tokens', 0):,} | " + _stage_cost(s, u) + " |"
                  for name, s in u.by_stage.items()]
            L.append("")
    (out / "report-summary.md").write_text("\n".join(L))


def _stage_cost(s: dict, u: Usage) -> str:
    if s.get("model_price_key") in u.unpriced_models and not float(s.get("cost_usd") or 0):
        return "not priced"
    return f"${float(s['cost_usd']):.4f}" if "cost_usd" in s else "–"


def usage_summary(u: Usage) -> str:
    """One line of AI usage for a run: calls, every token class, cost, and what the cost does not cover."""
    parts = [f"{u.calls} API calls ({u.cached_calls} served from cache, free)",
             f"input {u.input_tokens:,} · output {u.output_tokens:,} · cache read {u.cache_read_tokens:,} · "
             f"cache write {u.cache_write_tokens:,} tokens"]
    cost = f"est. ${u.estimated_cost_usd:.4f}"
    if u.unpriced_models:
        cost += f" (excludes unpriced {', '.join(u.unpriced_models)}; set ai.prices)" if u.estimated_cost_usd else \
            f" — not priced: {', '.join(u.unpriced_models)} (set ai.prices)"
    parts.append(cost)
    extra = [f"{n} {label}" for n, label in ((u.fallback_calls, "answered by the refusal-fallback model"),
                                             (u.failover_calls, "answered by the failover provider"),
                                             (u.schema_retries, "schema re-asks")) if n]
    return " · ".join(parts) + (f" · {'; '.join(extra)}" if extra else "")


def _write_feedback_howto(record: RunRecord, out: Path) -> None:
    cats = "\n".join(f"| `{k}` | {v} |" for k, v in CATEGORIES.items())
    res = "\n".join(f"| `{k}` | {v} |" for k, v in TEST_RESULTS.items())
    text = f"""# Reporting mistakes and test results

Every generated artifact is a draft until reviewed. Report problems with structured feedback;
the web UI (`ti2dac serve`) has the same forms on each rule page.

## Feedback on an artifact

```bash
# Describe the problem (AI can propose the fix later with `ti2dac feedback apply <id> --ai`)
ti2dac feedback add {record.run_id} rule-001 --artifact sigma_rule --category too_broad_fp \\
    --severity medium --comment "Fires on SCCM ccmexec.exe children; add a parent filter"

# Or supply the corrected rule; it is validated and becomes the next rule version immediately
ti2dac feedback add {record.run_id} rule-001 --artifact sigma_rule --category logic_error \\
    --severity high --comment "Needs OriginalFileName" --correction-file fixed.yml
```

Artifacts: `behaviour`, `attack_mapping`, `sigma_rule`, `query` (use `--target`), `telemetry`, `simulation`, `ads`, `other`.

| Category | Meaning |
|---|---|
{cats}

Applied feedback becomes a short *lesson* that is added to future generation prompts for the same
ATT&CK technique, so the same mistake is not repeated. Lessons can be listed and disabled with
`ti2dac lessons`.

## Test results and alert dispositions

| Result | Meaning |
|---|---|
{res}

```bash
ti2dac test record {record.run_id} rule-001 --target splunk --result fired --evidence "EventRecordID 4711"
```

## Review / approval

```bash
ti2dac review {record.run_id} rule-001 --status approved    # as a different user than the author
```
"""
    (out / "FEEDBACK.md").write_text(text)


def _ai_line(record: RunRecord) -> str:
    if not record.ai_enabled:
        return "disabled (deterministic mode)"
    models = ", ".join(f"{k}={v}" for k, v in record.ai_models.items()) or "-"
    return f"{record.ai_provider or 'anthropic'} ({_cell(models)})"


def _evidence(p: DetectionPackage) -> str:
    if p.evidence_matches < 0:
        return "-"
    return f"matched {p.evidence_matches}/{p.evidence_total}" + (" ✔" if p.evidence_matches else "")
