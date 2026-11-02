"""End-to-end orchestration: report -> behaviours -> detection packages.

LLM calls per report (AI mode): 1 analysis + 1 per selected behaviour, plus at most
`max_repair_attempts` small repair calls when a rule fails validation/conversion, plus one
call per (rule, llm_target) only if non-pySigma SIEMs are configured. Everything else is
deterministic.
"""
from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__, attack, duplicates, quality, redact, replay, safety
from . import sigma_tools as st
from .condense import condense, procedure_signals
from .config import Settings
from .feedback import Store
from .ingest import LoadedReport, load_report
from .iocs import extract_iocs
from .llm import LLM, LLMError, estimate_cost
from .models import (
    Behaviour, DetectionDraft, DetectionPackage, ExtractedBehaviour, IOCSet, Observables, QueryResult,
    ReportAnalysis, RunRecord, Scores, SigmaDraft, TranslationDraft,
)
from .prompts import (
    ANALYZE_SYSTEM, FAMILY_HINTS, GENERATE_SYSTEM, PROMPT_VERSION, REPAIR_SYSTEM, TRANSLATE_SYSTEM,
    analyze_user, generate_user, repair_user, translate_user,
)
from .targets import FAMILIES, LLM_TARGET_LABELS, NATIVE_FIELDS, RENAMING_TARGETS

log = logging.getLogger(__name__)
Progress = Callable[[str], None]
_STRICT_TARGETS = ("sentinel_asim", "defender_xdr", "qradar_aql")


def _noop(_: str) -> None:
    pass


# --------------------------------------------------------------------------- evidence
def _norm(s: str) -> str:
    s = s.replace("\\", "").replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", s).strip().lower()


def verify_evidence(quote: str, norm_source: str) -> bool:
    """Verbatim (whitespace/quote-insensitive) or >=85% of 5-word shingles present."""
    q = _norm(quote).strip(" .\"'…")
    if len(q) < 12:
        return False
    if q in norm_source:
        return True
    words = q.split()
    if len(words) < 6:
        return False
    shingles = [" ".join(words[i:i + 5]) for i in range(len(words) - 4)]
    return sum(1 for s in shingles if s in norm_source) / len(shingles) >= 0.85


# --------------------------------------------------------------------------- ranking
def rank(b: Behaviour) -> float:
    s = b.scores
    clamp = lambda v: max(1, min(5, v))  # noqa: E731
    score = (2 * clamp(s.observability) + clamp(s.reproducibility) + clamp(s.mapping_confidence)
             + (6 - clamp(s.fp_risk)))
    score += 2 if any(b.evidence_verified) else -3
    score -= 0 if b.attack_valid else 4
    score += 1 if b.platform in ("windows", "linux") else -2
    obs = b.observables
    score += min(2, len(obs.command_lines) + len(obs.registry) + len(obs.services_tasks)) * 0.5
    return round(score, 2)


def select(behaviours: list[Behaviour], count: int, explicit: list[str] | None = None) -> None:
    for b in behaviours:
        b.selected = False
    if explicit:
        wanted = {x.strip().upper() for x in explicit}
        for b in behaviours:
            b.selected = b.id.upper() in wanted
        return
    chosen: list[Behaviour] = []
    for b in sorted(behaviours, key=lambda x: x.rank_score, reverse=True):
        if len(chosen) >= count:
            break
        if any(c.technique_id == b.technique_id for c in chosen):
            continue   # diversity: one rule per technique per run
        if not any(b.evidence_verified):
            continue
        chosen.append(b)
    for b in chosen:
        b.selected = True


# --------------------------------------------------------------------------- stages
def _new_run_id(loaded: LoadedReport, output_dir: str | Path | None = None) -> str:
    """Unique per run: re-running a report must never overwrite an earlier package (its reviews, versions,
    test results). Rule IDs stay stable across runs because they derive from the report hash."""
    slug = re.sub(r"[^a-z0-9]+", "-", loaded.meta.title.lower()).strip("-")[:48] or "report"
    base = f"{date.today().isoformat()}-{slug}-{loaded.meta.sha256[:8]}"
    run_id, n = base, 2
    while output_dir is not None and (Path(output_dir) / run_id / "run.json").exists():
        run_id, n = f"{base}-{n}", n + 1
    return run_id


def heuristic_analysis(loaded: LoadedReport, iocs: IOCSet) -> ReportAnalysis:
    """No-AI mode: behaviours only for ATT&CK IDs the report states explicitly."""
    behaviours = []
    sentences = re.split(r"(?<=[.!?])\s+|\n", loaded.text)
    for i, tid in enumerate(iocs.attack_ids[:25], 1):
        info = attack.lookup(tid)
        if not info:
            continue
        ev = [s.strip()[:200] for s in sentences if tid in s][:2]
        behaviours.append(ExtractedBehaviour(
            id=f"B{i}", name=info["name"], description=f"Report references {tid} ({info['name']}).",
            tactic=(info["tactics"] or ["execution"])[0], technique_id=tid, technique_name=info["name"],
            platform="windows" if "Windows" in info["platforms"] else "linux" if "Linux" in info["platforms"] else "other",
            evidence=ev, observables=Observables(processes=[], command_lines=[], registry=[], files=[], services_tasks=[], network=[]),
            log_sources=[], detection_idea="Manual rule authoring required (no-AI mode).",
            scores=Scores(observability=3, reproducibility=3, mapping_confidence=4, fp_risk=3),
        ))
    return ReportAnalysis(title=loaded.meta.title, actors=[], malware_tools=[], victimology="",
                          summary="Deterministic (no-AI) analysis: ATT&CK IDs explicitly cited in the report.",
                          behaviours=behaviours, timeline=[])


def build_behaviours(analysis: ReportAnalysis, source_text: str) -> list[Behaviour]:
    norm_source = _norm(source_text)
    out = []
    for i, eb in enumerate(analysis.behaviours, 1):
        b = Behaviour(**eb.model_dump())
        b.id = f"B{i}"
        b.technique_id = b.technique_id.strip().upper()
        b.evidence_verified = [verify_evidence(q, norm_source) for q in b.evidence]
        ok, note, name, tactic = attack.validate_mapping(b.technique_id, b.technique_name, b.tactic)
        b.attack_valid, b.attack_note, b.technique_name, b.tactic = ok, note, name, tactic  # type: ignore[assignment]
        cal = quality.calibrate_scores(b.technique_id, b.scores)
        if cal:
            b.attack_note = "; ".join(x for x in (b.attack_note, cal) if x)
        b.rank_score = rank(b)
        out.append(b)
    return out


def analyze(loaded: LoadedReport, settings: Settings, llm: LLM | None, progress: Progress = _noop) -> tuple[RunRecord, list[str]]:
    warnings: list[str] = []
    iocs = extract_iocs(loaded.text)
    cond = condense(loaded.text, settings.ai.input_token_budget)
    loaded.meta.condensed_chars = len(cond.text)
    progress(f"condensed report {cond.original_tokens} -> {cond.condensed_tokens} est. tokens "
             f"({cond.kept_blocks}/{cond.total_blocks} blocks; dropped sections: {', '.join(cond.dropped_sections) or 'none'})")
    signals = procedure_signals(loaded.text)
    if signals < 8:
        warnings.append(f"The report has little procedural detail ({signals} command/tool/registry signals). It reads like a "
                        "trend or strategic report; generated rules will be generic. Prefer incident write-ups (DFIR Report, "
                        "CISA advisories, vendor case studies) for detection engineering.")
    if llm is not None:
        progress("stage 1: extracting behaviours")
        analysis = llm.structured("analyze", ANALYZE_SYSTEM,
                                  analyze_user(loaded.meta.title, cond.text, settings.ai.max_behaviours, loaded.meta.kind), ReportAnalysis)
    else:
        analysis = heuristic_analysis(loaded, iocs)
        warnings.append("AI disabled: behaviours limited to explicitly cited ATT&CK IDs; write Sigma rules manually "
                        "and use `ti2dac convert`.")
    behaviours = build_behaviours(analysis, loaded.text)
    for b in behaviours:
        if not any(b.evidence_verified):
            warnings.append(f"{b.id}: no evidence quote could be verified in the source (possible hallucination)")
        if b.attack_note:
            warnings.append(f"{b.id}: {b.attack_note}")
    record = RunRecord(
        run_id=_new_run_id(loaded, settings.output_dir), created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        tool_version=__version__, prompt_version=PROMPT_VERSION, ai_enabled=llm is not None,
        report=loaded.meta, iocs=iocs, analysis=analysis, behaviours=behaviours, warnings=warnings,
    )
    if llm is not None:
        record.usage = llm.usage
        record.ai_provider = settings.ai.provider
        record.ai_models = {s: getattr(settings.ai, s).model for s in ("analyze", "generate", "repair", "translate")}
        if settings.ai.provider == "gemini":
            warnings.append("AI provider is Gemini. On the free tier Google may use prompts to improve its products: "
                            "send only public reports, never internal incident data.")
    if not looks_english(loaded.text):
        warnings.append("The report does not look like English. Condensing heuristics are English-tuned, so more "
                        "context may be dropped; check behaviour-analysis.yaml against the source.")
    return record, warnings


_EN_STOP = set("the and of to in is that for with was were this by on as from be are it an or have has which".split())


def looks_english(text: str) -> bool:
    words = re.findall(r"[A-Za-z']+", text[:20000].lower())
    letters = sum(len(w) for w in words)
    if letters < 0.4 * max(1, len(re.sub(r"\s", "", text[:20000]))):
        return False
    return bool(words) and sum(w in _EN_STOP for w in words) / len(words) > 0.08


def _references(record: RunRecord) -> list[str]:
    if record.report.url.startswith("http"):
        return [record.report.url]
    return [f"Local report {Path(record.report.source).name} (sha256:{record.report.sha256[:16]}...)"]


def _assemble(record: RunRecord, b: Behaviour, draft: DetectionDraft, settings: Settings, slug: str,
              version: int = 1, rule_date: str | None = None) -> DetectionPackage:
    rule_id = st.stable_rule_id(record.report.sha256, f"{b.technique_id}:{b.name}")
    rule_yaml = st.render_rule(
        draft.sigma, rule_id=rule_id, author=settings.author, references=_references(record),
        tags=st.attack_tags(b.tactic, b.technique_id), rule_date=rule_date,
        modified=date.today().isoformat() if version > 1 else None,
    )
    return DetectionPackage(rule_id=rule_id, slug=slug, version=version, behaviour=b, draft=draft, rule_yaml=rule_yaml)


def _check(pkg: DetectionPackage, settings: Settings, record: RunRecord | None = None) -> list[str]:
    """Validate + convert + quality-check. Returns issues worth a repair call (empty = good)."""
    ok, issues = st.validate_rule(pkg.rule_yaml)
    pkg.sigma_issues = issues
    if not ok:
        pkg.sigma_status = "failed"
        return [i for i in issues if i.startswith("error")]
    pkg.sigma_status = "syntax-validated"
    pkg.quality_warnings = []
    brittle = quality.brittle_artifacts(pkg.rule_yaml, record.iocs.file_names if record else [])
    if brittle:
        pkg.quality_warnings.append(
            f"Rule references artifact names specific to this intrusion ({', '.join(brittle)}); attackers rename "
            "these freely. Confirm the rule also detects the procedure without them (paths, parent/child, arguments).")
    brittle_issue = ([f"quality: the positive selections rely on report-specific artifact names {brittle}. Generalise "
                      "to the procedure (locations, parent/child process, arguments, registry paths); keep such names "
                      "at most as an extra OR branch, never as the only discriminator."] if brittle and pkg.repair_attempts == 0 else [])
    leaked = sorted(set(redact.PLACEHOLDER.findall(yaml_values(pkg.rule_yaml))))
    placeholder_issue = []
    if leaked:
        pkg.quality_warnings.append(f"Rule contains redacted environment identifiers {leaked}: it would only match "
                                    "this one incident's host/user. It must describe the technique instead.")
        placeholder_issue = [f"quality: the rule uses redacted placeholders {leaked} (specific hosts/users/IPs of "
                             "this incident). Remove them; detect the technique on any host."]
    pkg.queries = st.convert(pkg.rule_yaml, settings.targets, settings.index_overrides)
    # Backends with strict field validation reject fields that are not in the Sigma taxonomy. One
    # backend rejecting a field is a vendor gap (documented in the field mapping); two or more
    # means the rule itself is wrong and is worth a repair call.
    probe = st.convert(pkg.rule_yaml, [t for t in _STRICT_TARGETS if t not in settings.targets]) if \
        any(t not in settings.targets for t in _STRICT_TARGETS) else []
    field_errors = [f"{q.target}: {q.error}" for q in pkg.queries + probe
                    if q.target in _STRICT_TARGETS and q.error and "field" in q.error.lower()]
    # Unit-test the rule against the events its own simulation should produce (and benign look-alikes).
    pkg.selftest, pkg.selftest_details = replay.selftest(pkg.rule_yaml, pkg.draft.test_events)
    selftest_issue = [f"self-test: {d}" for d in pkg.selftest_details] if pkg.selftest == "fail" else []
    if settings.telemetry:
        ls = st.first_doc(pkg.rule_yaml).get("logsource") or {}
        key = f"{ls.get('product', '')}:{ls.get('category') or ls.get('service', '')}"
        if key not in settings.telemetry:
            pkg.quality_warnings.append(f"Log source {key} is not in your telemetry inventory ({', '.join(settings.telemetry)}); "
                                        "this rule cannot fire until that data is collected.")
    return (field_errors if len(field_errors) >= 2 else []) + brittle_issue + selftest_issue + placeholder_issue


def _yaml_get(text: str, key: str):
    import yaml

    try:
        return st.first_doc(text).get(key)
    except Exception:
        return None


def _lint_simulation(pkg: DetectionPackage) -> None:
    sim = pkg.draft.simulation
    pkg.sim_lint = safety.lint_script(sim.simulate, sim.cleanup) + [
        f for f in safety.lint_script(sim.cleanup) if f.rule != "missing-cleanup"]
    pkg.sim_blocked = any(f.severity == "block" for f in pkg.sim_lint)


def _translate_llm(pkg: DetectionPackage, settings: Settings, llm: LLM) -> None:
    """AI translations: configured non-pySigma SIEMs, plus families no pySigma target could convert."""
    jobs: list[tuple[str, str, str, str, str]] = []   # (target id, label, language, hint, why)
    by_target = {q.target: q for q in pkg.queries}
    for fam in settings.ai_fill_gaps:
        members, label, lang = FAMILIES.get(fam, ([], "", ""))
        configured = [t for t in members if t in by_target]
        if configured and all(by_target[t].error for t in configured):
            why = "; ".join(f"{t}: {by_target[t].error}" for t in configured)[:400]
            jobs.append((f"{fam}_ai", label, lang, FAMILY_HINTS.get(fam, ""), why))
    for tid in settings.llm_targets:
        label, lang = LLM_TARGET_LABELS.get(tid, (tid, tid))
        jobs.append((tid, label, lang, "", ""))
    for tid, label, lang, hint, why in jobs:
        res = QueryResult(target=tid, label=label + " [AI-translated, unverified]", language=lang, method="llm")
        try:
            t = llm.structured("translate", TRANSLATE_SYSTEM, translate_user(pkg.rule_yaml, label, lang, hint, why),
                               TranslationDraft)
            res.query, res.notes = t.query.strip(), f"confidence={t.confidence}; {t.notes}"
        except LLMError as e:
            res.error, res.validation = str(e), "failed"
        pkg.queries.append(res)


def _flag_unmapped_fields(pkg: DetectionPackage) -> None:
    """A renaming pipeline that left a field unchanged did not map it: the query may never match.

    If NONE of the rule's fields were mapped, the pipeline does not know this log source at all (e.g. the
    CrowdStrike pipeline for Sysmon registry events): the query is marked failed so the AI gap translator
    writes a native one instead of shipping a query that can never match."""
    for q in pkg.queries:
        if not q.query or q.target not in RENAMING_TARGETS:
            continue
        fields = [fm.sigma_field for fm in pkg.field_mappings if not fm.targets.get(q.target, "").startswith("UNSUPPORTED")]
        native = NATIVE_FIELDS.get(q.target, set())
        unmapped = [f for f in fields if dict((fm.sigma_field, fm.targets.get(q.target)) for fm in pkg.field_mappings)[f] == f
                    and f not in native]
        if fields and len(unmapped) == len(fields):
            q.error = (f"{q.target} pipeline has no field mapping for this log source "
                       f"({', '.join(unmapped)} passed through unchanged); it will not match normalized data")
            q.notes = f"{q.notes} Raw pass-through query, only for un-normalized data: {q.query}".strip()
            q.query, q.validation = None, "failed"
        elif unmapped:
            note = f"Fields not mapped by the {q.target} pipeline (verify they exist in your data): {', '.join(unmapped)}"
            q.notes = f"{q.notes} {note}".strip()


def finalize_package(pkg: DetectionPackage, record: RunRecord, settings: Settings, llm: LLM | None,
                     feedback_text: str = "", progress: Progress = _noop, allow_repair: bool = True) -> DetectionPackage:
    """Validate/convert, repair with the model if needed, then map fields, lint, translate."""
    blocking = _check(pkg, settings, record)
    while ((blocking or feedback_text) and allow_repair and llm is not None
           and pkg.repair_attempts < settings.ai.max_repair_attempts):
        pkg.repair_attempts += 1
        progress(f"{pkg.slug}: repair attempt {pkg.repair_attempts} ({len(blocking)} issue(s))")
        fixed = llm.structured("repair", REPAIR_SYSTEM,
                               repair_user(rule_for_ai(pkg.rule_yaml), blocking or ["Apply reviewer feedback."],
                                           redact_for_ai(feedback_text, settings)),
                               SigmaDraft)
        feedback_text = ""
        pkg.draft.sigma = fixed
        rid, ver = pkg.rule_id, pkg.version
        rule_date = str(_yaml_get(pkg.rule_yaml, "date") or date.today().isoformat())
        rebuilt = _assemble(record, pkg.behaviour, pkg.draft, settings, pkg.slug, ver, rule_date)
        pkg.rule_yaml, pkg.rule_id = rebuilt.rule_yaml, rid
        blocking = _check(pkg, settings, record)
    if pkg.sigma_status != "failed":
        pkg.field_mappings = st.field_mappings(pkg.rule_yaml, settings.targets)
        _flag_unmapped_fields(pkg)
        pkg.similar_rules = duplicates.find_similar(pkg.rule_yaml, settings)
        if llm is not None:
            _translate_llm(pkg, settings, llm)
    _lint_simulation(pkg)
    return pkg


# Sigma logsource categories a behaviour's observables point to (lessons are stored per logsource).
_OBSERVABLE_CATEGORIES = {
    "processes": ["process_creation"], "command_lines": ["process_creation"], "services_tasks": ["process_creation"],
    "registry": ["registry_set", "registry_event", "registry_add"], "files": ["file_event"],
    "network": ["network_connection"],
}


def likely_categories(b) -> list[str]:
    obs = b.observables.model_dump()
    return list(dict.fromkeys(c for k, cats in _OBSERVABLE_CATEGORIES.items() if obs.get(k) for c in cats))


def generate(record: RunRecord, settings: Settings, llm: LLM, store: Store | None = None,
             progress: Progress = _noop, behaviour_ids: list[str] | None = None, actor: str = "") -> list[DetectionPackage]:
    todo = [b for b in record.behaviours if (b.id in behaviour_ids if behaviour_ids else b.selected)]
    existing = {p.behaviour.id for p in record.packages}
    todo = [b for b in todo if b.id not in existing]
    start = len(record.packages)
    analysis = record.analysis
    context = {"report": record.report.title, "actors": analysis.actors if analysis else [],
               "tools": (analysis.malware_tools if analysis else [])[:12]}
    if settings.telemetry:   # steer the logsource choice to data the organisation actually collects
        context["available_telemetry"] = settings.telemetry

    def one(arg):
        n, b = arg
        slug = f"rule-{start + n:03d}"
        progress(f"stage 2: {slug} <- {b.id} {b.technique_id} {b.name}")
        lessons = []
        if store is not None:
            prod = "windows" if b.platform == "windows" else b.platform
            lessons = [redact_for_ai(x, settings) for x in
                       store.relevant_lessons(b.technique_id, prod, likely_categories(b), settings.ai.max_lessons_in_prompt)]
        payload = b.model_dump(include={"name", "description", "tactic", "technique_id", "technique_name",
                                        "platform", "observables", "log_sources", "detection_idea"})
        payload["observables"] = {k: v for k, v in payload["observables"].items() if v}
        evidence = [q for q, ok in zip(b.evidence, b.evidence_verified) if ok] or b.evidence
        try:
            draft = llm.structured("generate", GENERATE_SYSTEM, generate_user(payload, evidence, context, lessons), DetectionDraft)
            pkg = _assemble(record, b, draft, settings, slug)
            pkg.created_by = actor or record.created_by
            return finalize_package(pkg, record, settings, llm, progress=progress)
        except LLMError as e:
            # One failed behaviour must not discard the others; it can be retried with `ti2dac generate`.
            record.warnings.append(f"{b.id} ({b.technique_id}) not generated: {e}. Retry: ti2dac generate {record.run_id} --select {b.id}")
            progress(f"{slug}: FAILED ({e})")
            return None

    parallel = settings.ai.max_parallel or (1 if settings.ai.provider == "gemini" else 4)
    with ThreadPoolExecutor(max_workers=min(parallel, max(1, len(todo)))) as ex:
        pkgs = [p for p in ex.map(one, enumerate(todo, 1)) if p is not None]
    for i, p in enumerate(pkgs, start + 1):   # keep slugs contiguous when a behaviour failed
        if p.slug != f"rule-{i:03d}":
            p.slug = f"rule-{i:03d}"
    record.packages.extend(pkgs)
    record.usage = llm.usage
    record.usage.estimated_cost_usd = estimate_cost(record.usage)
    return pkgs


def run(source: str, settings: Settings, *, count: int | None = None, explicit: list[str] | None = None,
        raw: bytes | None = None, filename: str | None = None, store: Store | None = None,
        progress: Progress = _noop, actor: str = "", incident: bool | None = None, tlp_override: str = "",
        evidence_events: list[dict] | None = None) -> tuple[RunRecord, LoadedReport]:
    attack.set_override_dir(settings.state_dir)
    loaded = load_report(source, settings.fetch, raw=raw, filename=filename)
    progress(f"ingested {loaded.meta.title!r} ({loaded.meta.content_type}, {loaded.meta.chars} chars, sha256 {loaded.meta.sha256[:12]})")
    prepare_report(loaded, settings, incident=incident, tlp_override=tlp_override, progress=progress)
    llm = LLM(settings) if settings.ai.enabled else None
    record, _ = analyze(loaded, settings, llm, progress)
    record.created_by = actor
    select(record.behaviours, count or settings.select_count, explicit)
    if record.behaviours and not any(b.selected for b in record.behaviours):
        record.warnings.append("No behaviour had evidence that could be verified in the report, so none was auto-selected. "
                               "Review behaviour-analysis.yaml and force a choice with --select B<n> if appropriate.")
    if tlp_override:
        record.warnings.append(f"TLP policy overridden by {actor or 'unknown'}: {tlp_override}")
        if store is not None:
            store.audit(actor, "tlp.override", {"run_id": record.run_id, "tlp": loaded.meta.tlp_effective,
                                                "provider": settings.ai.provider, "reason": tlp_override})
    if llm is not None:
        generate(record, settings, llm, store, progress, actor=actor)
    events = loaded.embedded_events + list(evidence_events or [])
    if events and record.packages:
        replay_evidence(record, events, store, actor, progress)
    return record, loaded


# --------------------------------------------------------------------------- incident reports
class PolicyError(ValueError):
    pass


_INCIDENT_HINTS = re.compile(
    r"incident report|incident summary|root cause|containment|eradication|lessons learned|post[- ]incident|"
    r"affected (host|system|user)s?|host was isolated|\bisolated\b|\bIR-\d|incident (id|number|ticket)|severity:|"
    r"timeline \(utc\)|first observed|patient zero|initial access vector", re.I)
_EVENT_LINE = re.compile(r"^\s*(\{.*\})\s*,?\s*$", re.M)


def looks_like_incident(text: str) -> bool:
    return len({m.group(0).lower() for m in _INCIDENT_HINTS.finditer(text[:100_000])}) >= 3


def extract_embedded_events(text: str) -> list[dict]:
    """Raw log events pasted into a report (JSON lines), e.g. Sysmon/EDR records in an evidence section."""
    events = []
    for m in _EVENT_LINE.finditer(text):
        try:
            obj = json.loads(m.group(1))
        except ValueError:
            continue
        if isinstance(obj, dict) and len(obj) >= 2:
            ev = replay.normalize_event(obj)
            if any(k in ev for k in ("EventID", "Image", "CommandLine", "TargetObject", "ScriptBlockText", "QueryName")):
                events.append(ev)
    return events


def prepare_report(loaded: LoadedReport, settings: Settings, *, incident: bool | None = None,
                   tlp_override: str = "", progress: Progress = _noop) -> None:
    """TLP policy, incident detection, redaction (before anything is condensed or sent) and evidence extraction."""
    meta = loaded.meta
    meta.kind = "incident" if (incident if incident is not None else looks_like_incident(loaded.text)) else "threat-intel"
    meta.tlp = redact.detect_tlp(loaded.text)
    default = settings.ai.default_tlp_incident if meta.kind == "incident" else settings.ai.default_tlp_threat_intel
    meta.tlp_effective = meta.tlp or default
    allowed = settings.ai.allowed_tlp.get(settings.ai.provider, [])
    if settings.ai.enabled and not redact.tlp_allowed(meta.tlp_effective, allowed):
        if not tlp_override:
            raise PolicyError(
                f"TLP:{meta.tlp_effective.upper()} {'(marked)' if meta.tlp else '(assumed for an unmarked ' + meta.kind + ' report)'} "
                f"may not be sent to provider '{settings.ai.provider}' (allowed: {', '.join(allowed) or 'none'}). "
                "Options: run with --no-ai (deterministic parts only), use a provider your policy allows "
                "(ai.allowed_tlp), or, if the data owner approves, pass --tlp-override \"<reason>\" (audited).")
        meta.tlp_override = tlp_override
    if settings.redaction.enabled:
        rc = settings.redaction
        sep = "\n\u241e\n"   # keeps title and body in one pass so placeholders are consistent
        red = redact.redact(meta.title + sep + loaded.text, internal_domains=rc.internal_domains,
                            internal_networks=rc.internal_networks, terms=rc.terms, hostname_patterns=rc.hostname_patterns)
        meta.title, loaded.text = red.text.split(sep, 1)
        loaded.redaction_map = red.mapping
        meta.redactions = red.counts
        if red.counts:
            progress("redacted before analysis: " + ", ".join(f"{v} {k.lower()}" for k, v in sorted(red.counts.items())))
    loaded.embedded_events = extract_embedded_events(loaded.text)
    meta.embedded_events = len(loaded.embedded_events)
    progress(f"document type: {meta.kind}, TLP:{meta.tlp_effective.upper()}"
             + (f", {meta.embedded_events} embedded log events" if meta.embedded_events else ""))


def replay_evidence(record: RunRecord, events: list[dict], store: Store | None, actor: str,
                    progress: Progress = _noop) -> None:
    """Would each rule have caught this incident? Replay the incident's own events (never sent to the AI)."""
    for pkg in record.packages:
        try:
            hits = replay.evaluate(pkg.rule_yaml, events)
        except replay.ReplayError as e:
            pkg.quality_warnings.append(f"incident evidence replay failed: {e}")
            continue
        scoped = len(replay._scoped(events, st.first_doc(pkg.rule_yaml)))
        pkg.evidence_matches, pkg.evidence_total = len(hits), len(events)
        progress(f"{pkg.slug}: matches {len(hits)} of {scoped} relevant incident events")
        if hits and store is not None:
            store.add_test_result(tester=actor or "ti2dac", run_id=record.run_id, slug=pkg.slug, rule_version=pkg.version,
                                  target="sigma_replay", result="fired", evidence=f"incident evidence: {len(hits)} event(s) matched",
                                  environment="incident evidence replay")
        elif not hits and scoped:
            pkg.quality_warnings.append(f"Rule matches none of the {scoped} incident events of its log source type; "
                                        "check that it detects what actually happened.")


# --------------------------------------------------------------------------- feedback application
def apply_correction(record: RunRecord, slug: str, settings: Settings, *, corrected_yaml: str | None = None,
                     feedback_text: str = "", llm: LLM | None = None, progress: Progress = _noop,
                     actor: str = "") -> DetectionPackage:
    """Create rule version n+1 from a human-corrected YAML or (with AI) from feedback text."""
    import yaml

    idx = next(i for i, p in enumerate(record.packages) if p.slug == slug)
    old = record.packages[idx]
    if llm is not None:
        try:
            check_tlp_for_run(record, settings)
        except PolicyError:
            if not corrected_yaml:
                raise                 # an AI rewrite would send report-derived content to the provider
            llm = None                # a human correction still applies; only AI gap translation is skipped
            record.warnings.append(f"{slug} v{old.version + 1}: AI gap translation skipped (TLP policy)")
    new = old.model_copy(deep=True)
    new.version = old.version + 1
    new.repair_attempts = 0
    new.review_status = "draft"
    new.created_by = actor   # author of v(n+1) cannot approve it (four-eyes)
    new.history.append({"version": str(old.version), "rule_yaml": old.rule_yaml,
                        "replaced_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "reason": (feedback_text or "human-corrected rule")[:300]})
    if corrected_yaml:
        try:
            docs = st.load_docs(corrected_yaml)
        except yaml.YAMLError as e:
            raise ValueError(f"correction is not valid YAML: {e}") from e
        if not docs or "detection" not in docs[0]:
            raise ValueError("correction is not a Sigma rule (first document needs a detection section)")
        data = docs[0]
        data["id"] = old.rule_id                     # identity is stable across versions
        data["modified"] = date.today().isoformat()
        new.rule_yaml = st.dump_docs(docs)
        new.draft.sigma.title = str(data.get("title", new.draft.sigma.title))
        new.draft.sigma.level = data.get("level", new.draft.sigma.level)
        new.draft.sigma.falsepositives = list(data.get("falsepositives") or [])
        # Never let the model rewrite a human correction; it may only fill SIEM query gaps.
        finalize_package(new, record, settings, llm, progress=progress, allow_repair=False)
    else:
        if llm is None:
            raise ValueError("no corrected rule supplied and AI is disabled")
        # Start from the CURRENT rule (which may be a human correction), never from the original AI draft.
        new.rule_yaml = st.set_status(old.rule_yaml, "experimental", modified=date.today().isoformat())
        finalize_package(new, record, settings, llm, feedback_text=feedback_text, progress=progress)
    if new.sigma_status == "failed":
        raise ValueError("corrected rule does not validate: " + "; ".join(new.sigma_issues[:5]))
    record.packages[idx] = new
    return new


def review_problem(pkg: DetectionPackage, status: str, reviewer: str) -> str:
    """Blocking reason for a review decision, or "" (four-eyes: authors don't approve their own version)."""
    if status != "approved":
        return ""
    if pkg.sigma_status == "failed":
        return f"{pkg.slug} v{pkg.version} does not validate; fix it before approval"
    if not pkg.created_by:
        return (f"{pkg.slug} v{pkg.version} has no recorded author, so four-eyes cannot be verified; "
                "regenerate or correct it under a named user")
    if not reviewer or pkg.created_by == reviewer:
        return (f"four-eyes rule: {reviewer} authored {pkg.slug} v{pkg.version} and cannot approve it; "
                "another approver must review it")
    return ""


def yaml_values(rule_yaml: str) -> str:
    """All detection values of the base rule as one string (for placeholder checks)."""
    det = st.first_doc(rule_yaml).get("detection") or {}
    out: list[str] = []
    quality._values({k: v for k, v in det.items() if k != "condition"}, out)
    return "\n".join(out)


def check_tlp_for_run(record: RunRecord, settings: Settings) -> None:
    """Re-check the TLP policy before more AI calls on an existing run (the provider may have changed)."""
    tlp = record.report.tlp_effective or "clear"
    if settings.ai.enabled and not record.report.tlp_override and \
            not redact.tlp_allowed(tlp, settings.ai.allowed_tlp.get(settings.ai.provider, [])):
        raise PolicyError(f"run {record.run_id} is TLP:{tlp.upper()}, which provider '{settings.ai.provider}' may not receive")


def redact_for_ai(text: str, settings: Settings) -> str:
    """Free text written by people (feedback comments, lessons) is redacted like reports before any prompt."""
    if not text or not settings.redaction.enabled:
        return text
    rc = settings.redaction
    return redact.redact(text, internal_domains=rc.internal_domains, internal_networks=rc.internal_networks,
                         terms=rc.terms, hostname_patterns=rc.hostname_patterns).text


def rule_for_ai(rule_yaml: str) -> str:
    """Detection-relevant part of a rule for repair prompts: no id/author/references/dates (file names, URLs)."""
    import yaml

    keep = ("title", "description", "logsource", "detection", "falsepositives", "level", "correlation", "name")
    docs = [{k: v for k, v in d.items() if k in keep} for d in st.load_docs(rule_yaml)]
    return "---\n".join(yaml.safe_dump(d, sort_keys=False, allow_unicode=True) for d in docs)
