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
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__, attack, chains, clients, duplicates, obs, quality, redact, replay, safety, wazuh
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
from .targets import FAMILIES, LLM_TARGET_LABELS, NATIVE_FIELDS, RENAMING_TARGETS, TARGETS

log = logging.getLogger(__name__)
Progress = Callable[[str], None]
_STRICT_TARGETS = ("sentinel_asim", "defender_xdr", "qradar_aql")
_SEP = "\n\u241e\n"   # joins texts redacted in one pass (consistent placeholders); no pattern touches it


def _noop(_: str) -> None:
    pass


# --------------------------------------------------------------------------- evidence
# Private Use Area code points: some PDF fonts map punctuation ("-", ":", "(", "[") to them, so the extracted
# text reads "202608" where the page shows "2026-08". A model quoting the page drops them.
_PRIVATE_USE = re.compile("[-]")


def _norm(s: str) -> str:
    s = s.replace("\\", "").replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", _PRIVATE_USE.sub("", s)).strip().lower()


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
    while output_dir is not None:
        # Reserve the directory now: run.json only appears at render, so two concurrent runs of one report
        # would otherwise both pick the same id.
        try:
            (Path(output_dir) / run_id).mkdir(parents=True)
            break
        except FileExistsError:
            run_id, n = f"{base}-{n}", n + 1
    return run_id


def _release_run_id(output_dir: str | Path | None, run_id: str) -> None:
    """Drop the reservation of a run that failed before anything was written (only an empty directory)."""
    if output_dir is not None and run_id:
        try:
            (Path(output_dir) / run_id).rmdir()
        except OSError:
            pass


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
        b.technique_id, moved = attack.resolve_revoked(b.technique_id)
        ok, note, name, tactic = attack.validate_mapping(b.technique_id, b.technique_name, b.tactic)
        note = "; ".join(x for x in (moved, note) if x)
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
    run_id = _new_run_id(loaded, settings.output_dir)
    obs.run_id.set(run_id)   # so the analysis call's ai.call event carries it
    if llm is not None:
        progress("stage 1: extracting behaviours")
        try:
            analysis = llm.structured("analyze", ANALYZE_SYSTEM,
                                      analyze_user(loaded.meta.title, cond.text, settings.ai.max_behaviours, loaded.meta.kind), ReportAnalysis)
        except BaseException:
            _release_run_id(settings.output_dir, run_id)
            raise
    else:
        analysis = heuristic_analysis(loaded, iocs)
        warnings.append("AI disabled: behaviours limited to explicitly cited ATT&CK IDs; write Sigma rules manually "
                        "and use `ti2dac convert`.")
    behaviours = build_behaviours(analysis, loaded.text)
    _check_sequences(analysis, behaviours, loaded.text, warnings)
    for b in behaviours:
        if not any(b.evidence_verified):
            warnings.append(f"{b.id}: no evidence quote could be verified in the source (possible hallucination)")
        if b.attack_note:
            warnings.append(f"{b.id}: {b.attack_note}")
    record = RunRecord(
        run_id=run_id, created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
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


def _check_sequences(analysis: ReportAnalysis, behaviours: list[Behaviour], source_text: str, warnings: list[str]) -> None:
    """Keep only proposed sequences whose steps exist and whose quote is really in the report."""
    known, norm_source, kept = {b.id for b in behaviours}, _norm(source_text), []
    for s in analysis.sequences:
        ids = list(dict.fromkeys(s.behaviour_ids))
        if not 2 <= len(ids) <= 4 or not set(ids) <= known:
            warnings.append(f"Sequence '{s.name}' dropped: it must reference 2-4 extracted behaviours (got {', '.join(s.behaviour_ids)})")
        elif not verify_evidence(s.evidence, norm_source):
            warnings.append(f"Sequence '{s.name}' dropped: its evidence quote is not in the report (possible hallucination)")
        elif not re.fullmatch(r"[1-9]\d{0,3}[smhd]", s.within.strip()):
            warnings.append(f"Sequence '{s.name}' dropped: time window {s.within!r} is not like 10m, 1h or 1d")
        else:
            s.behaviour_ids, s.within = ids, s.within.strip()
            kept.append(s)
    analysis.sequences = kept


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
    key = f"{b.technique_id}:{b.name}"
    first = next((x for x in record.behaviours if f"{x.technique_id}:{x.name}" == key), b)
    if first.id != b.id:   # a second behaviour with the same technique and name must not share the rule id
        key += f":{b.id}"
    rule_id = st.stable_rule_id(record.report.sha256, key)
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
    for c in clients.active(settings):   # the same rule in each client's own field names
        pkg.queries += st.convert(pkg.rule_yaml, c.targets or settings.targets, c.index_overrides, c)
    # Backends with strict field validation reject fields that are not in the Sigma taxonomy. One
    # backend rejecting a field is a vendor gap (documented in the field mapping); two or more
    # means the rule itself is wrong and is worth a repair call.
    probe = st.convert(pkg.rule_yaml, [t for t in _STRICT_TARGETS if t not in settings.targets]) if \
        any(t not in settings.targets for t in _STRICT_TARGETS) else []
    field_errors = [f"{q.target}: {q.error}" for q in pkg.queries + probe
                    if not q.client and q.target in _STRICT_TARGETS and q.error and "field" in q.error.lower()]
    # Unit-test the rule against the events its own simulation should produce (and benign look-alikes).
    pkg.selftest, pkg.selftest_details = replay.selftest(pkg.rule_yaml, pkg.draft.test_events)
    selftest_issue = [f"self-test: {d}" for d in pkg.selftest_details] if pkg.selftest == "fail" else []
    untested = replay.untested_filters(pkg.rule_yaml, pkg.draft.test_events) if pkg.selftest == "pass" else []
    if untested:
        pkg.quality_warnings.append(f"Self-test does not exercise {', '.join(untested)}: no benign test event is excluded "
                                    "by it, so whether the exclusion works is untested. Add a look-alike it should drop.")
    ls = st.first_doc(pkg.rule_yaml).get("logsource") or {}
    # A rule naming both a category and a service (windows authentication + security) is covered by either.
    keys = [f"{ls.get('product', '')}:{ls[k]}" for k in ("category", "service") if ls.get(k)] or [f"{ls.get('product', '')}:"]
    key = keys[0]
    if settings.telemetry and not set(keys) & set(settings.telemetry):
        pkg.quality_warnings.append(f"Log source {key} is not in your telemetry inventory ({', '.join(settings.telemetry)}); "
                                    "this rule cannot fire until that data is collected.")
    for c in clients.active(settings):
        if c.telemetry and not set(keys) & set(c.telemetry):
            pkg.quality_warnings.append(f"Client {c.name} does not collect {key} ({', '.join(c.telemetry)}); "
                                        "this rule cannot fire there until it does.")
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


_REFERENCE_ORDER = ("elastic_esql", "splunk", "sentinel_asim", "defender_xdr", "crowdstrike_cql", "elastic_eql")


def _ai_fields(pkg: DetectionPackage, client, members: list[str], tid: str) -> dict[str, str]:
    """Sigma field -> target name the AI must use: the deterministic mapping of the target family,
    overridden by the client profile. The same map is used to check the answer."""
    cname = client.name if client is not None else ""
    out: dict[str, str] = {}
    for fm in pkg.field_mappings:
        if fm.client != cname:
            continue
        for t in members:
            v = fm.targets.get(t, "")
            if v and not v.startswith("UNSUPPORTED") and not _passthrough(t, fm.sigma_field, v):
                out[fm.sigma_field] = v
                break
    if client is not None:
        used = set(st.rule_fields(pkg.rule_yaml))
        for t in [*members, tid]:
            out.update({f: n for f, n in client.fields_for(t).items() if f in used})
    return out


def _passthrough(target: str, sigma_field: str, mapped: str) -> bool:
    """A renaming pipeline left the Sigma name unchanged: it does not know the field. Handing it to the AI as the
    target name made it copy Sysmon names (TargetObject, Details) into a CrowdStrike query that cannot match."""
    return target in RENAMING_TARGETS and mapped == sigma_field and sigma_field not in NATIVE_FIELDS.get(target, set())


def leftover_sigma_names(rule_yaml: str, query: str, fields: dict[str, str], members: list[str]) -> list[str]:
    """Sigma field names an AI gap-fill translation still uses although the SIEM's data does not have them. Not
    counted: names mapped for the AI, native names of the family's targets (SecurityEvent's EventID), and names the
    query defines itself (`extend TaskContent = ...`, `eval x=`, `x := ...`, `(?<x>...)`, `... as x`)."""
    native = set().union(*(NATIVE_FIELDS.get(t, set()) for t in members)) if members else set()
    defined: set[str] = set()
    for clause in re.split(r"\|", query):
        if re.match(r"\s*(extend|eval|project|project-rename|let|parse|rename|summarize)\b", clause, re.I):
            defined |= set(re.findall(r"\b(\w+)\s*=(?!=)", clause))
    defined |= set(re.findall(r"\b(\w+)\s*:=", query)) | set(re.findall(r"\(\?P?<(\w+)>", query)) \
        | set(re.findall(r"\bas\s+(\w+)", query, re.I))
    return [f for f in st.rule_fields(rule_yaml) if f not in fields and f not in native and f not in defined
            and re.search(rf"(?<![\w.]){re.escape(f)}(?![\w.])", query)]


def _ai_references(pkg: DetectionPackage, cname: str) -> dict[str, str]:
    """Up to two verified converter outputs, so the AI copies the logic instead of re-deriving it."""
    ok = {q.target: q for q in pkg.queries if q.client == cname and q.query and q.method != "llm"}
    picks = [t for t in _REFERENCE_ORDER if t in ok][:2]
    return {TARGETS[t].label: ok[t].query[:1200] for t in picks}


def check_ai_query(query: str, fields: dict[str, str], target: str) -> list[str]:
    """Deterministic checks of an AI translation against the field map (and XML well-formedness for Wazuh)."""
    import xml.etree.ElementTree as ET

    problems = []
    for sigma, mapped in fields.items():
        names = [n.strip() for n in mapped.split(",") if n.strip()]
        if names and not any(n in query for n in names):
            problems.append(f"does not use {names[0]} (Sigma {sigma})")
        if names and sigma not in names and re.search(rf"(?<![\w.]){re.escape(sigma)}(?![\w.])", query):
            problems.append(f"uses the Sigma name {sigma} where the target field is {names[0]}")
    if target.startswith(("sentinel", "defender")) and re.search(r"\[\s*@\w+\s*=", query):
        problems.append("uses an XPath predicate ([@Name=...]), which KQL does not have; use mv-apply over the parsed array")
    if target == "google_secops_yaral" and not (re.search(r"\brule\s+\w+\s*\{", query) and "events:" in query
                                                 and "condition:" in query):
        problems.append("not a YARA-L 2.0 rule (needs rule <name> { meta: events: condition: })")
    if target.startswith("wazuh"):
        if re.search(r"<!(DOCTYPE|ENTITY)", query, re.I):   # untrusted model output: never expand entities
            problems.append("contains DTD/entity declarations, which Wazuh rules never need")
        else:
            try:
                ET.fromstring(f"<root>{re.sub(r'<!--.*?-->', '', query, flags=re.S)}</root>")
            except ET.ParseError as e:
                problems.append(f"not well-formed XML ({e})")
    return problems


def _translate_llm(pkg: DetectionPackage, settings: Settings, llm: LLM, redaction_map: dict | None = None) -> None:
    """AI translations: configured non-pySigma SIEMs, plus families no converter could produce, for the default
    schema and each client profile. The AI gets the field map and verified reference queries, and its answer is
    checked against the same map. Correlation rules are never sent: thresholds and joins are built by code."""
    correlated = len(st.load_docs(pkg.rule_yaml)) > 1
    default_results: dict[str, QueryResult] = {}
    safe = rule_for_ai(pkg.rule_yaml)   # same AI-safe form as repair: no file name / URL references
    for client in [None, *clients.active(settings)]:
        cname = client.name if client is not None else ""
        by_target = {q.target: q for q in pkg.queries if q.client == cname}
        jobs: list[tuple[str, str, str, str, str, list[str]]] = []   # (id, label, language, hint, why, family members)
        for fam in settings.ai_fill_gaps:
            members, label, lang = FAMILIES.get(fam, ([], "", ""))
            configured = [t for t in members if t in by_target]
            if configured and all(by_target[t].error for t in configured) and not correlated:
                why = "; ".join(f"{t}: {by_target[t].error}" for t in configured)[:400]
                jobs.append((f"{fam}_ai", label, lang, FAMILY_HINTS.get(fam, ""), why, configured))
        for tid in (client.llm_targets if client is not None else settings.llm_targets):
            label, lang = LLM_TARGET_LABELS.get(tid, (tid, tid))
            if correlated:
                pkg.queries.append(QueryResult(target=tid, label=label, language=lang, method="llm", client=cname,
                                               validation="failed", error="threshold rule: correlation logic is only "
                                               "built by code, and this SIEM has no converter"))
                continue
            jobs.append((tid, label, lang, FAMILY_HINTS.get(tid, ""), "", [tid]))
        for tid, label, lang, hint, why, members in jobs:
            prev = default_results.get(tid)
            if client is not None and prev is not None and prev.query and not any(
                    client.fields_for(t) or client.index_overrides.get(t) for t in [tid, *members]) \
                    and not client.notes_for(tid):
                # Nothing client-specific to tell the AI: the default translation is the client's query too.
                pkg.queries.append(prev.model_copy(update={"client": cname, "notes": f"{prev.notes} Same as the default "
                                                           f"translation: {cname} has no field map, index or notes for it."}))
                continue
            fields = _ai_fields(pkg, client, members, tid)
            res = QueryResult(target=tid, label=label + " [AI-translated, unverified]", language=lang, method="llm",
                              client=cname)
            # The rule (and so its converted reference queries) may be a human correction: redact both in one pass.
            refs = _ai_references(pkg, cname)
            sent = _SEP.join([safe, *refs.values()])
            red = _redaction(sent, settings, redaction_map)
            rule_text, *ref_texts = (red.text if red else sent).split(_SEP)
            try:
                t = llm.structured("translate", TRANSLATE_SYSTEM,
                                   translate_user(rule_text, label, lang, hint, why, fields, dict(zip(refs, ref_texts)),
                                                  client.notes_for(tid) if client else ""),
                                   TranslationDraft)
                res.query, res.notes = _unredact(t.query.strip(), red, sent), f"confidence={t.confidence}; {t.notes}"
                problems = check_ai_query(res.query, fields, tid)
                if members != [tid]:   # gap fill for a family: unmapped Sigma names do not exist in that SIEM
                    left = leftover_sigma_names(pkg.rule_yaml, res.query, fields, members)
                    if left:
                        problems.append(f"uses Sigma field names this SIEM's data does not have: {', '.join(left)}")
                if problems:
                    res.notes += " CHECK: " + "; ".join(problems)
            except LLMError as e:
                res.error, res.validation = str(e), "failed"
            pkg.queries.append(res)
            if client is None:
                default_results[tid] = res


def _flag_unmapped_fields(pkg: DetectionPackage, settings: Settings) -> None:
    """A renaming pipeline that left a field unchanged did not map it: the query may never match.

    If NONE of the rule's fields were mapped, the pipeline does not know this log source at all (e.g. the
    CrowdStrike pipeline for Sysmon registry events): the query is marked failed so the AI gap translator
    writes a native one instead of shipping a query that can never match. For a client with a field map
    for the target, every field the map does not cover is reported, whatever the target."""
    profiles = {c.name: c for c in clients.active(settings)}
    maps: dict[tuple[str, str], dict[str, str]] = {}
    for fm in pkg.field_mappings:
        for tid, v in fm.targets.items():
            maps.setdefault((fm.client, tid), {})[fm.sigma_field] = v
    for q in pkg.queries:
        if not q.query or q.method == "llm":
            continue
        m = {f: v for f, v in maps.get((q.client, q.target), {}).items() if not v.startswith("UNSUPPORTED")}
        native = NATIVE_FIELDS.get(q.target, set())
        declared = profiles[q.client].fields_for(q.target) if q.client in profiles else {}
        if declared:
            missing = [f for f, v in m.items() if f not in declared and v == f and f not in native]
            if missing:
                q.notes = (f"{q.notes} Not in client {q.client}'s field map for {q.target} (kept the Sigma name; add them "
                           f"to the profile if the client names them differently): {', '.join(missing)}").strip()
            continue
        if q.target not in RENAMING_TARGETS:
            continue
        unmapped = [f for f, v in m.items() if v == f and f not in native]
        if m and len(unmapped) == len(m):
            q.error = (f"{q.target} pipeline has no field mapping for this log source "
                       f"({', '.join(unmapped)} passed through unchanged); it will not match normalized data")
            q.notes = f"{q.notes} Raw pass-through query, only for un-normalized data: {q.query}".strip()
            q.query, q.validation = None, "failed"
        elif unmapped:
            note = f"Fields not mapped by the {q.target} pipeline (verify they exist in your data): {', '.join(unmapped)}"
            q.notes = f"{q.notes} {note}".strip()


def finalize_package(pkg: DetectionPackage, record: RunRecord, settings: Settings, llm: LLM | None,
                     feedback_text: str = "", progress: Progress = _noop, allow_repair: bool = True,
                     redaction_map: dict | None = None) -> DetectionPackage:
    """Validate/convert, repair with the model if needed, then map fields, lint, translate.
    `redaction_map`: the run's placeholders, reused for text sent to the AI (default: read from the run folder)."""
    if llm is not None and redaction_map is None and record is not None:
        redaction_map = run_redaction_map(record, settings)
    blocking = _check(pkg, settings, record)
    while ((blocking or feedback_text) and allow_repair and llm is not None
           and pkg.repair_attempts < settings.ai.max_repair_attempts):
        pkg.repair_attempts += 1
        progress(f"{pkg.slug}: repair attempt {pkg.repair_attempts} ({len(blocking)} issue(s))")
        # The rule may be a human correction: rule and feedback are redacted in one pass (same placeholders).
        sent = _SEP.join([rule_for_ai(pkg.rule_yaml), feedback_text])
        red = _redaction(sent, settings, redaction_map)
        rule_text, fb_text = (red.text if red else sent).split(_SEP)
        fixed = llm.structured("repair", REPAIR_SYSTEM, repair_user(rule_text, blocking or ["Apply reviewer feedback."], fb_text),
                               SigmaDraft)
        if red is not None:   # values people wrote come back; placeholders from the report stay
            fixed = SigmaDraft.model_validate_json(_unredact(fixed.model_dump_json(), red, sent, quote=True))
        feedback_text = ""
        pkg.draft.sigma = fixed
        rid, ver = pkg.rule_id, pkg.version
        rule_date = str(_yaml_get(pkg.rule_yaml, "date") or date.today().isoformat())
        rebuilt = _assemble(record, pkg.behaviour, pkg.draft, settings, pkg.slug, ver, rule_date)
        pkg.rule_yaml, pkg.rule_id = rebuilt.rule_yaml, rid
        blocking = _check(pkg, settings, record)
    if pkg.sigma_status != "failed":
        pkg.field_mappings = st.field_mappings(pkg.rule_yaml, settings.targets)
        for c in clients.active(settings):
            pkg.field_mappings += st.field_mappings(pkg.rule_yaml, c.targets or settings.targets, c)
        _flag_unmapped_fields(pkg, settings)
        pkg.similar_rules = duplicates.find_similar(pkg.rule_yaml, settings)
        if llm is not None:
            _translate_llm(pkg, settings, llm, redaction_map)
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
             progress: Progress = _noop, behaviour_ids: list[str] | None = None, actor: str = "",
             redaction_map: dict | None = None) -> list[DetectionPackage]:
    obs.run_id.set(record.run_id)
    if redaction_map is None:
        redaction_map = run_redaction_map(record, settings)
    todo = [b for b in record.behaviours if (b.id in behaviour_ids if behaviour_ids else b.selected)]
    existing = {p.behaviour.id for p in record.packages}
    todo = [b for b in todo if b.id not in existing]
    retried = tuple(f"{b.id} ({b.technique_id}) not generated: " for b in todo)
    record.warnings = [w for w in record.warnings if not w.startswith(retried)]   # re-added if it fails again
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
            lessons = [redact_for_ai(x, settings, redaction_map) for x in
                       store.relevant_lessons(b.technique_id, prod, likely_categories(b), settings.ai.max_lessons_in_prompt,
                                              redact.lesson_tlps(record.report.tlp_effective,
                                                                 settings.ai.allowed_tlp.get(settings.ai.provider, [])))]
        payload = b.model_dump(include={"name", "description", "tactic", "technique_id", "technique_name",
                                        "platform", "observables", "log_sources", "detection_idea"})
        payload["observables"] = {k: v for k, v in payload["observables"].items() if v}
        evidence = [q for q, ok in zip(b.evidence, b.evidence_verified) if ok] or b.evidence
        try:
            draft = llm.structured("generate", GENERATE_SYSTEM, generate_user(payload, evidence, context, lessons), DetectionDraft)
            pkg = _assemble(record, b, draft, settings, slug)
            pkg.created_by = actor or record.created_by
            return finalize_package(pkg, record, settings, llm, progress=progress, redaction_map=redaction_map)
        except Exception as e:
            # One failed behaviour must not discard the others; it can be retried with `ti2dac generate`.
            if not isinstance(e, LLMError):
                log.exception("%s: unexpected error generating %s", slug, b.id)
                e = f"{type(e).__name__}: {e}"
            record.warnings.append(f"{b.id} ({b.technique_id}) not generated: {e}. Retry: ti2dac generate {record.run_id} --select {b.id}")
            progress(f"{slug}: FAILED ({e})")
            obs.event("rule.failed", logging.WARNING, behaviour=b.id, technique=b.technique_id, error=str(e)[:500])
            return None

    parallel = settings.ai.max_parallel or (1 if settings.ai.provider == "gemini" else 4)
    with ThreadPoolExecutor(max_workers=min(parallel, max(1, len(todo)))) as ex:
        pkgs = [p for p in ex.map(obs.in_context(one), enumerate(todo, 1)) if p is not None]
    for i, p in enumerate(pkgs, start + 1):   # keep slugs contiguous when a behaviour failed
        if p.slug != f"rule-{i:03d}":
            p.slug = f"rule-{i:03d}"
    record.packages.extend(pkgs)
    wazuh.resolve_slot_collisions(record.packages)
    rebuild_chains(record, settings, progress)
    record.usage = llm.usage
    record.usage.estimated_cost_usd = estimate_cost(record.usage, settings.ai.prices)
    return pkgs


def recheck_run_metadata(record: RunRecord, run_dir: Path, settings: Settings) -> list[str]:
    """No-AI refresh of what ti2dac derives deterministically outside the rules: IOCs (re-extracted from the
    stored source copy), revoked ATT&CK ids, and the checks on kept AI translations. Returns what changed."""
    changed = []
    src = run_dir / "source" / Path(record.report.source).name
    if src.is_file():
        try:
            fresh = extract_iocs(load_report(str(src), settings.fetch).text)
        except Exception as e:   # noqa: BLE001 - a source that no longer parses keeps the old IOCs
            changed.append(f"IOCs kept: source copy could not be re-read ({type(e).__name__})")
        else:
            if fresh != record.iocs:
                record.iocs = fresh
                changed.append("IOCs re-extracted")
    with_rule = {p.behaviour.id for p in record.packages}
    for b in record.behaviours:
        new, moved = attack.resolve_revoked(b.technique_id)
        if not moved:
            continue
        b.technique_id = new
        ok, note, name, tactic = attack.validate_mapping(new, b.technique_name, b.tactic)
        b.attack_valid, b.technique_name, b.tactic = ok, name, tactic  # type: ignore[assignment]
        b.attack_note = "; ".join(x for x in (moved, note) if x)
        record.warnings = [w for w in record.warnings if not (w.startswith(f"{b.id}: ") and "revoked" in w)]
        record.warnings.append(f"{b.id}: {b.attack_note}" + (
            f"; its rule still carries the old ATT&CK tag: regenerate it (ti2dac generate {record.run_id} "
            f"--select {b.id})" if b.id in with_rule else ""))
        changed.append(f"{b.id}: {moved}")
    for pkg in record.packages:
        for q in pkg.queries:
            if q.method != "llm" or not q.query or not q.target.endswith("_ai"):
                continue
            members = FAMILIES.get(q.target[:-3], ([], "", ""))[0]
            left = leftover_sigma_names(pkg.rule_yaml, q.query, _ai_fields(pkg, None, members, q.target), members)
            stale = re.search(r" CHECK: uses Sigma field names this SIEM's data does not have: [^;]*", q.notes)
            if stale and not left:   # an earlier, cruder check flagged names the query defines or the SIEM has
                q.notes = q.notes.replace(stale.group(0), "")
                changed.append(f"{pkg.slug} {q.target}: cleared a false Sigma-field-name flag")
            if left and not stale:
                q.notes += f" CHECK: uses Sigma field names this SIEM's data does not have: {', '.join(left)}"
                changed.append(f"{pkg.slug} {q.target}: flagged Sigma field names")
    return changed


def rebuild_chains(record: RunRecord, settings: Settings, progress: Progress = _noop) -> None:
    """(Re)build every multi-event chain from the current rule versions: the sequences the analysis proposed
    (once all their steps have rules) plus chains an analyst defined. Deterministic, no AI calls."""
    by_beh = {p.behaviour.id: p for p in record.packages}
    by_slug = {p.slug: p for p in record.packages}
    specs = []
    # Recomputed below from the current rules: last build's "needs rules for" / "not built" notes are stale,
    # and so is a "not generated" note for a behaviour that has a rule by now.
    record.warnings = [w for w in record.warnings
                       if not re.match(r"Sequence '.*' (\(.*\) needs rules for |not built: )", w)
                       and not ((m := re.match(r"(B\d+) \(.*?\) not generated: ", w)) and m.group(1) in by_beh)]
    for s in (record.analysis.sequences if record.analysis else []):
        missing = [b for b in s.behaviour_ids if b not in by_beh]
        if missing:
            beh = {b.id: b for b in record.behaviours}
            dark = [b for b in missing if b in beh and beh[b].scores.observability <= 2]
            note = f"Sequence '{s.name}' ({' -> '.join(s.behaviour_ids)}) needs rules for {', '.join(missing)} first: "
            if dark:
                # e.g. in-memory reflective loading: suggesting a log rule for it sends the analyst nowhere
                note += (f"{', '.join(dark)} scored {'/'.join(str(beh[b].scores.observability) for b in dark)}/5 for "
                         "observability, so ordinary logs probably cannot show it; build this chain only if you have "
                         f"telemetry for it (ti2dac generate {record.run_id} --select {','.join(missing)})")
            else:
                note += f"ti2dac generate {record.run_id} --select {','.join(missing)}"
            if note not in record.warnings:
                record.warnings.append(note)
            continue
        specs.append((s.name, [by_beh[b] for b in s.behaviour_ids], s.ordered, s.within, s.join_on, "analysis", s.evidence))
    for c in record.chains:
        if c.source == "analyst" and all(x in by_slug for x in c.steps):
            specs.append((c.name, [by_slug[x] for x in c.steps], c.ordered, c.within, c.join_on, "analyst", c.evidence))
    # A chain keeps its number across rebuilds (its folder and any deployed copy refer to it); new ones get the next.
    def key(source, name, step_slugs):
        return (source, name) if source == "analysis" else (source, name, tuple(step_slugs))
    prev = {key(c.source, c.name, c.steps): c.slug for c in record.chains if c.slug}
    last = max((int(x[6:]) for x in prev.values() if re.fullmatch(r"chain-\d+", x)), default=0)
    built, active = [], clients.active(settings)
    for name, steps, ordered, within, join_on, source, evidence in specs:
        slug = prev.get(key(source, name, [p.slug for p in steps]))
        if slug is None:
            last += 1
            slug = f"chain-{last:03d}"
        try:
            built.append(chains.build(steps, slug=slug, name=name, ordered=ordered, within=within,
                                      join_on=join_on, source=source, evidence=evidence, settings=settings, clients=active))
        except ValueError as e:
            record.warnings.append(f"Sequence '{name}' not built: {e}")
    record.chains = sorted(built, key=lambda c: c.slug)
    if built:
        progress(f"{len(built)} multi-event chain(s) built from the rules (no AI)")


def add_chain(record: RunRecord, settings: Settings, slugs: list[str], *, name: str, within: str, join_on: str,
              ordered: bool = True) -> None:
    """An analyst-defined chain over existing rules (same deterministic build as proposed sequences)."""
    known = {p.slug for p in record.packages}
    if not 2 <= len(slugs) <= 4 or not set(slugs) <= known:
        raise ValueError(f"a chain needs 2-4 existing rules of run {record.run_id} (have: {', '.join(sorted(known))})")
    if not re.fullmatch(r"[1-9]\d{0,3}[smhd]", within):
        raise ValueError("within must look like 10m, 1h or 1d")
    if join_on not in ("host", "user", "source_ip"):
        raise ValueError("join on host, user or source_ip")
    from .models import ChainPackage

    record.chains.append(ChainPackage(slug="", name=name, steps=slugs, ordered=ordered, within=within,
                                      join_on=join_on, source="analyst", rule_yaml=""))
    rebuild_chains(record, settings)


def run(source: str, settings: Settings, **kw) -> tuple[RunRecord, LoadedReport]:
    """Full pipeline (see _run), reported as run.finish / run.failed events."""
    t0 = time.monotonic()
    obs.run_id.set("")
    try:
        record, loaded = _run(source, settings, **kw)
    except Exception as e:
        _release_run_id(settings.output_dir, obs.run_id.get())
        obs.event("run.failed", logging.WARNING, error_type=type(e).__name__, error=str(e)[:500],
                  duration_s=round(time.monotonic() - t0, 1))
        raise
    u = record.usage
    obs.event("run.finish", kind=record.report.kind, tlp=record.report.tlp_effective, ai=record.ai_enabled,
              behaviours=len(record.behaviours), rules=len(record.packages),
              rules_failed=sum(1 for w in record.warnings if " not generated: " in w), warnings=len(record.warnings),
              ai_calls=u.calls, ai_cached_calls=u.cached_calls, input_tokens=u.input_tokens, output_tokens=u.output_tokens,
              cost_usd=u.estimated_cost_usd, duration_s=round(time.monotonic() - t0, 1))
    return record, loaded


def _run(source: str, settings: Settings, *, count: int | None = None, explicit: list[str] | None = None,
         raw: bytes | None = None, filename: str | None = None, store: Store | None = None,
         progress: Progress = _noop, actor: str = "", incident: bool | None = None, tlp_override: str = "",
         evidence_events: list[dict] | None = None) -> tuple[RunRecord, LoadedReport]:
    attack.set_override_dir(settings.state_dir)
    loaded = load_report(source, settings.fetch, raw=raw, filename=filename)
    progress(f"ingested {loaded.meta.title!r} ({loaded.meta.content_type}, {loaded.meta.chars} chars, sha256 {loaded.meta.sha256[:12]})")
    prepare_report(loaded, settings, incident=incident, tlp_override=tlp_override, progress=progress)
    llm = LLM(settings, tlp=loaded.meta.tlp_effective) if settings.ai.enabled else None
    record, _ = analyze(loaded, settings, llm, progress)
    obs.run_id.set(record.run_id)
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
        generate(record, settings, llm, store, progress, actor=actor, redaction_map=loaded.redaction_map)
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
# [^\S\n], not \s: a \s* that spans blank lines rescans them from every line start (quadratic on whole reports).
_EVENT_LINE = re.compile(r"^[^\S\n]*(\{.*\})[^\S\n]*,?[^\S\n]*$", re.M)


def looks_like_incident(text: str) -> bool:
    return len({m.group(0).lower() for m in _INCIDENT_HINTS.finditer(text[:100_000])}) >= 3


def extract_embedded_events(text: str) -> list[dict]:
    """Raw log events pasted into a report (JSON lines), e.g. Sysmon/EDR records in an evidence section."""
    events = []
    for m in _EVENT_LINE.finditer(text):
        try:
            obj = json.loads(m.group(1))
            ev = replay.normalize_event(obj) if isinstance(obj, dict) and len(obj) >= 2 else None
        except (ValueError, RecursionError):   # deeply nested JSON: not a log event
            continue
        if ev is not None and any(k in ev for k in ("EventID", "Image", "CommandLine", "TargetObject", "ScriptBlockText",
                                                    "QueryName")):
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
        sep = _SEP   # keeps title and body in one pass so placeholders are consistent
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
        pkg.evidence_matches, pkg.evidence_total = len(hits), scoped   # events of the rule's log source type
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
                     actor: str = "", redaction_map: dict | None = None) -> DetectionPackage:
    """Create rule version n+1 from a human-corrected YAML or (with AI) from feedback text.
    Text sent to the AI is redacted with the run's placeholders (`redaction_map`, default: the run folder's)."""
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
        if isinstance(data["detection"], dict):
            data["detection"] = st.hoist_regex_flags(data["detection"])
        data["id"] = old.rule_id                     # identity is stable across versions
        data["modified"] = date.today().isoformat()
        new.rule_yaml = st.dump_docs(docs)
        new.draft.sigma.title = str(data.get("title", new.draft.sigma.title))
        new.draft.sigma.level = data.get("level", new.draft.sigma.level)
        new.draft.sigma.falsepositives = list(data.get("falsepositives") or [])
        # Never let the model rewrite a human correction; it may only fill SIEM query gaps.
        finalize_package(new, record, settings, llm, progress=progress, allow_repair=False, redaction_map=redaction_map)
    else:
        if llm is None:
            raise ValueError("no corrected rule supplied and AI is disabled")
        # Start from the CURRENT rule (which may be a human correction), never from the original AI draft.
        new.rule_yaml = st.set_status(old.rule_yaml, "experimental", modified=date.today().isoformat())
        finalize_package(new, record, settings, llm, feedback_text=feedback_text, progress=progress,
                         redaction_map=redaction_map)
    if new.sigma_status == "failed":
        raise ValueError("corrected rule does not validate: " + "; ".join(new.sigma_issues[:5]))
    record.packages[idx] = new
    wazuh.resolve_slot_collisions(record.packages)
    rebuild_chains(record, settings, progress)
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


def _redaction(text: str, settings: Settings, known: dict | None = None) -> redact.Redaction | None:
    if not text or not settings.redaction.enabled:
        return None
    rc = settings.redaction
    return redact.redact(text, internal_domains=rc.internal_domains, internal_networks=rc.internal_networks,
                         terms=rc.terms, hostname_patterns=rc.hostname_patterns, known=known)


def redact_for_ai(text: str, settings: Settings, known: dict | None = None) -> str:
    """Text written by people (feedback comments, lessons, corrected rules) is redacted like reports before any
    prompt. `known`: the run's redaction map, so hosts/users learned from the report stay hidden here too."""
    red = _redaction(text, settings, known)
    return red.text if red else text


def _unredact(answer: str, red: redact.Redaction | None, sent: str, quote: bool = False) -> str:
    """Put back the values this redaction hid (placeholders already in `sent` before redaction stay).
    `quote`: the answer is JSON text."""
    if red is None:
        return answer
    hidden = {ph: red.mapping[ph] for ph in set(redact.PLACEHOLDER.findall(red.text)) - set(redact.PLACEHOLDER.findall(sent))
              if ph in red.mapping}
    return redact.PLACEHOLDER.sub(lambda m: (json.dumps(hidden[m[0]])[1:-1] if quote else hidden[m[0]])
                                  if m[0] in hidden else m[0], answer)


def run_redaction_map(record: RunRecord, settings: Settings) -> dict[str, str]:
    """The run's placeholder map (source/redaction-map.json, written by render; never sent anywhere)."""
    dirs = [Path(settings.output_dir) / record.run_id]
    if Path(settings.db_path).is_file():
        p = Store(settings.db_path).run_path(record.run_id)
        if p:
            dirs.insert(0, Path(p))
    for d in dirs:
        try:
            data = json.loads((d / "source" / "redaction-map.json").read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    return {}


def rule_for_ai(rule_yaml: str) -> str:
    """Detection-relevant part of a rule for repair prompts: no id/author/references/dates (file names, URLs)."""
    import yaml

    keep = ("title", "description", "logsource", "detection", "falsepositives", "level", "correlation", "name")
    docs = [{k: v for k, v in d.items() if k in keep} for d in st.load_docs(rule_yaml)]
    return "---\n".join(yaml.safe_dump(d, sort_keys=False, allow_unicode=True) for d in docs)
