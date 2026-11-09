"""AI review of a finished run: a second opinion on everything the run produced, checked against the report.

Started on request, never automatically (web: the run page's "AI review" card; CLI: `ti2dac ai-review`):
  1. ti2dac's own checks (free, deterministic) find what code can see reliably: selections the condition never
     uses, KQL string operators given a `*` (a literal star in KQL), IOCs cut in two at a PDF line break, and
     encryption keys listed as file hashes.
  2. Unless "code checks only" was chosen, one call to the chosen model reads the report and the run's outputs
     and lists mistakes. A finding that rests on the report must quote it; quotes are machine-checked and a
     finding whose quote is not in the report is set aside as discarded, not shown as a finding.
Findings never change the run. An analyst accepts or dismisses each one: an accepted rule, query or simulation
finding becomes open feedback on that rule, fixed through the normal feedback flow (versioned, and a lesson
once applied); an accepted analysis or IOC finding is recorded as a run warning.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from pathlib import Path

from . import pipeline, redact
from .condense import condense, est_tokens
from .config import Settings
from .ingest import load_report
from .llm import LLM, price
from .models import ReviewDraft, ReviewFinding, RunRecord, RunReview
from .prompts import PROMPT_VERSION, REVIEW_SYSTEM, compact, review_user

CODE_ONLY = ""                   # provider value of a review without an AI call
_OUTPUT_TOKENS_EST = 5000        # thinking + findings, for the cost estimate shown before a review


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- state
def versions(record: RunRecord) -> dict[str, int]:
    return {p.slug: p.version for p in record.packages}


def out_of_date(record: RunRecord) -> list[str]:
    """What changed since the latest review, e.g. ['rule-001 v1 → v2', 'rule-004 added']; [] = current."""
    if record.review is None:
        return []
    old, new = record.review.versions, versions(record)
    return ([f"{s} v{old[s]} → v{v}" for s, v in new.items() if s in old and old[s] != v]
            + [f"{s} added" for s in new if s not in old] + [f"{s} removed" for s in old if s not in new])


def status(data: dict) -> dict:
    """Short state from run.json data (the runs list reads it raw): {state, open, total} with state one of
    none (never reviewed), open (findings await a decision), clean (nothing found), done (all decided),
    stale (a rule changed since the review)."""
    rv = data.get("review")
    if not rv:
        return {"state": "none", "open": 0, "total": 0}
    findings = rv.get("findings") or []
    n_open = sum(f.get("status", "open") == "open" for f in findings)
    now = {p.get("slug"): p.get("version", 1) for p in data.get("packages") or []}
    state = ("stale" if now != (rv.get("versions") or {}) else "open" if n_open
             else "clean" if not findings else "done")
    return {"state": state, "open": n_open, "total": len(findings)}


# --------------------------------------------------------------------------- the report as the run saw it
def source_text(record: RunRecord, run_dir: Path, settings: Settings) -> str:
    """Re-read the report from the run folder and redact it with the run's own placeholders."""
    src = Path(run_dir) / "source"
    try:
        _digest, name = (src / "SHA256SUMS").read_text().splitlines()[0].split("  ", 1)
    except (OSError, ValueError, IndexError):
        raise ValueError("the run folder has no source report (source/SHA256SUMS); a review needs the report") from None
    path = src / name.strip()
    if path.resolve().parent != src.resolve() or not path.is_file():
        raise ValueError(f"source report {name.strip()!r} is missing from the run folder")
    loaded = load_report(str(path), settings.fetch)
    if loaded.meta.sha256 != record.report.sha256:
        raise ValueError("the report in the run folder is not the one this run analysed (SHA-256 differs)")
    return pipeline.redact_for_ai(loaded.text, settings, known=pipeline.run_redaction_map(record, settings))


# --------------------------------------------------------------------------- ti2dac's own checks
_DANGLING = re.compile(r"DanglingDetectionIssue.*detection_name=([\w*-]+)")
# A KQL string operator whose literal holds "*": KQL has no wildcards there, so the star must be in the data.
_KQL_STAR = re.compile(r'(?<![\w!])(!?(?:endswith|startswith|contains|has|hasprefix|hassuffix)(?:_cs)?|=~|==|!=|!~)'
                       r'\s+@?"((?:[^"\\\n]|\\.)*\*(?:[^"\\\n]|\\.)*)"')
_TOKEN = r"[\w.\\-]+"
_KEY_CONTEXT = re.compile(r"(?i)\b(?:rc4|aes|xor|chacha20|salsa20|des|hex|encryption|decryption|session|api)\s+key\b"
                          r"|\bkey\s*[:=(]?\s*$")
_HASH_CONTEXT = re.compile(r"(?i)md5|sha-?(?:1|256|512)|\bhash|imphash|ssdeep|tlsh")
_IOC_CUT_TYPES = ("domains", "urls", "mutexes", "file_paths", "registry_keys", "file_names")


def _cut_ioc(value: str, text: str) -> str:
    """The full value when `value` is one half of a token split by a line break (PDF table cells wrap
    mid-word) and the joined token appears elsewhere in the report; else ''."""
    v = re.escape(value)
    for m in re.finditer(rf"({_TOKEN})[ \t]*\n[ \t]*{v}(?![\w\\-])", text):
        joined = m.group(1) + value
        if joined in text:
            return joined
    for m in re.finditer(rf"(?<![\w\\-]){v}[ \t]*\n[ \t]*({_TOKEN})", text):
        joined = (value + m.group(1)).rstrip(".")
        if joined != value and joined in text:
            return joined
    return ""


def _key_not_hash(value: str, text: str) -> bool:
    """The report calls the value a key ('RC4 key', 'key:') and never a hash next to it, so it is not a file hash."""
    before = [text[max(0, m.start() - 40):m.start()] for m in re.finditer(re.escape(value), text)]
    return any(_KEY_CONTEXT.search(b) for b in before) and not any(_HASH_CONTEXT.search(b) for b in before)


def code_checks(record: RunRecord, text: str) -> list[ReviewFinding]:
    out: list[ReviewFinding] = []

    def add(**kw) -> None:
        kw.setdefault("siem", "")
        kw.setdefault("report_quote", "")
        out.append(ReviewFinding(id="", source="code", **kw))

    for p in record.packages:
        for issue in p.sigma_issues:
            m = _DANGLING.search(issue)
            if m:
                add(area="rule", target=p.slug, category="logic_error", severity="medium",
                    problem=f"Selection '{m[1]}' is defined but the condition never uses it, so it has no effect. Its fields "
                            "still reach every SIEM converter, and a field a backend lacks fails that whole conversion.",
                    suggested_fix=f"Reference '{m[1]}' in the condition if it is needed, otherwise delete it.")
        for q in p.queries:
            if q.language != "KQL" or not q.query:
                continue
            bad = sorted({f'{m[1]} "{m[2]}"' for m in _KQL_STAR.finditer(q.query)})
            if bad:
                who = f" ({q.client})" if q.client else ""
                add(area="query", target=p.slug, siem=q.target, category="translation_error", severity="high",
                    problem=f"{q.label}{who}: {', '.join(bad)[:200]}. KQL string operators have no wildcards, so the "
                            "'*' is matched as a literal character and the condition (almost) never matches.",
                    suggested_fix="Drop the '*' (use the operator's own semantics, e.g. endswith/contains), or use "
                                  "'matches regex'.")
    iocs = record.iocs
    for kind in _IOC_CUT_TYPES:
        for value in getattr(iocs, kind):
            joined = _cut_ioc(value, text)
            if joined:
                add(area="ioc", target=f"iocs.{kind}", category="wrong_ioc", severity="high",
                    problem=f"'{value}' is only part of '{joined}': the report breaks it across two lines and the IOC "
                            "extractor kept one half.",
                    suggested_fix=f"Use '{joined}' and drop '{value}'.")
    for kind in ("md5", "sha1", "sha256"):
        for value in getattr(iocs, kind):
            if _key_not_hash(value, text):
                add(area="ioc", target=f"iocs.{kind}", category="wrong_ioc", severity="medium",
                    problem=f"'{value}' is described as a key in the report, not as a file hash; as a {kind.upper()} "
                            "IOC it would never match a file.",
                    suggested_fix=f"Remove it from the {kind.upper()} indicators (keep it as analysis context).")
    return out


# --------------------------------------------------------------------------- what the reviewer sees
def outputs(record: RunRecord) -> dict:
    """The run's outputs in compact form. pySigma-converted queries are left out (deterministic; the code
    checks cover them); AI-translated queries go in full."""
    rule_of = {p.behaviour.id: p.slug for p in record.packages}
    beh = [{"id": b.id, "name": b.name, "description": b.description, "technique": f"{b.technique_id} {b.technique_name}",
            "tactic": b.tactic, "rule": rule_of.get(b.id, ""),
            "evidence": [{"quote": q, "found_in_report": ok} for q, ok in zip(b.evidence, b.evidence_verified)]}
           for b in record.behaviours]
    rules = []
    for p in record.packages:
        sim = p.draft.simulation
        rules.append({
            "slug": p.slug, "version": p.version, "behaviour": p.behaviour.id, "sigma": pipeline.rule_for_ai(p.rule_yaml),
            "self_test": p.selftest,
            "test_events": [{"should_match": e.should_match, "description": e.description,
                             "fields": {f.name: f.value for f in e.fields}} for e in p.draft.test_events],
            "simulation": {"language": sim.language, "simulate": sim.simulate, "cleanup": sim.cleanup,
                           "expected_events": [e.model_dump() for e in sim.expected_events]},
            "llm_queries": [{"siem": q.target, "client": q.client, "method": "llm", "query": q.query, "notes": q.notes}
                            for q in p.queries if q.method == "llm" and q.query],
            "not_converted": {q.target + (f"/{q.client}" if q.client else ""): (q.error or "")[:120]
                              for q in p.queries if not q.query},
        })
    iocs = {k: v for k, v in record.iocs.model_dump().items() if v and k not in ("excluded", "attack_ids")}
    return {"behaviours": beh, "iocs": iocs, "rules": rules}


def estimate_tokens(record: RunRecord, settings: Settings) -> int:
    """Rough input size of an AI review of this run (report budget + outputs + instructions)."""
    return (min(settings.ai.review_input_token_budget, int(record.report.chars / 4) + 1)
            + est_tokens(compact(outputs(record))) + est_tokens(REVIEW_SYSTEM))


def estimate_cost(tokens_in: int, model: str, settings: Settings) -> float | None:
    """List-price estimate in USD for a review of `tokens_in` input tokens; None when the model is unpriced."""
    p = price(model, settings.ai.prices)
    return round((tokens_in * p[0] + _OUTPUT_TOKENS_EST * p[1]) / 1e6, 4) if p else None


# --------------------------------------------------------------------------- policy
def settings_for(settings: Settings, provider: str, model: str) -> Settings:
    """A copy of the settings that sends the review stage to `provider`/`model`."""
    s = copy.deepcopy(settings)
    s.ai.provider = provider
    s.ai.review.model = model
    return s


def policy_problem(record: RunRecord, settings: Settings, provider: str) -> str:
    """Why this run's report may not go to `provider` ('' = it may)."""
    if not settings.ai.enabled:
        return "AI is disabled"
    tlp = record.report.tlp_effective or "clear"
    if redact.tlp_allowed(tlp, settings.ai.allowed_tlp.get(provider, [])):
        return ""
    if record.report.tlp_override and provider == record.ai_provider:   # the data owner approved this provider
        return ""
    return f"TLP:{tlp.upper()} may not be sent to {provider} (ai.allowed_tlp)"


# --------------------------------------------------------------------------- the review
def _target(f) -> tuple[str, str]:
    """Normalise 'rule-001/defender_ai' or 'rule-001 defender_ai' into (rule-001, defender_ai)."""
    t = f.target.strip()
    m = re.match(r"(rule-\d{3})[\s/:]+([\w-]+)$", t)
    if m:
        return m[1], f.siem or m[2]
    return t, f.siem.strip()


def _carry(new: list[ReviewFinding], old: RunReview | None) -> None:
    """A finding identical to one already decided keeps that decision (code checks repeat word for word)."""
    if old is None:
        return
    decided = {(f.source, f.area, f.target, f.siem, f.problem): f for f in old.findings if f.status != "open"}
    for f in new:
        prev = decided.get((f.source, f.area, f.target, f.siem, f.problem))
        if prev is not None:
            f.status, f.decided_by, f.decided_at = prev.status, prev.decided_by, prev.decided_at
            f.note, f.feedback_id = prev.note, prev.feedback_id


def run_review(record: RunRecord, run_dir: Path, settings: Settings, llm: LLM | None, actor: str,
               progress=lambda _m: None) -> RunReview:
    """Review the run with `llm` (None = code checks only). Returns the review; the caller stores it."""
    text = source_text(record, run_dir, settings)
    found = code_checks(record, text)
    progress(f"code checks: {len(found)} finding(s)")
    review = RunReview(created_at=_now(), created_by=actor, versions=versions(record), prompt_version=PROMPT_VERSION)
    discarded: list[ReviewFinding] = []
    if llm is not None:
        cond = condense(text, settings.ai.review_input_token_budget)
        review.report_tokens = cond.condensed_tokens
        old = record.review
        dismissed = [f"[{f.area} {f.target}{'/' + f.siem if f.siem else ''}] {f.problem}"
                     + (f" (analyst: {f.note})" if f.note else "")
                     for f in (old.findings if old else []) if f.status == "dismissed"]
        checks = [f"[{f.area} {f.target}{'/' + f.siem if f.siem else ''}] {f.problem}" for f in found]
        sent = review_user(record.report.title, cond.text, outputs(record), checks, dismissed)
        # Outputs can hold text people wrote (corrected rules); redact the prompt like other AI calls.
        red = pipeline._redaction(sent, settings, pipeline.run_redaction_map(record, settings))
        cfg = settings.ai.review
        progress(f"AI review with {settings.ai.provider} {cfg.model} (~{est_tokens(sent):,} input tokens)")
        draft = llm.structured("review", REVIEW_SYSTEM, red.text if red else sent, ReviewDraft)
        if red is not None:   # values this pass hid come back; the report's own placeholders stay
            draft = ReviewDraft.model_validate_json(pipeline._unredact(draft.model_dump_json(), red, sent, quote=True))
        review.provider, review.model, review.summary = settings.ai.provider, cfg.model, draft.summary
        norm = pipeline._norm(text)
        for d in draft.findings:
            target, siem = _target(d)
            f = ReviewFinding(**{**d.model_dump(), "target": target, "siem": siem}, id="", source="ai")
            f.quote_verified = bool(f.report_quote.strip()) and pipeline.verify_evidence(f.report_quote, norm)
            if f.report_quote.strip() and not f.quote_verified:
                f.note = "report quote not found in the report"
                discarded.append(f)
            elif f.category == "missed_behaviour" and not f.quote_verified:
                f.note = "a missed behaviour needs a quote from the report"
                discarded.append(f)
            else:
                found.append(f)
        review.cost_usd = round(llm.usage.estimated_cost_usd, 6)
        review.unpriced = bool(llm.usage.unpriced_models)
        progress(f"AI review: {len(draft.findings)} finding(s), {len(discarded)} discarded (quote not in the report)")
    for i, f in enumerate(found, 1):
        f.id = f"F{i}"
    for i, f in enumerate(discarded, 1):
        f.id = f"D{i}"
    _carry(found, record.review)
    review.findings, review.discarded = found, discarded
    return review


# --------------------------------------------------------------------------- decisions
def rule_of(record: RunRecord, f: ReviewFinding) -> str:
    """The rule slug a finding is about ('' = none): rule-xxx targets, or a behaviour that has a rule."""
    slugs = {p.slug for p in record.packages}
    if f.target in slugs:
        return f.target
    return next((p.slug for p in record.packages if p.behaviour.id == f.target), "")


ARTIFACT = {"rule": "sigma_rule", "query": "query", "simulation": "simulation", "analysis": "behaviour", "ioc": "other"}


def feedback_comment(f: ReviewFinding, review: RunReview) -> str:
    who = f"{review.provider} {review.model}" if f.source == "ai" else "ti2dac checks"
    s = f"AI review {f.id} ({who}): {f.problem}"
    if f.report_quote and f.quote_verified:
        s += f' Report: "{f.report_quote}"'
    if f.suggested_fix:
        s += f" Suggested fix: {f.suggested_fix}"
    return s


def warning_text(f: ReviewFinding) -> str:
    """The run warning an accepted analysis/IOC finding becomes (removed again if it is reopened)."""
    return f"AI review {f.id} (accepted) [{f.target}]: {f.problem}" + (f" Fix: {f.suggested_fix}" if f.suggested_fix else "")


def finding(record: RunRecord, fid: str) -> ReviewFinding:
    if record.review is None:
        raise LookupError("this run has no review")
    f = next((x for x in record.review.findings if x.id == fid), None)
    if f is None:
        raise LookupError(f"no finding {fid}")
    return f
