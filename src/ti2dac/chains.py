"""Multi-event detections ("brute force, then a successful logon, then a new scheduled task within 10 minutes").

Language models are reliable at single-event logic and unreliable at stateful joins, so the join is never
written by the model: each step is an already generated (and validated) single-event rule, and this module
joins them with a Sigma correlation rule (temporal / temporal_ordered) and, where a pySigma backend cannot
convert that, with a fixed per-language template (KQL union + summarize, EQL sequence).
"""
from __future__ import annotations

import uuid

from . import sigma_tools as st
from .correlate import HOST_COLUMN, KQL_TARGETS
from .models import ChainPackage, DetectionPackage, QueryResult
from .targets import TARGETS, make_backend

_TIME_COLUMN = {"defender_xdr": "Timestamp"}


def join_field(base_doc: dict, join_on: str) -> str:
    """The Sigma field carrying the host / user / source IP for a rule's log source."""
    ls = base_doc.get("logsource") or {}
    product, category, service = ls.get("product", ""), ls.get("category", ""), ls.get("service", "")
    if join_on == "host":
        return "Computer" if product == "windows" else "Hostname"
    if join_on == "user":
        if product == "windows" and service in ("security", "system"):
            return "TargetUserName"
        return "User"
    if category == "firewall":
        return "src_ip"
    if category in ("webserver", "proxy"):
        return "c-ip"
    if product == "windows" and service == "security":
        return "IpAddress"
    return "SourceIp"


def _name(slug: str) -> str:
    return "ti2dac_" + slug.replace("-", "_")


def build_yaml(steps: list[DetectionPackage], *, name: str, ordered: bool, within: str, join_on: str,
               author: str) -> tuple[str, list[dict], list[str], list[str]]:
    """(rule YAML, step base docs, step join fields, warnings)."""
    docs, fields, warnings = [], [], []
    for p in steps:
        base = dict(st.first_doc(p.rule_yaml))
        if len(st.load_docs(p.rule_yaml)) > 1:
            warnings.append(f"{p.slug} is a threshold rule; the chain uses its single event, not its threshold")
        base["name"] = _name(p.slug)
        base["level"] = "informational"   # each step alone is context; the chain is the alert
        docs.append(base)
        fields.append(join_field(base, join_on))
    key = "|".join(p.rule_id for p in steps) + f"|{within}|{join_on}|{ordered}"
    corr = {
        "title": f"{name} (sequence)",
        "id": str(uuid.uuid5(st.RULE_NAMESPACE, "chain:" + key)),
        "status": "experimental",
        "description": f"{' then '.join(p.draft.sigma.title for p in steps)}, on the same {join_on.replace('_', ' ')} "
                       f"within {within}. Built by ti2dac from separately validated rules.",
        "author": author,
        "tags": sorted({t for d in docs for t in d.get("tags") or []}),
        "correlation": {
            "type": "temporal_ordered" if ordered else "temporal",
            "rules": [d["name"] for d in docs],
            "group-by": ["ti2dac_join"],
            "timespan": within,
            "aliases": {"ti2dac_join": {d["name"]: f for d, f in zip(docs, fields)}},
        },
        "falsepositives": ["Each step alone is common; review the combination"],
        "level": "high",
    }
    return st.dump_docs([*docs, corr]), docs, fields, warnings


def _kql(target: str, step_queries: list[str], keys: list[str], ordered: bool, within: str) -> tuple[str, str]:
    t = _TIME_COLUMN.get(target, "TimeGenerated")
    lets = [f"let Step{i} = {q}\n| extend JoinKey = tostring({k}), Step = {i};"
            for i, (q, k) in enumerate(zip(step_queries, keys), 1)]
    n = len(step_queries)
    aggs = ["Steps = dcount(Step)", f"FirstSeen = min({t})", f"LastSeen = max({t})"]
    where = [f"Steps == {n}"]
    note = "Built by ti2dac (deterministic template, not AI). Fixed time bins: run every half-window."
    if ordered:
        aggs += [f"First{i} = minif({t}, Step == {i}), Last{i} = maxif({t}, Step == {i})" for i in range(1, n + 1)]
        where += [f"First{i} <= Last{i + 1}" for i in range(1, n)]
        note += " Order check is approximate (the first step i is before the last step i+1)."
    q = "\n".join(lets) + f"\nunion {', '.join(f'Step{i}' for i in range(1, n + 1))}\n" \
        f"| summarize {', '.join(aggs)} by JoinKey, bin({t}, {within})\n| where {' and '.join(where)}"
    return q, note


def _spl(step_queries: list[str], keys: list[str], ordered: bool, within: str) -> tuple[str, str]:
    subs = "\n".join(f"    [search {q} | eval step={i}, join_key={k}]" for i, (q, k) in enumerate(zip(step_queries, keys), 1))
    n = len(step_queries)
    aggs = ["dc(step) as steps", "min(_time) as first_seen", "max(_time) as last_seen"]
    where = [f"steps={n}"]
    note = "Built by ti2dac (deterministic template, not AI). Fixed time bins: run every half-window."
    if ordered:
        aggs += [f"min(eval(if(step={i}, _time, null()))) as first{i} max(eval(if(step={i}, _time, null()))) as last{i}"
                 for i in range(1, n + 1)]
        where += [f"first{i}<=last{i + 1}" for i in range(1, n)]
        note += " Order check is approximate (the first step i is before the last step i+1)."
    q = (f"| multisearch\n{subs}\n| bin _time span={within}\n| stats {' '.join(aggs)} by join_key _time\n"
         f"| where {' AND '.join(where)}")
    return q, note


def _esql(step_queries: list[str], keys: list[str], ordered: bool, within: str) -> tuple[str, str]:
    import re

    conds, sources = [], []
    for q in step_queries:
        m = re.fullmatch(r"(?s)\s*from\s+(\S+)(?:\s+metadata\s+[\w, ]+?)?\s*\|\s*where\s+(.+)", q)
        if not m or "|" in m.group(2):
            raise ValueError("unexpected ES|QL query shape")
        sources.append(m.group(1))
        conds.append(m.group(2).strip())
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[within[-1]]
    step = "case(" + ", ".join(f"{c}, {i}" for i, c in enumerate(conds, 1)) + ")"
    key = "case(" + ", ".join(f"step == {i}, {k}" for i, k in enumerate(keys, 1)) + ")"
    source = ",".join(dict.fromkeys(x for s in sources for x in s.split(",")))   # every step's index pattern
    q = (f"from {source} metadata _id, _index\n| where {' or '.join(f'({c})' for c in conds)}\n"
         f"| eval step = {step}\n| eval join_key = {key}, timebucket = date_trunc({within[:-1]} {unit}, @timestamp)\n"
         f"| stats steps = count_distinct(step), first_seen = min(@timestamp), last_seen = max(@timestamp) by timebucket, join_key\n"
         f"| where steps == {len(conds)}")
    note = "Built by ti2dac (deterministic template, not AI). Fixed time bins: run every half-window."
    if ordered:
        note += " Step order is not enforced here; use the EQL version for an ordered sequence."
    return q, note


def _eql(step_queries: list[str], keys: list[str], ordered: bool, within: str) -> tuple[str, str]:
    body = "\n".join(f"  [{q}] by {k}" for q, k in zip(step_queries, keys))
    note = "Built by ti2dac (deterministic template, not AI)."
    if not ordered:
        note += " EQL sequences are ordered; the steps are in report order."
    return f"sequence with maxspan={within}\n{body}", note


_TEMPLATES = {**{t: None for t in KQL_TARGETS}, "elastic_eql": _eql, "splunk": _spl, "elastic_esql": _esql}


def queries(rule_yaml: str, docs: list[dict], fields: list[str], join_on: str, ordered: bool, within: str,
            target_ids: list[str], client=None, index_overrides: dict[str, str] | None = None) -> list[QueryResult]:
    from sigma.collection import SigmaCollection

    out = []
    product = (docs[0].get("logsource") or {}).get("product", "")
    for tid in target_ids:
        t = TARGETS.get(tid)
        if t is None:
            continue
        res = QueryResult(target=tid, label=t.label, language=t.language, method="pysigma",
                          client=client.name if client is not None else "")
        try:   # 1. the backend's own correlation support
            q = make_backend(t, product, client).convert(SigmaCollection.from_yaml(rule_yaml))
            res.query = (q if isinstance(q, str) else "\n".join(map(str, q))).strip() or None
            if res.query:
                res.query = st.apply_index_override(tid, res.query, (index_overrides or {}).get(tid, ""))
            if res.query:
                out.append(res)
                continue
        except Exception as e:
            res.error = st._short_error(e)
        if tid not in _TEMPLATES:
            res.error = f"no multi-event template for {tid} ({res.error or 'empty result'}); not sent to the AI"
            res.validation = "failed"
            out.append(res)
            continue
        # 2. ti2dac template over the separately converted steps
        step_q, keys = [], []
        for d, f in zip(docs, fields):
            (q1,) = st.convert(st.dump_docs([{k: v for k, v in d.items() if k != "name"}]), [tid], index_overrides, client)
            key = HOST_COLUMN.get(tid) if join_on == "host" else st.map_field(d, f, tid, client)
            if not q1.query or not key or key.startswith("UNSUPPORTED"):
                res.error = f"step {d.get('title')!r} does not convert for {tid}: {q1.error or key}"
                break
            step_q.append(q1.query)
            keys.append(key)
        else:
            try:
                q, note = (_kql(tid, step_q, keys, ordered, within) if tid in KQL_TARGETS
                           else _TEMPLATES[tid](step_q, keys, ordered, within))
                res.query, res.error, res.method, res.notes = q, None, "template", note
            except ValueError as e:
                res.error = f"{tid} template: {e}"
        if res.error:
            res.validation = "failed"
        out.append(res)
    return out


def build(steps: list[DetectionPackage], *, slug: str, name: str, ordered: bool, within: str, join_on: str,
          source: str, evidence: str, settings, clients=()) -> ChainPackage:
    rule_yaml, docs, fields, warnings = build_yaml(steps, name=name, ordered=ordered, within=within,
                                                   join_on=join_on, author=settings.author)
    ok, issues = st.validate_rule(rule_yaml)
    if not ok:
        raise ValueError(f"chain {name!r} is not a valid Sigma correlation: {'; '.join(issues)[:300]}")
    qs = queries(rule_yaml, docs, fields, join_on, ordered, within, settings.targets, None, settings.index_overrides)
    for c in clients:
        qs += queries(rule_yaml, docs, fields, join_on, ordered, within, c.targets or settings.targets, c, c.index_overrides)
    unknown = [f"{d['name']}: {f}" for d, f in zip(docs, fields) if f in ("Hostname", "SourceIp", "User")
               and (d.get("logsource") or {}).get("product") != "windows"]
    if unknown:
        warnings.append(f"join field guessed for non-Windows steps ({', '.join(unknown)}); check it in the rule file")
    return ChainPackage(slug=slug, name=name, steps=[p.slug for p in steps], ordered=ordered, within=within,
                        join_on=join_on, source=source, evidence=evidence, rule_yaml=rule_yaml, queries=qs,
                        warnings=warnings)
