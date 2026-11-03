"""Correlation queries assembled by code, never by the AI.

The model only writes single-event detection logic. Where a pySigma backend cannot convert a Sigma
correlation rule, ti2dac converts the base (single-event) rule with the backend and adds the aggregation
from a fixed template per query language, so thresholds stay deterministic and reviewable.
"""
from __future__ import annotations

import re

# Sigma host field -> the host column of each target (pySigma pipelines map it inconsistently or not at all).
_HOST_FIELDS = {"Computer", "ComputerName", "Hostname", "host"}
HOST_COLUMN = {
    "sentinel_asim": "DvcHostname", "sentinel_securityevent": "Computer", "defender_xdr": "DeviceName",
    "crowdstrike_cql": "ComputerName", "qradar_aql": "LOGSOURCENAME(logsourceid)", "splunk": "host",
    "splunk_cim": "dest", "elastic_lucene": "host.name", "elastic_esql": "host.name", "elastic_eql": "host.name",
    "opensearch": "host.name", "wazuh_indexer": "agent.name", "wazuh_rule": "win.system.computer", "loki": "host",
}
_TIME_COLUMN = {"defender_xdr": "Timestamp"}   # KQL; others use TimeGenerated
KQL_TARGETS = {"sentinel_asim", "sentinel_securityevent", "defender_xdr"}
_THRESHOLD_SETTINGS = {
    "elastic_lucene": "an Elastic Security threshold rule",
    "opensearch": "an OpenSearch bucket-level monitor",
    "wazuh_indexer": "a Wazuh dashboard visualization or an OpenSearch monitor (for alerting use the wazuh_rule output)",
}


def parse(rule_yaml_docs: list[dict]) -> dict | None:
    """The correlation of a ti2dac rule file: {type, group_by, timespan, gte, field}, or None."""
    for d in rule_yaml_docs[1:]:
        c = d.get("correlation")
        if isinstance(c, dict):
            cond = c.get("condition") or {}
            gte = int(cond["gte"]) if "gte" in cond else int(cond["gt"]) + 1 if "gt" in cond else 1
            return {"type": c.get("type", ""), "group_by": list(c.get("group-by") or []), "timespan": str(c.get("timespan", "")),
                    "gte": gte, "field": cond.get("field", "")}
    return None


def _minutes(ts: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd])", ts.strip())
    if not m:
        raise ValueError(f"unsupported timespan {ts!r}")
    n, unit = int(m.group(1)), m.group(2)
    return max(1, {"s": n // 60, "m": n, "h": n * 60, "d": n * 1440}[unit])


def threshold_query(target: str, base_query: str, corr: dict, mapped: dict[str, str]) -> tuple[str, str]:
    """(query, note) adding the threshold to a converted base query. `mapped`: Sigma field -> target field.

    Raises ValueError when the language cannot express it, so the caller can say so instead of guessing."""
    group = [HOST_COLUMN.get(target, g) if g in _HOST_FIELDS else mapped.get(g, "") for g in corr["group_by"]]
    if any(not g or g.startswith("UNSUPPORTED") for g in group):
        raise ValueError(f"no {target} field for group-by {corr['group_by']}")
    value = mapped.get(corr["field"], "") if corr["type"] == "value_count" else ""
    if corr["type"] == "value_count" and (not value or value.startswith("UNSUPPORTED")):
        raise ValueError(f"no {target} field for distinct-count field {corr['field']!r}")
    if corr["type"] not in ("event_count", "value_count"):
        raise ValueError(f"correlation type {corr['type']!r} is not a threshold")
    n, ts = corr["gte"], corr["timespan"]
    note = (f"Threshold added by ti2dac (deterministic template, not AI): "
            f"{'distinct ' + corr['field'] + ' values' if value else 'events'} >= {n} within {ts}"
            + (f" per {', '.join(corr['group_by'])}" if group else ""))

    if target in KQL_TARGETS:
        t = _TIME_COLUMN.get(target, "TimeGenerated")
        agg = f"DistinctCount = dcount({value})" if value else "EventCount = count()"
        by = ", ".join([*group, f"bin({t}, {ts})"])
        q = (f"{base_query}\n| summarize {agg}, FirstSeen = min({t}), LastSeen = max({t}) by {by}\n"
             f"| where {'DistinctCount' if value else 'EventCount'} >= {n}")
        return q, note + ". Fixed time bins, not a sliding window: run every half-window to avoid missing bursts."
    if target == "crowdstrike_cql":
        fn = f"count(field={value}, distinct=true, as=Matches)" if value else "count(as=Matches)"
        fields = f", field=[{', '.join(group)}]" if group else ""
        return f"{base_query}\n| bucket(span={ts}{fields}, function={fn})\n| test(Matches >= {n})", note
    if target == "qradar_aql":
        m = re.fullmatch(r"(?is)\s*SELECT\s+.+?\s+FROM\s+events\s+WHERE\s+(.+)", base_query)
        if not m:
            raise ValueError("unexpected QRadar query shape")
        cols = ", ".join(group)
        agg = f"UNIQUECOUNT({value}) AS matches" if value else "COUNT(*) AS matches"
        q = (f"SELECT {cols + ', ' if cols else ''}{agg} FROM events WHERE {m.group(1).strip()}"
             f"{' GROUP BY ' + cols if cols else ''} HAVING matches >= {n} LAST {_minutes(ts)} MINUTES")
        return q, note + ". Runs over the last window only: schedule it at that interval."
    if target == "elastic_eql":
        if value:
            raise ValueError("EQL has no distinct-count threshold; use the ES|QL query")
        if n > 100:
            raise ValueError("EQL sequences allow at most 100 runs; use the ES|QL query")
        by = f" by {', '.join(group)}" if group else ""
        return f"sequence{by} with maxspan={ts}\n  [{base_query}] with runs={n}", note
    if target in _THRESHOLD_SETTINGS:
        settings = (f"group by {', '.join(group) or '(none)'}, "
                    + (f"cardinality of {value} >= {n}" if value else f"count >= {n}") + f", window {ts}")
        return base_query, (f"This query matches single events; the threshold is NOT in it. Use it in "
                            f"{_THRESHOLD_SETTINGS[target]} with: {settings}.")
    raise ValueError(f"no deterministic threshold template for {target}")
