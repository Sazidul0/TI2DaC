"""Evaluate a Sigma rule locally against events (no SIEM needed).

Used two ways:
  * self-test during generation: the rule must match the events its simulation produces and
    must not match the benign look-alikes (both supplied by the model with the rule);
  * `ti2dac replay`: run the rule over real lab telemetry exported as JSON/JSONL/EVTX, which is
    the same idea as Zircolite/Chainsaw and gives a fired/not-fired result before SIEM onboarding.

The rule is converted with pySigma's SQLite backend (Sigma semantics, case-insensitive LIKE) and
executed over an in-memory table built from the events.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import yaml

from .targets import plugins

# Event IDs per Sigma category (Sysmon + Windows equivalents), used to scope replayed events
# that carry an EventID; events without one are not filtered.
CATEGORY_EVENT_IDS = {
    "process_creation": {1, 4688}, "network_connection": {3, 5156}, "image_load": {7},
    "create_remote_thread": {8}, "raw_access_thread": {9}, "process_access": {10}, "file_event": {11},
    "registry_add": {12}, "registry_delete": {12}, "registry_set": {13}, "registry_rename": {14},
    "registry_event": {12, 13, 14}, "create_stream_hash": {15}, "pipe_created": {17, 18},
    "wmi_event": {19, 20, 21}, "dns_query": {22}, "file_delete": {23, 26}, "ps_script": {4104},
    "ps_module": {4103}, "process_termination": {5},
}


class ReplayError(Exception):
    pass


def _flatten(obj, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        else:
            out[key] = v
            leaf = str(k)
            if prefix and leaf not in out:      # winlog.event_data.Image -> also Image
                out[leaf] = v
    return out


def normalize_event(e: dict) -> dict:
    flat = _flatten(e)
    # Common SIEM export spellings of the Windows event id
    for k in ("event.code", "EventCode", "winlog.event_id", "System.EventID", "EventID"):
        if k in flat and "EventID" not in flat:
            flat["EventID"] = flat[k]
    return {k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in flat.items()}


def load_events(path: str | Path) -> list[dict]:
    p = Path(path)
    if p.suffix.lower() == ".evtx":
        return _load_evtx(p)
    text = p.read_text(errors="replace").strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
    else:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [normalize_event(e) for e in data if isinstance(e, dict)]


def _load_evtx(p: Path) -> list[dict]:
    try:
        import Evtx.Evtx as evtx   # python-evtx (optional: pip install 'ti2dac[evtx]')
        from defusedxml import ElementTree as ET   # log content is untrusted: no XXE / entity expansion
    except ImportError as e:
        raise ReplayError("EVTX replay needs python-evtx and defusedxml: pip install 'ti2dac[evtx]' "
                          "(or export the events to JSON)") from e

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    with evtx.Evtx(str(p)) as log:
        for rec in log.records():
            root = ET.fromstring(rec.xml())
            ev: dict = {}
            sysn = root.find("e:System", ns)
            if sysn is not None:
                eid = sysn.find("e:EventID", ns)
                ch = sysn.find("e:Channel", ns)
                comp = sysn.find("e:Computer", ns)
                ev["EventID"] = int(eid.text) if eid is not None and eid.text else None
                ev["Channel"] = ch.text if ch is not None else None
                ev["Computer"] = comp.text if comp is not None else None
            for d in root.iterfind(".//e:EventData/e:Data", ns):
                if d.get("Name"):
                    ev[d.get("Name")] = d.text
            events.append(ev)
    return events


def _first_doc(rule_yaml: str) -> dict:
    return next(iter(yaml.safe_load_all(rule_yaml)), {}) or {}


def _scoped(events: list[dict], rule: dict) -> list[int]:
    ls = rule.get("logsource") or {}
    ids = CATEGORY_EVENT_IDS.get(ls.get("category", ""))
    keep = []
    for i, e in enumerate(events):
        eid = e.get("EventID")
        if ids and eid not in (None, "") and str(eid).isdigit() and int(eid) not in ids:
            continue
        keep.append(i)
    return keep


def _regexp(pattern, value) -> bool:
    if value is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


def evaluate(rule_yaml: str, events: list[dict]) -> list[int]:
    """Indices of `events` matched by the rule's detection (correlation thresholds are not applied)."""
    from sigma.collection import SigmaCollection

    base = _first_doc(rule_yaml)
    base_only = yaml.safe_dump(base, sort_keys=False)
    try:
        sql = plugins().backends["sqlite"]().convert(SigmaCollection.from_yaml(base_only))[0]
    except KeyError as e:
        raise ReplayError("pySigma SQLite backend not installed (pip install 'pySigma-backend-sqlite==0.2.0')") from e
    except Exception as e:
        raise ReplayError(f"rule cannot be evaluated locally: {type(e).__name__}: {e}") from e
    from .sigma_tools import rule_fields

    idx = _scoped(events, base)
    # SQLite column names are case-insensitive: unify field spellings (rule spelling wins), so an event key
    # `commandline` lands in the rule's `CommandLine` column instead of crashing CREATE TABLE.
    canon: dict[str, str] = {}
    for f in rule_fields(base_only):
        canon.setdefault(f.lower(), f)
    for i in idx:
        for k in events[i]:
            if k:
                canon.setdefault(k.lower(), k)
    cols = sorted(set(canon.values())) + ["__idx"]
    rows = []
    for i in idx:
        # Missing fields are '' rather than NULL: with NULL, SQL three-valued logic turns
        # `NOT ParentImage LIKE ...` into NULL and silently drops events that lack the field,
        # whereas in Sigma a filter on an absent field simply does not match. (Trade-off: `field: null`
        # checks are not supported by local replay.)
        row = {c: "" for c in cols}
        for k, v in events[i].items():
            if k and v not in (None, "") and row[canon[k.lower()]] == "":
                row[canon[k.lower()]] = str(v)
        row["__idx"] = i
        rows.append([row[c] for c in cols])
    query = sql.replace("<TABLE_NAME>", "logs")
    query = re.sub(r"^SELECT \*", 'SELECT "__idx"', query)
    conn = sqlite3.connect(":memory:")
    try:
        conn.create_function("REGEXP", 2, lambda p, v: _regexp(p, v))
        # NUMERIC affinity: '4698' is stored as 4698, so `EventID = 4698` and `>`/`<` compare as numbers;
        # NOCASE: Sigma string comparison is case-insensitive (LIKE already is; '=' needs the collation).
        conn.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" NUMERIC COLLATE NOCASE' for c in cols) + ")")
        conn.executemany("INSERT INTO logs VALUES (" + ",".join("?" * len(cols)) + ")", rows)
        return sorted(int(r[0]) for r in conn.execute(query))
    except sqlite3.Error as e:
        raise ReplayError(f"local evaluation failed: {e} -- query: {query[:300]}") from e
    finally:
        conn.close()


def selftest(rule_yaml: str, test_events) -> tuple[str, list[str]]:
    """Run the model-supplied test events through the rule. Returns (status, problems)."""
    if not test_events:
        return "n/a", ["no test events supplied"]
    events = [{f.name: f.value for f in t.fields} for t in test_events]
    try:
        matched = set(evaluate(rule_yaml, events))
    except ReplayError as e:
        return "n/a", [str(e)]
    problems = []
    for i, t in enumerate(test_events):
        if t.should_match and i not in matched:
            problems.append(f"rule does NOT match the simulation's expected event '{t.description}': {events[i]}")
        if not t.should_match and i in matched:
            problems.append(f"rule matches benign look-alike '{t.description}' (false positive): {events[i]}")
    if not any(t.should_match for t in test_events):
        problems.append("no positive test event supplied")
    return ("fail" if problems else "pass"), problems
