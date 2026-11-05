"""Evaluate a Sigma rule locally against events (no SIEM needed).

Used two ways:
  * self-test during generation: the rule must match the events its simulation produces and
    must not match the benign look-alikes (both supplied by the model with the rule);
  * `ti2dac replay`: run the rule over real lab telemetry exported as JSON/JSONL/EVTX, which is
    the same idea as Zircolite/Chainsaw and gives a fired/not-fired result before SIEM onboarding.

The rule is converted with pySigma's SQLite backend (adjusted below for Sigma semantics) and
executed over an in-memory table built from the events.
"""
from __future__ import annotations

import json
import re
import sqlite3
from functools import lru_cache
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
    try:
        if text.startswith("["):
            data = json.loads(text)
        else:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        return [normalize_event(e) for e in data if isinstance(e, dict)]
    except RecursionError as e:
        raise ReplayError(f"{p.name}: JSON nested too deeply to be a log event export") from e


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


@lru_cache(maxsize=1024)
def _like_re(pattern: str, esc: str | None) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if esc and c == esc and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1].casefold()))
            i += 2
            continue
        out.append(".*" if c == "%" else "." if c == "_" else re.escape(c.casefold()))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def _like(pattern, value, esc=None):
    # Replaces SQLite's LIKE, whose case folding is ASCII-only ('ÄÖ' vs 'äö')
    if pattern is None or value is None:
        return None
    return _like_re(pattern, esc).fullmatch(str(value).casefold()) is not None


def _casefold_cmp(a: str, b: str) -> int:
    a, b = a.casefold(), b.casefold()
    return (a > b) - (a < b)


def _num(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _glob_literal(text: str) -> str:
    return "".join(f"[{c}]" if c in "*?[" else c for c in text)


@lru_cache(maxsize=1)
def _backend_cls():
    from sigma.types import SpecialChars

    class ReplayBackend(plugins().backends["sqlite"]):
        """Missing fields are NULL; NULL counts as "no match" everywhere, including under NOT."""
        field_null_expression = "({field} IS NULL OR {field} = '')"
        # Values are stored as TEXT: compare numerically only where the rule asks for it
        compare_op_expression = "sigma_num({field}) {operator} {value}"

        def convert_condition_not(self, cond, state):
            expr = super().convert_condition_not(cond, state)
            if isinstance(expr, str) and expr.startswith("NOT "):
                return f"NOT coalesce({expr[4:]}, 0)"
            return expr

        def convert_value_re(self, r, state):
            return super().convert_value_re(r, state).replace("'", "''")

        def convert_condition_field_eq_val_str_case_sensitive(self, cond, state):
            # The stock rendering uses `GLOB ... ESCAPE`, which SQLite rejects; GLOB escapes via [x]
            parts = []
            for p in cond.value.s:
                if isinstance(p, str):
                    parts.append(_glob_literal(p))
                elif p == SpecialChars.WILDCARD_MULTI:
                    parts.append("*")
                elif p == SpecialChars.WILDCARD_SINGLE:
                    parts.append("?")
                else:
                    raise NotImplementedError(f"unsupported value part in cased match: {p!r}")
            pattern = "".join(parts).replace("'", "''")
            return f"{self.escape_and_quote_field(cond.field)} GLOB '{pattern}'"

    return ReplayBackend


def evaluate(rule_yaml: str, events: list[dict]) -> list[int]:
    """Indices of `events` matched by the rule's detection (correlation thresholds are not applied)."""
    from sigma.collection import SigmaCollection

    base = _first_doc(rule_yaml)
    base_only = yaml.safe_dump(base, sort_keys=False)
    try:
        sql = _backend_cls()().convert(SigmaCollection.from_yaml(base_only))[0]
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
        # Missing fields stay NULL (`field: null`, `|exists`); the backend wraps NOT in coalesce() so
        # `not filter` on an absent field still keeps the event.
        row: dict = {c: None for c in cols}
        for k, v in events[i].items():
            if k and v is not None and row[canon[k.lower()]] in (None, ""):
                row[canon[k.lower()]] = str(v)
        row["__idx"] = i
        rows.append([row[c] for c in cols])
    query = sql.replace("<TABLE_NAME>", "logs")
    query = re.sub(r"^SELECT \*", 'SELECT "__idx"', query)
    conn = sqlite3.connect(":memory:")
    try:
        conn.create_function("REGEXP", 2, lambda p, v: _regexp(p, v))
        conn.create_function("like", 2, _like)
        conn.create_function("like", 3, _like)
        conn.create_function("sigma_num", 1, _num)
        conn.create_collation("SIGMA", _casefold_cmp)
        # TEXT keeps '0012'/'1e5' verbatim; numeric literals in `EventID=4698` take TEXT affinity too.
        # SIGMA collation: Unicode-aware case-insensitive '=' (Sigma's default).
        conn.execute("CREATE TABLE logs (" + ", ".join(f'"{c}" TEXT COLLATE SIGMA' for c in cols) + ")")
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
