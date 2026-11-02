"""Sigma rendering, validation (sigma check equivalent), conversion and field mapping."""
from __future__ import annotations

import re
import uuid
import warnings
from datetime import date

import yaml

from .models import FieldMapping, QueryResult, SigmaDraft
from .targets import TARGETS, make_backend, plugins

RULE_NAMESPACE = uuid.UUID("5b1f3c2e-8a0d-4f6e-9c3a-7d2b1e0f4a91")

_MOD_ORDER = ["wide", "utf16le", "utf16be", "utf16", "base64", "base64offset", "windash",
              "contains", "startswith", "endswith", "re", "i", "m", "s", "cidr", "exists",
              "gt", "gte", "lt", "lte", "cased", "all"]
# Validators that only make sense for a rule repository on disk.
_SKIP_VALIDATORS = {"duplicate_filename", "filename_length", "custom_attributes", "identifier_uniqueness",
                    "duplicate_title", "duplicate_references"}


class _Dumper(yaml.SafeDumper):
    pass


def _str_repr(dumper, data: str):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str_repr)


def stable_rule_id(report_sha256: str, key: str) -> str:
    return str(uuid.uuid5(RULE_NAMESPACE, f"{report_sha256}:{key}"))


# A rule file holds one base rule, optionally followed by a Sigma correlation rule (multi-document).
def load_docs(rule_yaml: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(rule_yaml) if isinstance(d, dict)]


def first_doc(rule_yaml: str) -> dict:
    try:
        docs = load_docs(rule_yaml)
    except yaml.YAMLError:
        return {}
    return docs[0] if docs else {}


def dump_docs(docs: list[dict]) -> str:
    return "---\n".join(yaml.dump(d, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=200) for d in docs)


def set_status(rule_yaml: str, status: str, modified: str | None = None) -> str:
    docs = load_docs(rule_yaml)
    for d in docs:
        d["status"] = status
        if modified:
            d["modified"] = modified
    return dump_docs(docs)


def _value(v: str, mods: list[str]):
    if "exists" in mods:
        return v.strip().lower() not in ("false", "0", "no")
    if not mods and re.fullmatch(r"-?\d{1,10}", v):
        return int(v)
    return v


def _expand_wildcards(condition: str, names: list[str]) -> str:
    """'1 of selection_*' / 'all of them' -> explicit boolean expressions over `names`."""
    from fnmatch import fnmatchcase

    def repl(m: re.Match) -> str:
        quant, pattern = m.group(1), m.group(2)
        hits = names if pattern == "them" else [n for n in names if fnmatchcase(n, pattern)]
        if not hits:
            return m.group(0)
        return "(" + f" {'and' if quant == 'all' else 'or'} ".join(hits) + ")"

    return re.sub(r"\b(1|all|any) of ([\w*]+)", repl, condition)


def build_detection(draft: SigmaDraft) -> tuple[dict, str]:
    """Structured selections -> Sigma detection mapping. Returns (detection, condition)."""
    detection: dict = {}
    condition = draft.condition.strip()
    splits: dict[str, list[str]] = {}
    for sel in draft.selections:
        name = re.sub(r"[^A-Za-z0-9_]", "_", sel.name) or "selection"
        if all(not c.field for cl in sel.clauses for c in cl.conditions):
            detection[name] = [v for cl in sel.clauses for c in cl.conditions for v in c.values]
            continue
        rendered, extra = [], []
        for cl in sel.clauses:
            m: dict = {}
            for c in cl.conditions:
                mods = sorted(set(c.modifiers), key=_MOD_ORDER.index)
                key = "|".join([c.field, *mods]) if c.field else "|".join(mods)
                vals = [_value(v, mods) for v in c.values] or [""]
                val = vals[0] if len(vals) == 1 else vals
                if key in m:   # same field twice in one AND-clause -> separate AND-ed selection
                    extra.append({key: val})
                else:
                    m[key] = val
            rendered.append(m)
        detection[name] = rendered[0] if len(rendered) == 1 else rendered
        if extra:
            # Same field twice in one AND-clause cannot live in one YAML map: move the extra
            # conditions to sibling selections that are AND-ed wherever the original is used.
            splits[name] = []
            for i, e in enumerate(extra, 2):
                detection[f"{name}_and{i}"] = e
                splits[name].append(f"{name}_and{i}")
    if splits:
        # Expand wildcards first so the new siblings cannot be picked up by '1 of x*' (OR) patterns.
        condition = _expand_wildcards(condition, [n for n in detection if not any(n in v for v in splits.values())])
        for name, siblings in splits.items():
            condition = re.sub(rf"\b{re.escape(name)}\b", "(" + " and ".join([name, *siblings]) + ")", condition)
    detection["condition"] = condition
    return detection, condition


def render_rule(draft: SigmaDraft, *, rule_id: str, author: str, references: list[str], tags: list[str],
                status: str = "experimental", rule_date: str | None = None, modified: str | None = None) -> str:
    detection, _ = build_detection(draft)
    logsource = {k: v for k, v in draft.logsource.model_dump().items() if v}
    rule: dict = {
        "title": draft.title.strip(),
        "id": rule_id,
        "status": status,
        "description": draft.description.strip(),
        "references": references,
        "author": author,
        "date": rule_date or date.today().isoformat(),
    }
    if modified:
        rule["modified"] = modified
    rule.update({
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": draft.falsepositives or ["Unknown"],
        "level": draft.level,
    })
    if not draft.correlation:
        return dump_docs([rule])
    # Threshold behaviour: the base rule describes one event; a Sigma correlation rule counts them.
    c = draft.correlation[0]
    base_name = "ti2dac_" + rule_id.replace("-", "")[:12]
    rule = {"title": rule["title"], "id": rule_id, "name": base_name,
            **{k: v for k, v in rule.items() if k not in ("title", "id")}}
    rule["level"] = "informational"   # the single event alone is not the alert
    condition: dict = {"gte": max(1, c.gte)}
    if c.type == "value_count":
        condition["field"] = c.value_field or (c.group_by[0] if c.group_by else "")
    corr = {
        "title": f"{draft.title.strip()} (threshold)",
        "id": str(uuid.uuid5(RULE_NAMESPACE, rule_id + ":correlation")),
        "status": status,
        "description": draft.description.strip(),
        "author": author,
        "date": rule["date"],
        "references": references,
        "tags": tags,
        "correlation": {"type": c.type, "rules": [base_name], "group-by": c.group_by,
                        "timespan": c.timespan, "condition": condition},
        "falsepositives": draft.falsepositives or ["Unknown"],
        "level": draft.level,
    }
    return dump_docs([rule, corr])


def attack_tags(tactic: str, technique_id: str) -> list[str]:
    return [f"attack.{tactic}", f"attack.{technique_id.lower()}"]


# --------------------------------------------------------------------------- validation
def validate_rule(rule_yaml: str) -> tuple[bool, list[str]]:
    """Parse + run pySigma validators (what `sigma check` does). Returns (parses_ok, issues)."""
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator

    try:
        col = SigmaCollection.from_yaml(rule_yaml, collect_errors=True)
    except Exception as e:   # YAML-level errors
        return False, [f"error: {e}"]
    errors = [f"error: {err}" for r in col.rules for err in r.errors]
    if errors or not col.rules:
        return False, errors or ["error: no rule parsed"]
    # Force condition parsing: unknown selection names surface here.
    try:
        for r in col.rules:
            if not hasattr(r, "detection"):   # correlation rules reference other rules instead
                continue
            for c in r.detection.parsed_condition:
                c.parse()
    except Exception as e:
        return False, [f"error: condition: {e}"]
    validators = [cls for name, cls in plugins().validators.items() if name not in _SKIP_VALIDATORS]
    issues = []
    for issue in SigmaValidator(validators).validate_rules(col.rules):
        if _known_new_attack_tag(issue):
            continue
        issues.append(f"{issue.severity.name.lower()}: {issue.__class__.__name__}: {issue.description}"
                      + (f" ({_issue_detail(issue)})" if _issue_detail(issue) else ""))
    return True, issues


def _known_new_attack_tag(issue) -> bool:
    """pySigma's bundled ATT&CK data can predate the local index (e.g. v18+ tactics 'stealth',
    'defense-impairment'); don't report tags the authoritative local index knows."""
    if issue.__class__.__name__ != "InvalidATTACKTagIssue":
        return False
    from . import attack

    name = str(getattr(getattr(issue, "tag", None), "name", "")).lower()
    techniques = attack.load_index()["techniques"]
    tactics = {t for v in techniques.values() for t in v["tactics"]}
    return name in tactics or name.upper() in techniques


def _issue_detail(issue) -> str:
    skip = {"rules", "description", "severity"}
    parts = [f"{k}={v}" for k, v in vars(issue).items() if k not in skip and v not in (None, "", [])]
    return ", ".join(parts)[:200]


# --------------------------------------------------------------------------- conversion
def _product(rule_yaml: str) -> str:
    try:
        return (first_doc(rule_yaml).get("logsource") or {}).get("product", "") or ""
    except Exception:
        return ""


def apply_index_override(target: str, query: str, value: str) -> str:
    """Scope a query to the environment's index/table (pySigma emits generic 'from *' / no index)."""
    if not value:
        return query
    if target == "elastic_esql":
        return re.sub(r"^from \*", f"from {value}", query)
    if target == "loki":
        return re.sub(r"^\{[^}]*\}", value, query)
    if target in ("splunk", "splunk_cim", "crowdstrike_cql", "elastic_lucene", "opensearch"):
        return f"{value} {query}" if target.startswith(("splunk", "crowdstrike")) else f"({value}) AND ({query})"
    return query


def convert(rule_yaml: str, target_ids: list[str], index_overrides: dict[str, str] | None = None) -> list[QueryResult]:
    from sigma.collection import SigmaCollection

    product = _product(rule_yaml)
    results = []
    for tid in target_ids:
        t = TARGETS.get(tid)
        if t is None:
            continue
        res = QueryResult(target=tid, label=t.label, language=t.language, method="pysigma", notes=t.notes)
        try:
            backend = make_backend(t, product)
            # Some backends only *warn* when they drop part of the rule (e.g. QRadar removes conditions it
            # cannot map), which silently broadens the query. Surface those warnings on the query.
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                out = backend.convert(SigmaCollection.from_yaml(rule_yaml))   # fresh parse: pipelines mutate rules
            q = out if isinstance(out, str) else "\n".join(str(x) for x in out)
            if not q.strip():
                raise ValueError("backend returned an empty query")
            res.query = apply_index_override(tid, q.strip(), (index_overrides or {}).get(tid, ""))
            res.validation = "not-tested"
            msgs = list(dict.fromkeys(str(w.message) for w in caught
                                      if issubclass(w.category, UserWarning) and "ZZPROBEZZ" not in str(w.message)))
            if msgs:
                res.notes = f"{res.notes} Backend warning (query may not match the rule exactly): {'; '.join(msgs)[:300]}".strip()
        except Exception as e:
            res.error = _short_error(e)
            res.validation = "failed"
        results.append(res)
    return results


def _short_error(e: Exception) -> str:
    msg = str(e).split("\n")[0]
    msg = re.sub(r"(\b[^.]{20,}\.)\s*\1", r"\1", msg)          # some backends repeat the sentence
    msg = re.sub(r"\s*\(while (converting|applying)[^)]*\)", "", msg)
    return f"{type(e).__name__}: {msg}"[:300]


def _walk(det):
    from sigma.rule import SigmaDetection

    for it in det.detection_items:
        if isinstance(it, SigmaDetection):
            yield from _walk(it)
        else:
            yield it


def rule_fields(rule_yaml: str) -> list[str]:
    try:
        det = first_doc(rule_yaml)["detection"]
    except Exception:
        return []
    out: dict[str, None] = {}

    def visit(node):
        if isinstance(node, dict):
            for k in node:
                f = str(k).split("|")[0]
                if f:
                    out.setdefault(f, None)
        elif isinstance(node, list):
            for n in node:
                visit(n)

    for k, v in det.items():
        if k != "condition":
            visit(v)
    return list(out)


def field_mappings(rule_yaml: str, target_ids: list[str]) -> list[FieldMapping]:
    """Probe each field through each target's pipeline to show the real mapped field name."""
    from sigma.collection import SigmaCollection

    data = first_doc(rule_yaml)
    logsource = data.get("logsource", {})
    product = logsource.get("product", "")
    rows = []
    for f in rule_fields(rule_yaml):
        probe = yaml.safe_dump({
            "title": "probe", "logsource": logsource,
            "detection": {"sel": {f: "ZZPROBEZZ"}, "condition": "sel"},
        })
        mapped: dict[str, str] = {}
        for tid in target_ids:
            t = TARGETS.get(tid)
            if t is None:
                continue
            try:
                col = SigmaCollection.from_yaml(probe)
                make_backend(t, product).convert(col)
                names = [it.field for d in col.rules[0].detection.detections.values() for it in _walk(d)
                         if any("ZZPROBEZZ" in str(v) for v in it.value)]
                mapped[tid] = ", ".join(dict.fromkeys(n for n in names if n)) or f
            except Exception as e:
                mapped[tid] = "UNSUPPORTED: " + _short_error(e).split(": ", 1)[-1][:140]
        rows.append(FieldMapping(sigma_field=f, targets=mapped))
    return rows
