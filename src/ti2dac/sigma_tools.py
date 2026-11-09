"""Sigma rendering, validation (sigma check equivalent), conversion and field mapping."""
from __future__ import annotations

import re
import sys
import threading
import uuid
import warnings
from datetime import date

import pyparsing
import yaml
from sigma import conditions as _sigma_conditions
from sigma.types import SigmaType

from . import correlate
from .models import FieldMapping, QueryResult, SigmaDraft
from .targets import TARGETS, make_backend, plugins

# Sigma conditions are parsed with pyparsing; without its packrat cache every field probe re-parses the
# condition grammar from scratch (about 8x slower per rule). The cache is global and not thread-safe, and
# rules are generated in parallel, so condition parsing is serialized (it is CPU-bound under the GIL anyway).
pyparsing.ParserElement.enable_packrat()
_PARSE_LOCK = threading.RLock()


def _serialized(parse):
    def locked(self, *a, **kw):
        with _PARSE_LOCK:
            return parse(self, *a, **kw)
    return locked


_sigma_conditions.SigmaCondition.parse = _serialized(_sigma_conditions.SigmaCondition.parse)

if sys.version_info >= (3, 14):
    def _to_plain_python_314(self):
        return self.__getattribute__(next(iter(self.__class__.__annotations__)))

    SigmaType.to_plain = _to_plain_python_314

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


_INLINE_FLAGS = re.compile(r"\(\?([ims]+)\)")


def hoist_regex_flags(detection: dict) -> dict:
    """`Field|re: '(?i)x'` -> `Field|re|i: 'x'`. Sigma states regex flags as modifiers; an inline group only
    works in some backends (Lucene/Elastic regexes have none, and our Wazuh XML checks put it mid-pattern).
    Only hoisted when every value of the field carries the same leading flags."""
    def fix(m: dict) -> dict:
        out = {}
        for key, val in m.items():
            mods = str(key).split("|")[1:]
            vals = val if isinstance(val, list) else [val]
            heads = {_INLINE_FLAGS.match(v).group(0) if isinstance(v, str) and _INLINE_FLAGS.match(v) else None
                     for v in vals}
            if "re" not in mods or len(heads) != 1 or None in heads:
                out[key] = val
                continue
            head = heads.pop()
            flags = [f for f in "ims" if f in head and f not in mods]
            rest = [v[len(head):] for v in vals]
            out["|".join([str(key).split("|")[0], *sorted(set(mods) | set(flags), key=_MOD_ORDER.index)])] = \
                rest if isinstance(val, list) else rest[0]
        return out

    return {name: (sel if name == "condition" else fix(sel) if isinstance(sel, dict)
                   else [fix(x) if isinstance(x, dict) else x for x in sel] if isinstance(sel, list) else sel)
            for name, sel in detection.items()}


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
    splits: dict[str, str] = {}   # selection -> expression over the selections it was split into
    taken = {re.sub(r"[^A-Za-z0-9_]", "_", sel.name) or "selection" for sel in draft.selections}

    def fresh(base: str) -> str:
        n, out = 2, base
        while out in taken:
            out, n = f"{base}_{n}", n + 1
        taken.add(out)
        return out

    for sel in draft.selections:
        name = re.sub(r"[^A-Za-z0-9_]", "_", sel.name) or "selection"
        if all(not c.field for cl in sel.clauses for c in cl.conditions):
            detection[name] = [v for cl in sel.clauses for c in cl.conditions for v in c.values]
            continue
        rendered: list[tuple[dict, list[dict]]] = []
        for cl in sel.clauses:
            m: dict = {}
            extra: list[dict] = []
            for c in cl.conditions:
                mods = sorted(set(c.modifiers), key=_MOD_ORDER.index)
                key = "|".join([c.field, *mods]) if c.field else "|".join(mods)
                vals = [_value(v, mods) for v in c.values] or [""]
                val = vals[0] if len(vals) == 1 else vals
                if key in m:   # same field twice in one AND-clause -> separate AND-ed selection
                    extra.append({key: val})
                else:
                    m[key] = val
            rendered.append((m, extra))
        plain = [m for m, extra in rendered if not extra]
        if len(plain) == len(rendered):
            detection[name] = plain[0] if len(plain) == 1 else plain
            continue
        # Same field twice in one AND-clause cannot live in one YAML map: move the extra conditions to sibling
        # selections AND-ed with that clause only (not with the selection's other OR-ed clauses).
        parts = []
        if plain:
            detection[name] = plain[0] if len(plain) == 1 else plain
            parts.append(name)
        for m, extra in (r for r in rendered if r[1]):
            base = name if not parts and len(rendered) == 1 else fresh(f"{name}_or")
            detection[base] = m
            sibs = [fresh(f"{base}_and{i}") for i in range(2, len(extra) + 2)]
            detection.update(zip(sibs, extra))
            parts.append("(" + " and ".join([base, *sibs]) + ")")
        splits[name] = parts[0] if len(parts) == 1 else "(" + " or ".join(parts) + ")"
    if splits:
        # Expand wildcards first so the new siblings cannot be picked up by '1 of x*' (OR) patterns.
        names = list(dict.fromkeys(re.sub(r"[^A-Za-z0-9_]", "_", x.name) or "selection" for x in draft.selections))
        condition = _expand_wildcards(condition, names)
        condition = re.sub(r"\b(" + "|".join(map(re.escape, splits)) + r")\b", lambda m: splits[m[1]], condition)
    detection["condition"] = condition
    return hoist_regex_flags(detection), condition


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
    issues += _revoked_attack_tags(col)
    return True, issues


def _revoked_attack_tags(col) -> list[str]:
    """pySigma's bundled ATT&CK data predates v20, so it accepts ids that the local index knows are revoked (an
    analyst-edited rule tagged attack.t1562.001)."""
    from . import attack

    out = []
    for r in col.rules:
        for tag in getattr(r, "tags", None) or []:
            if str(tag.namespace) != "attack" or not re.fullmatch(r"t\d{4}(\.\d{3})?", str(tag.name), re.I):
                continue
            tid = str(tag.name).upper()
            new, _ = attack.resolve_revoked(tid)
            t = attack.lookup(tid)
            if t and t.get("revoked"):
                out.append(f"warning: RevokedATTACKTag: attack.{tag.name} is revoked in ATT&CK"
                           + (f"; use attack.{new.lower()}" if new != tid else ""))
    return out


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


def convert(rule_yaml: str, target_ids: list[str], index_overrides: dict[str, str] | None = None,
            client=None) -> list[QueryResult]:
    """Deterministic queries. A correlation the backend cannot convert gets ti2dac's threshold template
    (correlate.py) around the converted base rule; correlation logic is never left to the AI."""
    from sigma.collection import SigmaCollection

    product = _product(rule_yaml)
    docs = load_docs(rule_yaml)
    corr = correlate.parse(docs)
    results = []
    for tid in target_ids:
        t = TARGETS.get(tid)
        if t is None:
            continue
        res = QueryResult(target=tid, label=t.label, language=t.language, notes=t.notes,
                          method="template" if t.backend.startswith("ti2dac_") else "pysigma",
                          client=client.name if client is not None else "")
        try:
            backend = make_backend(t, product, client)
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
            _regex_notes(res, rule_yaml)
        except Exception as e:
            res.error = _short_error(e)
            if isinstance(e, AttributeError) and "'NoneType' object has no attribute 'format'" in str(e):
                # e.g. ES|QL has no template for keyword (field-less) values and crashes instead of saying so
                res.error = f"SigmaFeatureNotSupportedByBackendError: {t.label} has no form for this rule's " \
                            "keyword (field-less) or other value type: not supported"
            # A field this SIEM's data lacks is a coverage gap, not a broken query
            res.validation = "failed" if conversion_problem(res.error) == "failed" else "not-tested"
            narrowed = _without_unavailable(docs, res.error) if res.validation == "not-tested" else None
            if narrowed is not None:
                (alt,) = convert(narrowed[0], [tid], index_overrides, client)   # recurses once per missing field
                if alt.query:
                    alt.notes = f"{alt.notes} {narrowed[1]}".strip()
                    res = alt
            if res.error and corr is not None:
                _threshold_fallback(res, docs, corr, client, (index_overrides or {}).get(tid, ""))
        results.append(res)
    return results


_MISSING_FIELD = re.compile(r"field name encountered: (\w+(?:\.\w+)*)|field '([\w.]+)' is not supported"
                            r"|does not support the (\w+) field", re.I)


def _without_unavailable(docs: list[dict], error: str) -> tuple[str, str] | None:
    """The rule without the OR alternatives that use fields this SIEM does not have, e.g. `Image|endswith` OR
    `OriginalFileName` on SecurityEvent (4688 has no OriginalFileName). None when such a field is required
    (AND-ed) somewhere, since dropping it would change what the rule means."""
    import copy

    missing = {next(x for x in groups if x) for groups in _MISSING_FIELD.findall(error)}
    if not missing or not docs or not isinstance(docs[0].get("detection"), dict):
        return None
    doc = copy.deepcopy(docs[0])
    det = doc["detection"]

    def uses(m) -> bool:
        return isinstance(m, dict) and any(str(k).split("|")[0] in missing for k in m)

    dropped = []
    for name, sel in det.items():
        if name == "condition":
            continue
        if isinstance(sel, list) and any(uses(m) for m in sel):
            keep = [m for m in sel if not uses(m)]
            if not keep:
                return None
            det[name] = keep[0] if len(keep) == 1 else keep
            dropped.append(name)
        elif uses(sel):
            return None
    if not dropped:
        return None
    filters = [n for n in dropped if str(n).startswith("filter")]
    note = (f"Converted without the {', '.join(sorted(missing))} alternative in {', '.join(dropped)}: this SIEM's "
            "data does not record that field, so only the other alternatives can match.")
    if filters:
        note += f" The exclusion {', '.join(filters)} is narrower here, so expect more false positives."
    return dump_docs([doc, *docs[1:]]), note


def rule_regexes(rule_yaml: str) -> list[str]:
    """Every `|re` value in the rule's detection."""
    out: list[str] = []

    def visit(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if "re" in str(k).split("|")[1:]:
                    out.extend(str(x) for x in (v if isinstance(v, list) else [v]))
        elif isinstance(node, list):
            for n in node:
                visit(n)

    try:
        for doc in load_docs(rule_yaml):
            for k, v in (doc.get("detection") or {}).items():
                if k != "condition":
                    visit(v)
    except Exception:
        pass
    return out


def _regex_notes(res: QueryResult, rule_yaml: str) -> None:
    """Whole-value regex engines get a rewritten pattern (targets.REGEX_FLAVOR); say what Lucene cannot express."""
    from . import regexes
    from .targets import REGEX_FLAVOR

    flavor = REGEX_FLAVOR.get(res.target)
    if not flavor:
        return
    if flavor in ("lucene", "eql"):
        problems = sorted({p for r in rule_regexes(rule_yaml) for p in regexes.lucene_problems(r)})
        if problems:
            res.notes = (f"{res.notes} The rule's regex uses {', '.join(problems)}, which Lucene regular expressions "
                         "do not support: the query will not parse or match as intended; rewrite it for this "
                         "target.").strip()


def _threshold_fallback(res: QueryResult, docs: list[dict], corr: dict, client, index_override: str) -> None:
    base_doc = {k: v for k, v in docs[0].items() if k != "name"}
    (base,) = convert(dump_docs([base_doc]), [res.target], None, client)
    if not base.query:
        res.error = f"correlation: the base rule does not convert ({base.error})"
        return
    mapped = {f: map_field(base_doc, f, res.target, client) for f in [*corr["group_by"], corr["field"]] if f}
    try:
        query, note = correlate.threshold_query(res.target, base.query, corr, mapped)
    except ValueError as e:
        res.error = f"correlation not expressible for {res.target}: {e}. Not sent to the AI: thresholds are only " \
                    "built by code"
        return
    res.query, res.error, res.validation, res.method = apply_index_override(res.target, query, index_override), None, \
        "not-tested", "template"
    res.notes = f"{res.notes} {note}".strip()


def _short_error(e: Exception) -> str:
    msg = str(e).split("\n")[0]
    sentences = [x.strip() for x in re.split(r"(?<=\.)\s+", msg)]   # some backends repeat the sentence
    msg = " ".join(x for i, x in enumerate(sentences) if x.rstrip(".") not in (y.rstrip(".") for y in sentences[:i]))
    msg = re.sub(r"(?<=\.)\s[^.]*:$", "", msg)                      # drop a dangling "... in this order:" lead-in
    msg = re.sub(r"\s*\(while (converting|applying)[^)]*\)", "", msg)
    return f"{type(e).__name__}: {msg}"[:300]


_UNAVAILABLE = ("does not support logsource", "invalid sigmadetectionitem field name", "is not supported",
                "not supported", "has no field mapping", "not yet supported", "does not support the",
                "unable to determine table name",      # Kusto: no Sentinel/Defender table for this log source
                "only file name of",                   # CrowdStrike: no full image path in its events
                "have no wazuh rule equivalent", "expands to more than",
                "no valid hash algo")                  # Defender: Hashes with only IMPHASH etc.


def conversion_problem(error: str) -> str:
    """'not-available': the SIEM's data or backend has no equivalent (expected for some log sources);
    'failed': ti2dac or the backend broke on a rule it should convert."""
    e = (error or "").lower()
    return "not-available" if any(x in e for x in _UNAVAILABLE) else "failed"


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


def map_field(base_doc: dict, field: str, tid: str, client=None) -> str:
    """The name `field` gets in target `tid` (through the client's mapping, if any), or 'UNSUPPORTED: reason'.

    The field is probed inside a copy of the rule: some backends pick the table from the rule's other
    conditions (e.g. Kusto from the EventID), so a field probed alone would look unsupported."""
    from sigma.collection import SigmaCollection

    t = TARGETS.get(tid)
    if t is None:
        return "UNSUPPORTED: unknown target"
    logsource = base_doc.get("logsource") or {}
    det = dict(base_doc.get("detection") or {})
    cond = det.pop("condition", "")
    det["ti2dac_probe"] = {field: "ZZPROBEZZ"}
    probe = yaml.safe_dump({"title": "probe", "logsource": logsource,
                            "detection": {**det, "condition": f"({cond}) and ti2dac_probe" if cond else "ti2dac_probe"}})
    try:
        col = SigmaCollection.from_yaml(probe)
        make_backend(t, logsource.get("product", ""), client).convert(col)
        names = [it.field for d in col.rules[0].detection.detections.values() for it in _walk(d)
                 if any("ZZPROBEZZ" in str(v) for v in it.value)]
        return ", ".join(dict.fromkeys(n for n in names if n)) or field
    except Exception as e:
        reason = _short_error(e).split(": ", 1)[-1]
        if det != {"ti2dac_probe": {field: "ZZPROBEZZ"}} and field.split("|")[0].lower() not in reason.lower():
            # Another field of the rule broke the probe; this one alone may map fine.
            return map_field({"logsource": logsource, "detection": {}}, field, tid, client)
        return "UNSUPPORTED: " + reason[:140]


def field_mappings(rule_yaml: str, target_ids: list[str], client=None) -> list[FieldMapping]:
    """Probe each field through each target's pipeline to show the real mapped field name."""
    doc = first_doc(rule_yaml)
    return [FieldMapping(sigma_field=f, client=client.name if client is not None else "",
                         targets={tid: map_field(doc, f, tid, client) for tid in target_ids if tid in TARGETS})
            for f in rule_fields(rule_yaml)]
