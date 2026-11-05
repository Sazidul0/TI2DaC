"""Wazuh: Sigma -> Wazuh rule XML (deterministic) and the field mapping for Wazuh Indexer hunting queries.

Wazuh's eventchannel decoder exposes Windows events as win.system.* and win.eventdata.<field>, where the
EventData name has its first letter lower-cased (CommandLine -> win.eventdata.commandLine). In the indexer
(wazuh-alerts-* / wazuh-archives-*) the same fields sit under data.

A custom Wazuh rule only fires if it hangs off the most specific built-in rule that matches the event:
evaluation descends into the first matching child, so a rule attached higher up is never reached. The
parent table comes from the Wazuh default ruleset (data/wazuh_parents.json). Generated rules still need a
check with `wazuh-logtest` on the manager before deployment.
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

# Sigma windows `service` -> event channel
CHANNELS = {
    "security": "Security", "system": "System", "application": "Application",
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "powershell": "Microsoft-Windows-PowerShell/Operational", "powershell-classic": "Windows PowerShell",
    "windefend": "Microsoft-Windows-Windows Defender/Operational",
    "taskscheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "wmi": "Microsoft-Windows-WMI-Activity/Operational",
    "firewall-as": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "bits-client": "Microsoft-Windows-Bits-Client/Operational",
    "ntlm": "Microsoft-Windows-NTLM/Operational",
    "codeintegrity-operational": "Microsoft-Windows-CodeIntegrity/Operational",
    "dns-server": "DNS Server", "driver-framework": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
}
# Sigma categories the sysmon pipeline does not cover
_CATEGORY_EVENTS = {
    "ps_script": ("Microsoft-Windows-PowerShell/Operational", 4104),
    "ps_module": ("Microsoft-Windows-PowerShell/Operational", 4103),
    "ps_classic_start": ("Windows PowerShell", 400),
    "ps_classic_provider_start": ("Windows PowerShell", 600),
}
_SYSTEM_FIELDS = {"EventID": "eventID", "Channel": "channel", "Provider_Name": "providerName",
                  "Computer": "computer", "Level": "level", "Keywords": "keywords", "Task": "task"}
_LEVELS = {"informational": 3, "low": 5, "medium": 8, "high": 12, "critical": 14}
RULE_ID_BASE, RULE_ID_SLOTS, SLOT_SIZE = 100000, 1000, 20   # custom-rule range 100000-119999, 20 ids per Sigma rule


@lru_cache(maxsize=1)
def parents() -> dict:
    return json.loads((Path(__file__).parent / "data" / "wazuh_parents.json").read_text())


def field(name: str, prefix: str = "") -> str:
    """Sigma (Windows event) field -> Wazuh decoded field."""
    if name in _SYSTEM_FIELDS:
        return f"{prefix}win.system.{_SYSTEM_FIELDS[name]}"
    if name.startswith(("win.", "data.", "agent.", "rule.", "manager.")):
        return name if not prefix or name.startswith(prefix) else prefix + name
    return f"{prefix}win.eventdata.{name[:1].lower()}{name[1:]}"


def pipeline(prefix: str = ""):
    """Event-channel conditions plus Wazuh field names. Use after the `sysmon` pipeline (which adds EventIDs)."""
    from sigma.processing.conditions import FieldNameProcessingItemAppliedCondition, LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import AddConditionTransformation, FieldFunctionTransformation

    items = [ProcessingItem(identifier=f"ti2dac_wazuh_channel_{svc}", transformation=AddConditionTransformation({"Channel": ch}),
                            rule_conditions=[LogsourceCondition(product="windows", service=svc)])
             for svc, ch in CHANNELS.items()]
    items += [ProcessingItem(identifier=f"ti2dac_wazuh_{cat}", transformation=AddConditionTransformation({"Channel": ch, "EventID": eid}),
                             rule_conditions=[LogsourceCondition(product="windows", category=cat)])
              for cat, (ch, eid) in _CATEGORY_EVENTS.items()]
    items.append(ProcessingItem(identifier="ti2dac_wazuh_fields",
                                transformation=FieldFunctionTransformation(lambda f: field(f, prefix)),
                                rule_conditions=[LogsourceCondition(product="windows")],
                                # fields a client profile already renamed keep the client's name
                                field_name_conditions=[FieldNameProcessingItemAppliedCondition("ti2dac_client_fields")],
                                field_name_condition_negation=True))
    return ProcessingPipeline(name=f"ti2dac Wazuh {'indexer' if prefix else 'rule'} fields", priority=20, items=items)


# --------------------------------------------------------------------------- rule XML backend
class _Lit:
    __slots__ = ("field", "patterns", "neg")

    def __init__(self, field_: str | None, patterns: list[str], neg: bool = False):
        self.field, self.patterns, self.neg = field_, patterns, neg


def _pattern(value, anchored: bool = True) -> str:
    """One Sigma value -> PCRE2 pattern with Sigma's full-match, case-insensitive semantics. Keywords
    (`anchored=False`) are substring matches against the whole log line."""
    from sigma.types import SigmaExpansion, SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars

    a, z = ("^", "$") if anchored else ("", "")
    if isinstance(value, SigmaExpansion):
        return "(?:" + "|".join(_pattern(v, anchored) for v in value.values) + ")"
    if isinstance(value, SigmaNumber):
        return f"{a}{value.number}{z}"
    if isinstance(value, SigmaRegularExpression):
        flags = "".join(sorted({str(getattr(f, "name", f)).lower()[:1] for f in getattr(value, "flags", set()) or set()}
                               & {"i", "m", "s"}))
        return f"(?{flags}:{value.regexp})" if flags else f"(?:{value.regexp})"
    if isinstance(value, SigmaString):
        out = []
        for part in value.s:
            if part == SpecialChars.WILDCARD_MULTI:
                out.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                out.append(".")
            else:
                out.append(re.escape(str(part)))
        cased = type(value).__name__ == "SigmaCasedString"
        return ("(?:" if cased else "(?i:") + a + "".join(out) + z + ")"   # scoped flag: safe inside alternations
    raise NotImplementedError(f"{type(value).__name__} values (e.g. cidr, null, numeric comparisons, field "
                              "references) have no Wazuh rule equivalent here")


def _dnf(node) -> list[list[_Lit]]:
    """Condition tree -> OR of AND-ed literals. Same-field OR lists stay one literal (a regex alternation)."""
    from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR,
                                  ConditionValueExpression)

    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[_Lit(node.field, [_pattern(node.value)])]]
    if isinstance(node, ConditionValueExpression):
        return [[_Lit(None, [_pattern(node.value, anchored=False)])]]
    if isinstance(node, ConditionOR):
        leaves = node.args
        if all(isinstance(a, ConditionFieldEqualsValueExpression) for a in leaves) and len({a.field for a in leaves}) == 1:
            return [[_Lit(leaves[0].field, [_pattern(a.value) for a in leaves])]]
        return [conj for a in leaves for conj in _dnf(a)]
    if isinstance(node, ConditionAND):
        out: list[list[_Lit]] = [[]]
        for a in node.args:
            out = [x + y for x in out for y in _dnf(a)]
            if len(out) > SLOT_SIZE - 1:
                raise NotImplementedError(f"condition expands to more than {SLOT_SIZE - 1} Wazuh rules; simplify the rule")
        return out
    if isinstance(node, ConditionNOT):
        inner = _dnf(node.args[0])
        # NOT (c1 OR c2 ...) = AND of NOT ci; NOT (a AND b) = NOT a OR NOT b
        out = [[]]
        for conj in inner:
            out = [x + [_Lit(lit.field, lit.patterns, not lit.neg)] for x in out for lit in conj]
            if len(out) > SLOT_SIZE - 1:
                raise NotImplementedError(f"condition expands to more than {SLOT_SIZE - 1} Wazuh rules; simplify the rule")
        return out
    raise NotImplementedError(f"condition element {type(node).__name__} is not supported for Wazuh rules")


def _merge(conj: list[_Lit]) -> list[tuple[str | None, str, bool]]:
    """One (field, regex, negate) per field: several conditions on one field become lookaheads in one regex."""
    by: dict[str | None, list[_Lit]] = {}
    for lit in conj:
        by.setdefault(lit.field, []).append(lit)
    out = []
    for f, lits in by.items():
        alts = [("(?:" + "|".join(lit.patterns) + ")") if len(lit.patterns) > 1 else lit.patterns[0] for lit in lits]
        if len(lits) == 1:
            out.append((f, alts[0], lits[0].neg))
        elif all(lit.neg for lit in lits):      # NOT a AND NOT b = NOT (a OR b)
            out.append((f, "(?:" + "|".join(alts) + ")", True))
        else:
            out.append((f, "".join(("(?!" if lit.neg else "(?=") + a + ")" for lit, a in zip(lits, alts)), False))
    return out


def _values(conj, fieldname: str) -> list[str]:
    """Literal values of a positive exact-match condition on `fieldname` (e.g. the EventIDs the pipeline added)."""
    for f, pat, neg in conj:
        if f == fieldname and not neg and "(?=" not in pat:
            return [re.sub(r"\\(.)", r"\1", v) for v in re.findall(r"\^((?:[^$\\]|\\.)*)\$", pat)]
    return []


def _parent(conj) -> str:
    p = parents()
    channels = _values(conj, "win.system.channel")
    events = _values(conj, "win.system.eventID")
    channel = channels[0] if len(channels) == 1 else ""
    table = {"Microsoft-Windows-Sysmon/Operational": p["sysmon_event"], "Security": p["security_event"],
             "Microsoft-Windows-PowerShell/Operational": p["powershell_event"]}.get(channel, {})
    if events and table and all(e in table for e in events):
        return ", ".join(dict.fromkeys(s.strip() for e in events for s in table[e].split(",")))
    return p["channel"].get(channel, p["fallback"])


def rule_slot(sigma_id: str) -> int:
    return RULE_ID_BASE + int(hashlib.sha256(sigma_id.encode()).hexdigest(), 16) % RULE_ID_SLOTS * SLOT_SIZE


_RULE_ID = re.compile(r'(<rule id=")(\d+)(")')


def resolve_slot_collisions(packages) -> None:
    """Rules hash into RULE_ID_SLOTS slots, so two rules of one run can share ids (even odds at ~37 rules).
    Each rule, in package order, gets its hashed slot or the next free one; per client, as each client deploys
    its own copy. Deterministic for a given list of packages, and idempotent."""
    used: dict[str, set[int]] = {}
    for p in packages:
        want = (rule_slot(p.rule_id) - RULE_ID_BASE) // SLOT_SIZE
        for q in p.queries:
            ids = [int(m[2]) for m in _RULE_ID.finditer(q.query or "")] if q.target == "wazuh_rule" and q.method != "llm" else []
            taken = used.setdefault(q.client, set())
            if not ids or len(taken) >= RULE_ID_SLOTS:
                continue
            slot = want
            while slot in taken:
                slot = (slot + 1) % RULE_ID_SLOTS
            taken.add(slot)
            delta = (slot - (min(ids) - RULE_ID_BASE) // SLOT_SIZE) * SLOT_SIZE
            if delta:
                q.query = _RULE_ID.sub(lambda m, d=delta: f"{m[1]}{int(m[2]) + d}{m[3]}", q.query)


def _rule_elements(rule, level: int | None = None, group: str = "") -> list[ET.Element]:
    sigma_id = str(rule.id or rule.title)
    conjs = [_merge(c) for cond in rule.detection.parsed_condition for c in _dnf(cond.parsed)]
    if len(conjs) > SLOT_SIZE - 1:
        raise NotImplementedError(f"condition expands to {len(conjs)} Wazuh rules; simplify the rule")
    lvl = level if level is not None else _LEVELS.get(str(rule.level.name).lower() if rule.level else "medium", 8)
    techniques = sorted({t.name.upper() for t in rule.tags if t.namespace == "attack" and re.fullmatch(r"t\d{4}(\.\d{3})?", t.name)})
    out = []
    for i, conj in enumerate(conjs):
        el = ET.Element("rule", id=str(rule_slot(sigma_id) + i), level=str(lvl))
        ET.SubElement(el, "if_sid").text = _parent(conj)
        for f, pat, neg in conj:
            re.compile(pat)   # surface broken patterns now (generated patterns use syntax PCRE2 and Python share)
            attrs = {"type": "pcre2", **({"negate": "yes"} if neg else {})}
            sub = ET.SubElement(el, "regex", attrs) if f is None else ET.SubElement(el, "field", {"name": f, **attrs})
            sub.text = pat
        ET.SubElement(el, "description").text = (f"{rule.title} (Sigma {sigma_id})" +
                                                 (f" [{i + 1}/{len(conjs)}]" if len(conjs) > 1 else ""))
        if techniques:
            mitre = ET.SubElement(el, "mitre")
            for t in techniques:
                ET.SubElement(mitre, "id").text = t
        ET.SubElement(el, "group").text = ",".join(x for x in ("ti2dac", "sigma", group) if x) + ","
        out.append(el)
    return out


def _correlation_element(corr, base_rule, group: str) -> ET.Element:
    ctype = str(getattr(corr.type, "name", corr.type)).lower()
    cond = corr.condition
    op = str(getattr(cond.op, "name", cond.op)).lower()
    if ctype not in ("event_count", "value_count") or op not in ("gte", "gt"):
        raise NotImplementedError(f"Wazuh rules support event_count/value_count thresholds with gte/gt, not {ctype} {op}")
    count = max(2, cond.count + (1 if op == "gt" else 0))
    el = ET.Element("rule", id=str(rule_slot(str(base_rule.id or base_rule.title)) + SLOT_SIZE - 1),
                    level=str(_LEVELS.get(str(corr.level.name).lower() if corr.level else "medium", 8)),
                    frequency=str(count), timeframe=str(corr.timespan.seconds))
    ET.SubElement(el, "if_matched_group").text = group
    for g in corr.group_by or []:
        ET.SubElement(el, "same_field").text = field(g)
    if ctype == "value_count" and cond.fieldref:
        ET.SubElement(el, "different_field").text = field(cond.fieldref)
    ET.SubElement(el, "description").text = (f"{corr.title}: {count}+ matches within {corr.timespan.spec}"
                                             + (f" per {', '.join(corr.group_by)}" if corr.group_by else ""))
    ET.SubElement(el, "group").text = "ti2dac,sigma,correlation,"
    return el


class WazuhRuleBackend:
    """pySigma-backend-shaped converter: `convert(collection) -> str` with Wazuh rule XML."""

    def __init__(self, processing_pipeline=None, **_):
        self.pipeline = processing_pipeline

    def convert(self, collection) -> str:
        from sigma.correlations import SigmaCorrelationRule

        rules = [r for r in collection.rules if not isinstance(r, SigmaCorrelationRule)]
        corrs = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
        root = ET.Element("group", name="ti2dac,sigma,")
        for r in rules:
            if self.pipeline is not None:
                self.pipeline.apply(r)
        base_of = {}
        for c in corrs:
            if len(c.rules) != 1:
                raise NotImplementedError("Wazuh threshold rules here cover one base rule; multi-rule sequences are not generated")
            base_of[c.rules[0].reference] = c
        for r in rules:
            corr = base_of.get(r.name or "")
            group = f"ti2dac_{hashlib.sha256(str(r.id).encode()).hexdigest()[:8]}" if corr else ""
            root.extend(_rule_elements(r, level=0 if corr else None, group=group))
            if corr:
                root.append(_correlation_element(corr, r, group))
        ET.indent(root, space="  ")
        header = (f"<!-- Generated by ti2dac from Sigma. Parent rules (if_sid) follow the Wazuh {parents()['ruleset_version']} "
                  "default ruleset; rule ids are in 100000-119999 (renumber to fit your local_rules.xml). "
                  "Test with /var/ossec/bin/wazuh-logtest before deploying. -->")
        return header + "\n" + ET.tostring(root, encoding="unicode")
