"""Data models.

Two families:
  * LLM I/O schemas (``Extracted*``, ``*Draft``): passed to the API as structured-output
    JSON schemas. Every field is required (strict schema), descriptions are terse because
    they are sent with every request.
  * Pipeline records (``Behaviour``, ``DetectionPackage``, ``RunRecord``): what we persist.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

# ATT&CK v18+ split "defense-evasion" into "stealth" and "defense-impairment"; the old name is
# accepted from the model and corrected against the local ATT&CK index (attack.validate_mapping).
Tactic = Literal[
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]
Platform = Literal["windows", "linux", "macos", "cloud", "network", "other"]
Level = Literal["informational", "low", "medium", "high", "critical"]
Modifier = Literal[
    "contains", "startswith", "endswith", "all", "re", "windash", "base64", "base64offset",
    "cidr", "exists", "cased", "wide", "utf16le", "utf16be", "utf16", "gt", "gte", "lt", "lte",
    "i", "m", "s",
]
ValidationStatus = Literal[
    "not-tested", "syntax-validated", "desk-checked", "tested-positive", "tested-negative",
    "tested-positive-and-negative", "failed",
]


# --------------------------------------------------------------------------- stage 1 (analyze)
class Observables(BaseModel):
    processes: list[str] = Field(description="Executable names, e.g. rundll32.exe")
    command_lines: list[str] = Field(description="Verbatim command lines or fragments")
    registry: list[str]
    files: list[str] = Field(description="Paths / file name patterns (not hashes)")
    services_tasks: list[str] = Field(description="Service, scheduled task, WMI names")
    network: list[str] = Field(description="Ports/protocols/patterns, not IOC IPs/domains")


class Scores(BaseModel):
    observability: int = Field(description="1-5: visible in common endpoint/OS logs")
    reproducibility: int = Field(description="1-5: can be safely simulated in a lab")
    mapping_confidence: int = Field(description="1-5: confidence in the ATT&CK mapping")
    fp_risk: int = Field(description="1-5: 5 = very noisy in normal enterprise activity")


class ExtractedBehaviour(BaseModel):
    id: str = Field(description="B1, B2, ...")
    name: str = Field(description="<= 10 words")
    description: str = Field(description="<= 40 words, what the attacker did")
    tactic: Tactic
    technique_id: str = Field(description="ATT&CK ID, sub-technique when known, e.g. T1059.001")
    technique_name: str
    platform: Platform
    evidence: list[str] = Field(description="1-3 VERBATIM quotes from the report, each <= 200 chars")
    observables: Observables
    log_sources: list[str] = Field(description="e.g. 'Sysmon EID 1', 'Security 4698', 'auditd execve'")
    detection_idea: str = Field(description="<= 25 words")
    scores: Scores


class TimelineEvent(BaseModel):
    when: str
    event: str


class ReportAnalysis(BaseModel):
    title: str
    actors: list[str]
    malware_tools: list[str]
    victimology: str
    summary: str = Field(description="<= 60 words")
    behaviours: list[ExtractedBehaviour]
    timeline: list[TimelineEvent] = Field(description="<= 8 key events, empty if none")


# --------------------------------------------------------------------------- stage 2 (generate)
class FieldCondition(BaseModel):
    field: str = Field(description="Sigma taxonomy field name; empty string = keyword search")
    modifiers: list[Modifier]
    values: list[str] = Field(description="OR-ed values (AND-ed with the 'all' modifier)")


class Clause(BaseModel):
    conditions: list[FieldCondition] = Field(description="AND-ed field conditions")


class Selection(BaseModel):
    name: str = Field(description="selection_*, filter_* ...")
    clauses: list[Clause] = Field(description="OR-ed clauses; usually exactly one")


class LogSource(BaseModel):
    product: str
    category: str = Field(description="Sigma category or empty string")
    service: str = Field(description="Sigma service or empty string")


class CorrelationDraft(BaseModel):
    type: Literal["event_count", "value_count", "temporal"]
    group_by: list[str] = Field(description="Fields to group by, e.g. [IpAddress] or [Computer, User]")
    timespan: str = Field(description="e.g. 5m, 1h")
    gte: int = Field(description="Threshold: alert when the count is >= this")
    value_field: str = Field(description="value_count only: field whose distinct values are counted; else empty")


class SigmaDraft(BaseModel):
    title: str = Field(description="<= 10 words")
    description: str = Field(description="<= 50 words")
    logsource: LogSource
    selections: list[Selection]
    condition: str = Field(description="Sigma condition over selection names")
    falsepositives: list[str]
    level: Level
    correlation: list[CorrelationDraft] = Field(
        description="[] for single-event rules. One item ONLY when the behaviour is a threshold/rate "
                    "(spraying, brute force, mass discovery); the selection then describes ONE such event.")

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data):   # records written before correlation support
        if isinstance(data, dict):
            data.setdefault("correlation", [])
        return data


class TelemetryDraft(BaseModel):
    log_source: str
    event_ids: list[str]
    required_fields: list[str]
    config_requirements: list[str] = Field(description="Audit policy / Sysmon / auditd settings needed")
    blind_spots: list[str]


class ExpectedEvent(BaseModel):
    source: str
    event_id: str
    matching_fields: str = Field(description="field=value pairs the rule will match on")


class SimulationDraft(BaseModel):
    platform: Literal["windows", "linux", "macos", "cloud"]
    privileges: Literal["user", "admin"]
    language: Literal["powershell", "bash", "python"]
    preconditions: list[str]
    simulate: str = Field(description="Benign script reproducing ONLY the telemetry pattern")
    cleanup: str = Field(description="Script reverting every change made by simulate")
    expected_events: list[ExpectedEvent]
    atomic_tests: list[str] = Field(description="Atomic Red Team test names you are sure exist; else []")
    safety_notes: list[str]


class NegativeTestDraft(BaseModel):
    benign_activities: list[str] = Field(description="Similar-looking legitimate actions that must NOT alert")


class ADSDraft(BaseModel):
    goal: str
    strategy_abstract: str
    technical_context: str = Field(description="<= 120 words")
    triage_steps: list[str]
    response_actions: list[str]


class EventField(BaseModel):
    name: str = Field(description="Sigma taxonomy field name, same as used in the rule")
    value: str


class TestEvent(BaseModel):
    description: str
    should_match: bool
    fields: list[EventField] = Field(description="Flat log event as the telemetry would record it")


class DetectionDraft(BaseModel):
    sigma: SigmaDraft
    telemetry: TelemetryDraft
    simulation: SimulationDraft
    negative_test: NegativeTestDraft
    ads: ADSDraft
    test_events: list[TestEvent] = Field(
        description="2-4 events: the exact event(s) the simulation produces (should_match=true) and benign "
                    "look-alikes from the negative test (should_match=false). Used to unit-test the rule.")

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data):   # records written before rule self-tests
        if isinstance(data, dict):
            data.setdefault("test_events", [])
        return data


class TranslationDraft(BaseModel):
    query: str
    notes: str = Field(description="Assumptions: index/table names, field names")
    confidence: Literal["low", "medium", "high"]


# --------------------------------------------------------------------------- pipeline records
class ReportMeta(BaseModel):
    source: str
    title: str = ""
    sha256: str
    retrieved_at: str
    content_type: str
    chars: int
    condensed_chars: int = 0
    authors: str = ""
    published: str = ""
    url: str = ""                    # canonical URL (fetched URL, or <link rel=canonical> of a saved page)
    kind: Literal["threat-intel", "incident"] = "threat-intel"
    tlp: str = ""                    # marking found in the document ('' = unmarked)
    tlp_effective: str = ""          # marking applied (found, or the configured default)
    tlp_override: str = ""           # reason, if a human overrode the TLP policy
    redactions: dict[str, int] = {}  # placeholder kind -> count (the mapping itself stays in source/)
    embedded_events: int = 0         # raw log events found inside the report


class IOCSet(BaseModel):
    ipv4: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    md5: list[str] = []
    sha1: list[str] = []
    sha256: list[str] = []
    cves: list[str] = []
    attack_ids: list[str] = []
    file_paths: list[str] = []
    registry_keys: list[str] = []
    file_names: list[str] = []       # executable/script names mentioned (used to spot brittle rules)


class Behaviour(ExtractedBehaviour):
    evidence_verified: list[bool] = []
    attack_valid: bool = True
    attack_note: str = ""
    rank_score: float = 0.0
    selected: bool = False


class QueryResult(BaseModel):
    target: str
    label: str
    language: str
    method: Literal["pysigma", "llm"]
    query: str | None = None
    error: str | None = None
    notes: str = ""
    validation: ValidationStatus = "not-tested"


class FieldMapping(BaseModel):
    sigma_field: str
    targets: dict[str, str]          # target -> mapped field(s) or "UNSUPPORTED: reason"


class LintFinding(BaseModel):
    severity: Literal["block", "warn"]
    rule: str
    line: int
    text: str


class DetectionPackage(BaseModel):
    rule_id: str                     # stable UUID (uuid5 of report hash + behaviour id)
    slug: str                        # rule-001
    version: int = 1
    behaviour: Behaviour
    draft: DetectionDraft
    rule_yaml: str
    sigma_issues: list[str] = []
    sigma_status: ValidationStatus = "not-tested"
    queries: list[QueryResult] = []
    field_mappings: list[FieldMapping] = []
    sim_lint: list[LintFinding] = []
    sim_blocked: bool = False
    quality_warnings: list[str] = []
    selftest: Literal["pass", "fail", "n/a"] = "n/a"   # rule evaluated locally against its test events
    selftest_details: list[str] = []
    similar_rules: list[str] = []      # possible duplicates in SigmaHQ / internal rule repos
    evidence_matches: int = -1         # incident evidence events this rule matches (-1 = no evidence given)
    evidence_total: int = 0
    created_by: str = ""               # author of the current version (four-eyes review)
    repair_attempts: int = 0
    review_status: Literal["draft", "reviewed", "approved", "rejected"] = "draft"
    history: list[dict[str, str]] = []   # previous versions: {version, rule_yaml, replaced_at, reason}


class Usage(BaseModel):
    calls: int = 0
    cached_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    by_stage: dict[str, dict[str, int | str]] = {}
    estimated_cost_usd: float = 0.0


class RunRecord(BaseModel):
    run_id: str
    created_at: str
    tool_version: str
    prompt_version: str
    ai_enabled: bool
    ai_provider: str = ""
    ai_models: dict[str, str] = {}
    created_by: str = ""
    report: ReportMeta
    iocs: IOCSet
    analysis: ReportAnalysis | None = None
    behaviours: list[Behaviour] = []
    packages: list[DetectionPackage] = []
    usage: Usage = Usage()
    warnings: list[str] = []
