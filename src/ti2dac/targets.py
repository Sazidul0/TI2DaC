"""SIEM target registry.

Each deterministic target = pySigma backend + processing pipelines chosen per logsource
product. Translation through pySigma costs zero tokens and is reproducible, which is why
the LLM is never used for SIEMs that have a backend.

Add a SIEM: install its pySigma backend, then add a Target here (``sigma list targets`` /
``sigma list pipelines`` show the identifiers).
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from functools import lru_cache

warnings.filterwarnings("ignore", category=SyntaxWarning)   # noisy regex literals in some backends


@dataclass(frozen=True)
class Target:
    id: str
    label: str
    language: str
    backend: str
    ext: str
    # product -> pipeline identifiers ("*" = any product). None = target unsupported for product.
    pipelines: dict[str, list[str] | None] = field(default_factory=dict)
    backend_options: dict = field(default_factory=dict)
    notes: str = ""

    def pipelines_for(self, product: str) -> list[str] | None:
        if product in self.pipelines:
            return self.pipelines[product]
        return self.pipelines.get("*", [])


TARGETS: dict[str, Target] = {t.id: t for t in [
    Target("splunk", "Splunk SPL (Sysmon / WinEventLog sourcetypes)", "SPL", "splunk", "spl",
           {"windows": ["sysmon", "splunk_windows"], "*": []},
           notes="Prepend your index, e.g. index=wineventlog."),
    Target("splunk_cim", "Splunk SPL (CIM data models)", "SPL", "splunk", "cim.spl",
           {"*": ["splunk_cim"]}, notes="Requires the Endpoint/Network CIM data models to be populated."),
    Target("elastic_lucene", "Elastic Lucene (ECS)", "Lucene", "lucene", "lucene",
           {"windows": ["ecs_windows"], "linux": ["ti2dac_ecs_linux"], "*": []}),
    Target("elastic_esql", "Elastic ES|QL (ECS)", "ES|QL", "esql", "esql",
           {"windows": ["ecs_windows"], "linux": ["ti2dac_ecs_linux"], "*": []},
           notes="Replace 'from *' with your index pattern, e.g. logs-endpoint.events.*"),
    Target("elastic_eql", "Elastic EQL (ECS)", "EQL", "eql", "eql",
           {"windows": ["ecs_windows"], "linux": ["ti2dac_ecs_linux"], "*": []}),
    Target("sentinel_asim", "Microsoft Sentinel KQL (ASIM parsers)", "KQL", "kusto", "asim.kql",
           {"*": ["ti2dac_asim_fixups", "sentinel_asim"]}),
    Target("sentinel_securityevent", "Microsoft Sentinel KQL (SecurityEvent table)", "KQL", "kusto", "securityevent.kql",
           {"windows": ["azure_monitor"], "*": None}),
    Target("defender_xdr", "Microsoft Defender XDR Advanced Hunting KQL", "KQL", "kusto", "xdr.kql",
           {"*": ["microsoft_xdr"]}),
    Target("crowdstrike_cql", "CrowdStrike Falcon NG-SIEM / LogScale CQL", "CQL", "log_scale", "cql",
           {"*": ["crowdstrike_falcon"]}, notes="Desk-check only unless an NG-SIEM tenant is available."),
    Target("qradar_aql", "IBM QRadar AQL", "AQL", "q_radar_aql", "aql",
           {"*": ["qradar-aql-fields"]}),
    Target("opensearch", "OpenSearch Lucene (ECS)", "Lucene", "opensearch_lucene", "opensearch.lucene",
           {"windows": ["ecs_windows"], "linux": ["ti2dac_ecs_linux"], "*": []}),
    Target("loki", "Grafana Loki LogQL", "LogQL", "loki", "logql",
           {"windows": ["loki_promtail_sysmon"], "*": []}),
]}

# SIEM families. When every configured deterministic target of a family in `ai_fill_gaps` fails
# (e.g. the Kusto backend cannot pick a Sentinel table for PowerShell 4104 or service 7045 rules),
# one AI translation fills the gap so each rule still has a query for each required SIEM.
FAMILIES: dict[str, tuple[list[str], str, str]] = {
    "splunk": (["splunk", "splunk_cim"], "Splunk SPL", "SPL"),
    "elastic": (["elastic_lucene", "elastic_esql", "elastic_eql"], "Elastic ES|QL (ECS / Elastic integrations)", "ES|QL"),
    "sentinel": (["sentinel_asim", "sentinel_securityevent"], "Microsoft Sentinel KQL (native tables)", "KQL"),
    "defender": (["defender_xdr"], "Microsoft Defender XDR Advanced Hunting KQL", "KQL"),
    "crowdstrike": (["crowdstrike_cql"], "CrowdStrike Falcon NG-SIEM / LogScale CQL", "CQL"),
    "qradar": (["qradar_aql"], "IBM QRadar AQL", "AQL"),
}

# Targets whose pipelines rename Sigma fields; a field that comes out unchanged was not mapped
# and probably does not exist under that name in the SIEM.
RENAMING_TARGETS = {"splunk_cim", "elastic_lucene", "elastic_esql", "elastic_eql", "opensearch",
                    "sentinel_asim", "sentinel_securityevent", "defender_xdr", "crowdstrike_cql"}

# Sigma field names that are ALSO the platform's native field name, so passing through unchanged is correct.
NATIVE_FIELDS: dict[str, set[str]] = {
    "crowdstrike_cql": {"CommandLine", "ImageFileName", "UserName", "ParentBaseFileName", "TargetFileName"},
    "sentinel_securityevent": {"CommandLine", "ParentProcessName", "NewProcessName", "Computer", "EventID",
                               "TargetUserName", "SubjectUserName", "LogonType", "IpAddress", "ServiceName"},
    "sentinel_asim": {"EventID"},
    "defender_xdr": {"ActionType"},
}

# Common names for SIEMs without a pySigma backend (LLM-translated, flagged unverified).
LLM_TARGET_LABELS = {
    "google_secops_yaral": ("Google SecOps (Chronicle) YARA-L 2.0", "YARA-L"),
    "sumologic": ("Sumo Logic Search", "Sumo"),
    "exabeam": ("Exabeam Search", "EQL-Exabeam"),
    "securonix": ("Securonix Spotter", "Spotter"),
    "logrhythm": ("LogRhythm SIEM", "LogRhythm"),
    "fortisiem": ("FortiSIEM", "FortiSIEM"),
    "wazuh": ("Wazuh rule XML", "Wazuh XML"),
    "sentinelone_pq": ("SentinelOne PowerQuery", "S1QL"),
}


def _ecs_linux_pipeline():
    from sigma.processing.conditions import LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation

    linux = LogsourceCondition(product="linux")
    mapping = {
        "Image": "process.executable", "CommandLine": "process.command_line", "ProcessId": "process.pid",
        "ParentImage": "process.parent.executable", "ParentCommandLine": "process.parent.command_line",
        "ParentProcessId": "process.parent.pid", "CurrentDirectory": "process.working_directory",
        "User": "user.name", "LogonId": "process.user.id", "TargetFilename": "file.path",
        "DestinationIp": "destination.ip", "DestinationPort": "destination.port",
        "DestinationHostname": "destination.domain", "SourceIp": "source.ip", "SourcePort": "source.port",
        "Protocol": "network.transport", "QueryName": "dns.question.name",
        "type": "auditd.data.type", "a0": "auditd.data.a0", "a1": "auditd.data.a1", "a2": "auditd.data.a2",
        "exe": "process.executable", "comm": "process.name", "key": "tags",
    }
    return ProcessingPipeline(
        name="ti2dac ECS mapping for Linux (Elastic Agent / Auditbeat)",
        priority=20,
        items=[
            ProcessingItem(identifier="ti2dac_ecs_linux_proc_cond",
                           transformation=AddConditionTransformation({"event.category": "process", "event.type": "start"}),
                           rule_conditions=[LogsourceCondition(product="linux", category="process_creation")]),
            ProcessingItem(identifier="ti2dac_ecs_linux_fields",
                           transformation=FieldMappingTransformation(mapping), rule_conditions=[linux]),
        ],
    )


def _asim_fixups_pipeline():
    """pySigma-backend-kusto 0.4 maps OriginalFileName to a column imProcessCreate does not have."""
    from sigma.processing.conditions import LogsourceCondition
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    return ProcessingPipeline(
        name="ti2dac ASIM field fix-ups", priority=5,
        items=[ProcessingItem(identifier="ti2dac_asim_originalfilename",
                              transformation=FieldMappingTransformation({"OriginalFileName": "TargetProcessFileOriginalName"}),
                              rule_conditions=[LogsourceCondition(category="process_creation")])],
    )


_LOCAL_PIPELINES = {"ti2dac_ecs_linux": _ecs_linux_pipeline, "ti2dac_asim_fixups": _asim_fixups_pipeline}


@lru_cache(maxsize=1)
def plugins():
    from sigma.plugins import InstalledSigmaPlugins

    return InstalledSigmaPlugins.autodiscover()


def resolve_pipeline(names: list[str]):
    from sigma.processing.pipeline import ProcessingPipeline

    resolver = plugins().get_pipeline_resolver()
    pipeline = ProcessingPipeline()
    for n in names:
        pipeline = pipeline + (_LOCAL_PIPELINES[n]() if n in _LOCAL_PIPELINES else resolver.resolve_pipeline(n))
    return pipeline


def make_backend(target: Target, product: str):
    names = target.pipelines_for(product)
    if names is None:
        raise LookupError(f"{target.label} does not support logsource product '{product}'")
    backend_cls = plugins().backends.get(target.backend)
    if backend_cls is None:
        raise LookupError(f"pySigma backend '{target.backend}' is not installed")
    return backend_cls(processing_pipeline=resolve_pipeline(names) if names else None, **target.backend_options)
