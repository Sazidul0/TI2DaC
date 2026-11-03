"""Client profiles: per-client SIEM field names, pySigma pipelines, indexes, telemetry and schema notes.

One Sigma rule is client-neutral; each client's SIEM names fields its own way (Client A's Splunk: dest_ip,
Client B's Sentinel: DestinationIP, Client C's Wazuh: data.dstip). A profile in <clients_dir>/<name>.yaml
maps Sigma fields to that client's names per target. The mapping runs before the standard pipelines, so the
deterministic converters produce the client's own queries, and the same map is given to the AI translator
for SIEMs without a converter.

    name: acme
    description: Acme Corp, Splunk without CIM + Wazuh
    targets: [splunk, wazuh_rule]          # default: the global `targets`
    fields:                                 # target id (or "*" for all) -> {Sigma field: client field}
      splunk: {DestinationIp: dest_ip, SourceIp: src_ip, DestinationPort: dest_port}
    pipelines:                              # extra pySigma pipeline YAML files, relative to this file
      splunk: [acme-splunk.yml]
    index_overrides: {splunk: "index=acme_windows"}
    telemetry: [windows:process_creation, windows:security]
    notes:                                  # schema hints for AI translation, per target or family
      splunk: "Firewall logs: index=acme_fw sourcetype=pan:traffic"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .targets import FAMILIES, LLM_TARGET_LABELS, TARGETS

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,40}")


class ClientError(ValueError):
    pass


@dataclass
class ClientProfile:
    name: str
    path: Path
    description: str = ""
    targets: list[str] = field(default_factory=list)
    llm_targets: list[str] = field(default_factory=list)
    fields: dict[str, dict[str, str]] = field(default_factory=dict)
    pipelines: dict[str, list[str]] = field(default_factory=dict)
    index_overrides: dict[str, str] = field(default_factory=dict)
    telemetry: list[str] = field(default_factory=list)
    notes: dict[str, str] = field(default_factory=dict)

    def fields_for(self, target: str) -> dict[str, str]:
        return {**self.fields.get("*", {}), **self.fields.get(target, {})}

    def notes_for(self, target: str) -> str:
        fam = next((f for f, (members, _, _) in FAMILIES.items() if target in members or target == f"{f}_ai"), "")
        return " ".join(x for x in (self.notes.get("*", ""), self.notes.get(fam, "") if fam != target else "",
                                    self.notes.get(target, "")) if x)

    def pipeline_for(self, target: str):
        """Client mapping (runs first, priority 1) plus the client's pipeline files for this target, or None."""
        from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
        from sigma.processing.transformations import FieldMappingTransformation

        pipe = None
        mapping = self.fields_for(target)
        if mapping:
            pipe = ProcessingPipeline(name=f"client {self.name} fields", priority=1, items=[ProcessingItem(
                identifier="ti2dac_client_fields", transformation=FieldMappingTransformation(mapping))])
        for rel in self.pipelines.get(target, []):
            p = (self.path.parent / rel).resolve()
            if not p.is_relative_to(self.path.parent.resolve()) or not p.is_file():
                raise ClientError(f"client {self.name}: pipeline file {rel!r} not found next to {self.path.name}")
            extra = ProcessingPipeline.from_yaml(p.read_text())
            pipe = extra if pipe is None else pipe + extra
        return pipe


def _load(path: Path) -> ClientProfile:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise ClientError(f"{path.name}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ClientError(f"{path.name}: expected a mapping")
    name = str(data.get("name") or path.stem)
    if not _NAME.fullmatch(name):
        raise ClientError(f"{path.name}: client name {name!r} must be lower-case letters, digits, '-' or '_'")
    prof = ClientProfile(name=name, path=path, description=str(data.get("description", "")),
                         targets=list(data.get("targets") or []), llm_targets=list(data.get("llm_targets") or []),
                         fields={str(k): {str(a): str(b) for a, b in (v or {}).items()} for k, v in (data.get("fields") or {}).items()},
                         pipelines={str(k): list(v or []) for k, v in (data.get("pipelines") or {}).items()},
                         index_overrides={str(k): str(v) for k, v in (data.get("index_overrides") or {}).items()},
                         telemetry=list(data.get("telemetry") or []),
                         notes={str(k): str(v) for k, v in (data.get("notes") or {}).items()})
    unknown = [t for t in [*prof.targets, *prof.pipelines] if t not in TARGETS] + \
              [t for t in [*prof.fields, *prof.index_overrides] if t != "*" and t not in TARGETS and t not in LLM_TARGET_LABELS]
    if unknown:
        raise ClientError(f"client {name}: unknown target(s) {', '.join(sorted(set(unknown)))} "
                          f"(known: {', '.join(TARGETS)})")
    bad_llm = [t for t in prof.llm_targets if t not in LLM_TARGET_LABELS]
    if bad_llm:
        raise ClientError(f"client {name}: unknown llm_targets {', '.join(bad_llm)}")
    for t in prof.pipelines:   # fail early on broken pipeline files
        prof.pipeline_for(t)
    return prof


def _is_pipeline(path: Path) -> bool:
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return False
    return isinstance(data, dict) and "transformations" in data


def load_all(clients_dir: str | Path) -> dict[str, ClientProfile]:
    d = Path(clients_dir)
    out: dict[str, ClientProfile] = {}
    for p in sorted([*d.glob("*.yaml"), *d.glob("*.yml")]) if d.is_dir() else []:
        if _is_pipeline(p):   # a client's pySigma pipeline file kept next to its profile
            continue
        prof = _load(p)
        if prof.name in out:
            raise ClientError(f"two profiles named {prof.name!r} in {d}")
        out[prof.name] = prof
    return out


def active(settings) -> list[ClientProfile]:
    """Profiles named in settings.clients ("*" = every profile in clients_dir)."""
    if not settings.clients:
        return []
    profiles = load_all(settings.clients_dir)
    names = list(profiles) if "*" in settings.clients else settings.clients
    missing = [n for n in names if n not in profiles]
    if missing:
        raise ClientError(f"no client profile {', '.join(missing)} in {settings.clients_dir}/ "
                          f"(found: {', '.join(profiles) or 'none'})")
    return [profiles[n] for n in names]


def starter(name: str, targets: list[str], sigma_fields: list[str]) -> str:
    """A profile skeleton listing the Sigma fields existing rules use, to fill in with the client's names."""
    lines = [f"name: {name}", "description: \"\"", f"targets: [{', '.join(targets)}]", "fields:"]
    for t in targets:
        lines.append(f"  {t}:")
        lines += [f"    # {f}: <client field name>" for f in sigma_fields] or ["    {}"]
    lines += ["pipelines: {}", "index_overrides: {}", "telemetry: []", "notes: {}"]
    return "\n".join(lines) + "\n"
