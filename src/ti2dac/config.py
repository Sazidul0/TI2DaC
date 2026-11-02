"""Runtime configuration.

Precedence: built-in defaults < ti2dac.yaml (or --config) < environment variables (TI2DAC_*).
Secrets (ANTHROPIC_API_KEY, web credentials) are only ever read from the environment.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class StageConfig:
    model: str = "claude-opus-5-5"
    effort: str = "medium"          # low | medium | high | xhigh | max
    max_tokens: int = 16000


@dataclass
class AIConfig:
    enabled: bool = True
    # "anthropic" (default, Claude) or "gemini" (Google AI Studio; key in GEMINI_API_KEY).
    provider: str = "anthropic"
    gemini_model: str = "gemini-flash-latest"   # used for every stage still set to a Claude model
    # Per-stage model/effort. Effort is the main token lever: extraction is mechanical,
    # rule generation is where reasoning pays off.
    analyze: StageConfig = field(default_factory=lambda: StageConfig(effort="medium", max_tokens=16000))
    generate: StageConfig = field(default_factory=lambda: StageConfig(effort="high", max_tokens=24000))
    repair: StageConfig = field(default_factory=lambda: StageConfig(effort="medium", max_tokens=8000))
    translate: StageConfig = field(default_factory=lambda: StageConfig(effort="low", max_tokens=4000))
    # Server-side refusal fallback (security content can trip the cyber classifier).
    server_side_fallback: bool = True
    max_repair_attempts: int = 2
    # Report text sent to the analysis call is condensed to roughly this many tokens.
    input_token_budget: int = 6000
    max_behaviours: int = 10
    response_cache: bool = True
    max_lessons_in_prompt: int = 5
    # TLP 2.0 data-handling policy: which markings may be sent (after redaction) to each provider.
    # Gemini's free tier may use prompts for training, so it only gets public-grade content.
    allowed_tlp: dict[str, list[str]] = field(default_factory=lambda: {
        "anthropic": ["clear", "green", "amber"],
        "gemini": ["clear", "green"],
    })
    # Our own daily request cap per provider (0 = none). Stops BEFORE the provider's limit, e.g. 18 for a
    # 20-requests/day free tier. Counts real requests only (cache hits are free).
    daily_request_limit: int = 0
    # Parallel generation calls (0 = auto: 1 for gemini, whose free tier punishes bursts; 4 for anthropic).
    max_parallel: int = 0
    # Assumed marking for unmarked documents.
    default_tlp_threat_intel: str = "clear"
    default_tlp_incident: str = "amber"


@dataclass
class RedactionConfig:
    """Pseudonymization applied to every report before condensing and before any AI call."""
    enabled: bool = True
    internal_domains: list[str] = field(default_factory=list)    # e.g. [corp.local, example-corp.com]
    internal_networks: list[str] = field(default_factory=list)   # extra CIDRs beyond RFC1918
    terms: list[str] = field(default_factory=list)               # customer / organisation / project names
    hostname_patterns: list[str] = field(default_factory=list)   # regexes for your host naming scheme


@dataclass
class FetchConfig:
    allow_urls: bool = True
    allowed_domains: list[str] = field(default_factory=list)   # empty = any public host
    max_bytes: int = 25 * 1024 * 1024
    timeout_s: float = 30.0


@dataclass
class Settings:
    author: str = "SHL Detection Engineering (ti2dac)"
    output_dir: str = "output"
    state_dir: str = ".ti2dac"
    select_count: int = 3
    # Deterministic pySigma targets (see targets.py for the registry).
    targets: list[str] = field(default_factory=lambda: [
        "splunk", "splunk_cim", "elastic_lucene", "elastic_esql", "elastic_eql",
        "sentinel_asim", "sentinel_securityevent", "defender_xdr", "crowdstrike_cql",
        "qradar_aql", "opensearch", "loki",
    ])
    # SIEMs without a pySigma backend; translated by the model and flagged as unverified.
    llm_targets: list[str] = field(default_factory=list)
    # SIEM families (targets.FAMILIES) that must always get a query: if no pySigma target of the
    # family converts a rule, the model writes one (flagged unverified). One small call per gap.
    ai_fill_gaps: list[str] = field(default_factory=lambda: ["splunk", "elastic", "sentinel", "defender", "crowdstrike"])
    # Log sources the organisation actually collects, as "product:category" or "product:service"
    # (e.g. windows:process_creation, windows:security, linux:auditd). Empty = don't check.
    telemetry: list[str] = field(default_factory=list)
    # Environment-specific query scoping, e.g. {splunk: "index=wineventlog", elastic_esql: "logs-endpoint.events.*"}
    index_overrides: dict[str, str] = field(default_factory=dict)
    # Folders of existing (internal) Sigma rules to check generated rules against for duplicates.
    rule_repos: list[str] = field(default_factory=list)
    ai: AIConfig = field(default_factory=AIConfig)
    fetch: FetchConfig = field(default_factory=FetchConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)

    @property
    def cache_dir(self) -> Path:
        return Path(self.state_dir) / "cache"

    @property
    def db_path(self) -> Path:
        return Path(self.state_dir) / "ti2dac.db"


def _merge(obj: Any, data: dict[str, Any]) -> Any:
    for f in fields(obj):
        if f.name not in data:
            continue
        cur, new = getattr(obj, f.name), data[f.name]
        if is_dataclass(cur) and isinstance(new, dict):
            _merge(cur, new)
        else:
            setattr(obj, f.name, new)
    return obj


def load_dotenv(path: str | Path = ".env") -> None:
    """Read KEY=VALUE lines from a local .env (git-ignored) into the environment; real env vars win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def env_file() -> Path:
    return Path(os.environ.get("TI2DAC_ENV_FILE", ".env"))


def _env_file_values(p: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if p.is_file():
        for line in p.read_text().splitlines():
            key, sep, value = line.strip().removeprefix("export ").partition("=")
            if sep and key.strip() and not key.strip().startswith("#"):
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                out[key.strip()] = value
    return out


def env_source(name: str) -> str:
    """Where the current value of a secret comes from: '.env', 'environment' (shell / service manager) or ''."""
    if not os.environ.get(name):
        return ""
    return ".env" if _env_file_values(env_file()).get(name) == os.environ[name] else "environment"


def set_env_secret(name: str, value: str | None) -> Path:
    """Write NAME=value to the .env file (or remove it with None) and apply it to this process.

    The file is replaced atomically and kept owner-readable only; other lines are preserved."""
    p = env_file()
    lines = p.read_text().splitlines() if p.is_file() else []
    keep = [ln for ln in lines if ln.strip().removeprefix("export ").partition("=")[0].strip() != name]
    if value is not None:
        keep.append(f"{name}={value}")
    tmp = p.with_name(p.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(keep) + ("\n" if keep else ""))
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    return p


def load_settings(path: str | Path | None = None) -> Settings:
    load_dotenv(os.environ.get("TI2DAC_ENV_FILE", ".env"))
    s = Settings()
    cfg = Path(path) if path else Path(os.environ.get("TI2DAC_CONFIG", "ti2dac.yaml"))
    if cfg.is_file():
        _merge(s, yaml.safe_load(cfg.read_text()) or {})
    elif path:
        raise FileNotFoundError(f"config file not found: {cfg}")

    env = os.environ
    if "TI2DAC_AUTHOR" in env:
        s.author = env["TI2DAC_AUTHOR"]
    if "TI2DAC_OUTPUT_DIR" in env:
        s.output_dir = env["TI2DAC_OUTPUT_DIR"]
    if "TI2DAC_STATE_DIR" in env:
        s.state_dir = env["TI2DAC_STATE_DIR"]
    if env.get("TI2DAC_NO_AI", "").lower() in ("1", "true", "yes"):
        s.ai.enabled = False
    if "TI2DAC_PROVIDER" in env:
        s.ai.provider = env["TI2DAC_PROVIDER"].lower()
    if s.ai.provider not in ("anthropic", "gemini"):
        raise ValueError(f"ai.provider must be 'anthropic' or 'gemini', not {s.ai.provider!r}")
    stages = (s.ai.analyze, s.ai.generate, s.ai.repair, s.ai.translate)
    if s.ai.provider == "gemini":
        for st in stages:
            if st.model.startswith("claude"):
                st.model = s.ai.gemini_model
    if "TI2DAC_MODEL" in env:   # one switch to move every stage to another model
        for st in stages:
            st.model = env["TI2DAC_MODEL"]
    return s
