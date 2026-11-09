"""Runtime configuration.

Precedence: built-in defaults < ti2dac.yaml (or --config) < the model choice saved from the web AI page or
`ti2dac model` (<state_dir>/ai_models.json) < environment variables (TI2DAC_*).
Secrets (ANTHROPIC_API_KEY, web credentials) are only ever read from the environment.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
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
    # AI review of a finished run (on request): reads the report and the run's outputs and lists mistakes.
    # Reasoning-heavy, so high effort. A reviewer model other than the one that wrote the rules gives a more
    # independent second opinion; it can be picked per review (web) or saved (`ti2dac model --stage review`).
    review: StageConfig = field(default_factory=lambda: StageConfig(effort="high", max_tokens=16000))
    # Server-side refusal fallback (security content can trip the cyber classifier).
    server_side_fallback: bool = True
    # Provider to use when the primary is down (connection error, timeout, 5xx/529 after retries); "" = off.
    # Only used when the report's TLP is in allowed_tlp for that provider. failover_model "" = provider default.
    failover_provider: str = ""
    failover_model: str = ""
    # USD per 1M tokens [input, output, cache_read] by model id, added to / overriding llm.PRICES
    # (e.g. a paid Gemini tier). Models without a price are reported as unpriced, not as $0.
    prices: dict[str, list[float]] = field(default_factory=dict)
    max_repair_attempts: int = 2
    # Report text sent to the analysis call is condensed to roughly this many tokens.
    input_token_budget: int = 6000
    # Report text sent with an AI review is condensed to roughly this many tokens (larger than the analysis
    # budget: the reviewer checks details such as patterns and lengths that the analysis may have skipped).
    review_input_token_budget: int = 16000
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
class LogConfig:
    """Operational logs (JSON lines, metadata only) for files, stderr and syslog; see obs.py."""
    level: str = "INFO"
    dir: str = ""                 # "" = <state_dir>/logs
    max_mb: int = 10              # rotate at this size; 0 = no log file
    backups: int = 5              # rotated files kept (oldest deleted)
    json_stderr: bool = False     # JSON lines on stderr too (containers, journald)
    syslog: str = ""              # forward events: "udp://siem.example:514", "tcp://host:514" or "/dev/log"


@dataclass
class HealthConfig:
    min_free_mb: int = 1024       # /healthz warns below this free space in state/output dirs; fails below a quarter
    stuck_job_minutes: int = 60   # a web job running longer than this is reported as stuck


@dataclass
class JobConfig:
    # "process": each web job runs in its own worker process, so a runaway report cannot freeze or crash
    # the UI and a job can be stopped. "thread": inside the server process (tests that patch the AI).
    isolation: str = "process"
    timeout_minutes: float = 180   # a web job running longer is stopped
    memory_mb: int = 4096          # address-space cap of a job's worker process; 0 = none


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
        "qradar_aql", "opensearch", "loki", "wazuh_rule", "wazuh_indexer",
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
    # Client profiles (clients.py): each run also produces queries in these clients' own SIEM schemas.
    clients: list[str] = field(default_factory=list)     # profile names, or ["*"] for every profile
    clients_dir: str = "clients"
    # Folders of existing (internal) Sigma rules to check generated rules against for duplicates.
    rule_repos: list[str] = field(default_factory=list)
    ai: AIConfig = field(default_factory=AIConfig)
    fetch: FetchConfig = field(default_factory=FetchConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    log: LogConfig = field(default_factory=LogConfig)
    health: HealthConfig = field(default_factory=HealthConfig)
    jobs: JobConfig = field(default_factory=JobConfig)

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
    apply_model_choice(s, read_model_choice(s.state_dir))
    apply_ai_env(s)
    return s


# --------------------------------------------------------------------------- model choice (web AI page / `ti2dac model`)
PROVIDERS = ("anthropic", "gemini")
STAGES = ("analyze", "generate", "repair", "translate", "review")
ENV_MODEL_VARS = ("TI2DAC_PROVIDER", "TI2DAC_MODEL")


def model_choice_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "ai_models.json"


def read_model_choice(state_dir: str | Path) -> dict:
    """{"provider": ..., "models": {provider: {stage: model}}, "updated_by", "updated_at"}; {} if never set."""
    try:
        data = json.loads(model_choice_path(state_dir).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_model_choice(state_dir: str | Path, provider: str, models: dict[str, str], actor: str) -> dict:
    data = read_model_choice(state_dir)
    data["provider"] = provider
    data.setdefault("models", {})[provider] = {k: models[k] for k in STAGES}
    data.update(updated_by=actor, updated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    p = model_choice_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(p)
    return data


def apply_model_choice(s: Settings, choice: dict) -> None:
    """The saved choice overrides ti2dac.yaml (environment variables still override both)."""
    if choice.get("provider") in PROVIDERS:
        s.ai.provider = choice["provider"]
    models = (choice.get("models") or {}).get(s.ai.provider) or {}
    for stage in STAGES:
        if isinstance(models.get(stage), str) and models[stage]:
            getattr(s.ai, stage).model = models[stage]


def apply_ai_env(s: Settings) -> None:
    """AI environment overrides and provider/model consistency. Idempotent, so it can be re-applied after a change."""
    env = os.environ
    if env.get("TI2DAC_NO_AI", "").lower() in ("1", "true", "yes"):
        s.ai.enabled = False
    if "TI2DAC_PROVIDER" in env:
        s.ai.provider = env["TI2DAC_PROVIDER"].lower()
    if s.ai.provider not in PROVIDERS:
        raise ValueError(f"ai.provider must be 'anthropic' or 'gemini', not {s.ai.provider!r}")
    if s.ai.failover_provider not in ("", *PROVIDERS):
        raise ValueError(f"ai.failover_provider must be '', 'anthropic' or 'gemini', not {s.ai.failover_provider!r}")
    for stage in STAGES:   # a stage still naming the other provider's model gets this provider's default
        st = getattr(s.ai, stage)
        if s.ai.provider == "gemini" and st.model.startswith("claude"):
            st.model = s.ai.gemini_model
        elif s.ai.provider == "anthropic" and not st.model.startswith("claude"):
            st.model = StageConfig().model
    if "TI2DAC_MODEL" in env:   # one switch to move every stage to another model
        for stage in STAGES:
            getattr(s.ai, stage).model = env["TI2DAC_MODEL"]
