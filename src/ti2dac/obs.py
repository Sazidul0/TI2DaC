"""Operational logging: JSON lines for files, stderr and syslog, so a SIEM can ingest ti2dac's own events.

Events carry metadata only: ids, counts, models, tokens, durations, outcomes. Never report text, prompts,
model output, redaction maps or keys; the formatter also scrubs anything shaped like an API key.

    obs.event("ai.call", stage="generate", model="claude-opus-5-5", outcome="ok", ...)

Each line has ts, level, event, component (cli/web), host, pid and, when set, run_id / job_id / request_id.
"""
from __future__ import annotations

import contextvars
import json
import logging
import logging.handlers
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("ti2dac.events")

run_id: contextvars.ContextVar[str] = contextvars.ContextVar("run_id", default="")
job_id: contextvars.ContextVar[str] = contextvars.ContextVar("job_id", default="")
request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")
_component = "cli"
_HOST = socket.gethostname()
_SECRET = re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}|AIza[0-9A-Za-z_\-]{20,}|(?i:basic|bearer)\s+[A-Za-z0-9+/=._\-]{12,}")
_OWN = {"name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info", "exc_text",
        "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime"}


def scrub(text: str) -> str:
    return _SECRET.sub("[SECRET]", text)


def event(name: str, level: int = logging.INFO, **fields) -> None:
    """One structured event. Field values must be metadata (see module docstring)."""
    log.log(level, name, extra={"event": name, **fields})


def in_context(fn):
    """Wrap `fn` so worker threads (ThreadPoolExecutor) see the caller's run/job/request ids."""
    ctx = contextvars.copy_context()
    return lambda *a, **kw: ctx.copy().run(fn, *a, **kw)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {"ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
               "level": record.levelname.lower(), "event": getattr(record, "event", "log"),
               "component": _component, "host": _HOST, "pid": record.process}
        for var in (run_id, job_id, request_id):
            if var.get():
                out[var.name] = var.get()
        if out["event"] == "log":
            out["logger"], out["message"] = record.name, record.getMessage()
        out.update({k: v for k, v in record.__dict__.items() if k not in _OWN and k != "event"})
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)[-2000:]
        return scrub(json.dumps(out, ensure_ascii=False, default=str))


class _HumanFormatter(logging.Formatter):
    """Terminal output for the CLI: the old format, with event fields appended."""

    def format(self, record: logging.LogRecord) -> str:
        extra = {k: v for k, v in record.__dict__.items() if k not in _OWN and k != "event"}
        tail = " " + " ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""
        return scrub(f"{record.levelname} {record.name}: {record.getMessage()}{tail}")


def _syslog_handler(address: str) -> logging.Handler:
    """'udp://host:514', 'tcp://host:514' or a local socket path such as /dev/log."""
    if address.startswith(("udp://", "tcp://")):
        host, _, port = address[6:].rpartition(":")
        kind = socket.SOCK_STREAM if address.startswith("tcp") else socket.SOCK_DGRAM
        h = logging.handlers.SysLogHandler((host, int(port or 514)), socktype=kind)
    else:
        h = logging.handlers.SysLogHandler(address)
    h.ident = "ti2dac: "
    return h


def setup(settings, component: str = "cli", verbose: bool = False) -> Path | None:
    """Configure logging once per process. Returns the log file path (None when file logging is off).

    The CLI and the web server write separate files: rotation is not safe across processes sharing one file."""
    global _component
    _component = component
    cfg = settings.log
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_ti2dac", False):
            root.removeHandler(h)
            h.close()
    root.setLevel(logging.DEBUG if verbose else getattr(logging, cfg.level.upper(), logging.INFO))
    for noisy in ("httpx", "httpx2", "httpcore", "anthropic", "google_genai", "urllib3"):   # one line per HTTP call
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbose else logging.WARNING)

    def add(h: logging.Handler, level: int, fmt: logging.Formatter) -> None:
        h.setLevel(level)
        h.setFormatter(fmt)
        h._ti2dac = True   # type: ignore[attr-defined]
        root.addHandler(h)

    if cfg.json_stderr:
        add(logging.StreamHandler(), logging.DEBUG if verbose else logging.INFO, JsonFormatter())
    else:   # the terminal keeps showing only warnings, as before
        add(logging.StreamHandler(), logging.DEBUG if verbose else logging.WARNING, _HumanFormatter())
    path = None
    if cfg.max_mb > 0:
        d = Path(cfg.dir or Path(settings.state_dir) / "logs")
        try:
            d.mkdir(parents=True, exist_ok=True)
            path = d / f"ti2dac-{component}.jsonl"
            fh = logging.handlers.RotatingFileHandler(path, maxBytes=cfg.max_mb * 1024 * 1024,
                                                      backupCount=max(cfg.backups, 1), encoding="utf-8")
            add(fh, logging.DEBUG, JsonFormatter())
            os.chmod(path, 0o600)
        except OSError as e:   # read-only state dir: keep running, say why
            logging.getLogger(__name__).warning("file logging disabled: %s", e)
            path = None
    if cfg.syslog:
        try:
            add(_syslog_handler(cfg.syslog), logging.INFO, JsonFormatter())
        except (OSError, ValueError) as e:
            logging.getLogger(__name__).warning("syslog forwarding to %s disabled: %s", cfg.syslog, e)
    return path
