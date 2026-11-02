"""AI provider health: limit detection, circuit breaker and request counting.

Shared by the CLI and the web UI through <state_dir>/ai_status.json, so that once a provider says
"quota exhausted" (or our own daily cap is reached) NO process sends further requests until the reset
time. Hammering a provider after it refused is wasteful and can look like abuse to the provider.

States per provider:
  ok               last call succeeded
  rate_limited     short-term limit (per-minute); calls resume after retry_at
  quota_exhausted  daily/monthly quota, credit or spend limit; calls blocked until retry_at (or manual reset)
  daily_cap        our own `ai.daily_request_limit` reached; resets at local midnight
  auth_error       key missing/invalid; blocked until reset
  refused          the model declined a request (informational; does not block)
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

BLOCKING = {"rate_limited", "quota_exhausted", "daily_cap", "auth_error"}
DAILY_COUNTERS = ("requests_today", "input_tokens_today", "output_tokens_today", "cache_read_tokens_today", "cost_today_usd")
TOTAL_COUNTERS = ("input_tokens_total", "output_tokens_total", "cost_total_usd")
_LOCK = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "ai_status.json"


def load(state_dir: str | Path) -> dict:
    try:
        return json.loads(_path(state_dir).read_text())
    except (OSError, ValueError):
        return {}


def _save(state_dir: str | Path, data: dict) -> None:
    p = _path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(p)


def provider_status(state_dir: str | Path, provider: str) -> dict:
    s = load(state_dir).get(provider, {})
    today = datetime.now().date().isoformat()
    if s.get("day") != today:
        s = {**s, "day": today, **{k: 0 for k in DAILY_COUNTERS}}
        if s.get("state") == "daily_cap":
            s["state"] = "ok"
    return s


def update(state_dir: str | Path, provider: str, **fields) -> dict:
    with _LOCK:
        data = load(state_dir)
        cur = provider_status(state_dir, provider) if provider in data else {
            "day": datetime.now().date().isoformat(), "requests_today": 0}
        cur.update(fields)
        cur["updated_at"] = _now().isoformat(timespec="seconds")
        data[provider] = cur
        _save(state_dir, data)
        return cur


def count_request(state_dir: str | Path, provider: str) -> int:
    with _LOCK:
        data = load(state_dir)
        cur = provider_status(state_dir, provider)
        cur["requests_today"] = int(cur.get("requests_today", 0)) + 1
        data[provider] = cur
        _save(state_dir, data)
        return cur["requests_today"]


def add_usage(state_dir: str | Path, provider: str, input_tokens: int, output_tokens: int,
              cache_read_tokens: int, cost_usd: float) -> None:
    """Token accounting per provider: today (resets at local midnight) and since the state dir was created."""
    with _LOCK:
        data = load(state_dir)
        cur = provider_status(state_dir, provider)
        for key, val in (("input_tokens", input_tokens), ("output_tokens", output_tokens)):
            cur[f"{key}_today"] = int(cur.get(f"{key}_today", 0)) + val
            cur[f"{key}_total"] = int(cur.get(f"{key}_total", 0)) + val
        cur["cache_read_tokens_today"] = int(cur.get("cache_read_tokens_today", 0)) + cache_read_tokens
        cur["cost_today_usd"] = round(float(cur.get("cost_today_usd", 0)) + cost_usd, 4)
        cur["cost_total_usd"] = round(float(cur.get("cost_total_usd", 0)) + cost_usd, 4)
        data[provider] = cur
        _save(state_dir, data)


def record_ok(state_dir: str | Path, provider: str) -> None:
    update(state_dir, provider, state="ok", message="", retry_at="", last_success=_now().isoformat(timespec="seconds"))


def record_block(state_dir: str | Path, provider: str, state: str, message: str, retry_after_s: float | None) -> None:
    retry_at = (_now() + timedelta(seconds=retry_after_s)).isoformat(timespec="seconds") if retry_after_s else ""
    update(state_dir, provider, state=state, message=message[:500], retry_at=retry_at)


def reset(state_dir: str | Path, provider: str | None = None) -> None:
    with _LOCK:
        data = load(state_dir)
        for name in ([provider] if provider else list(data)):
            if name in data:
                data[name].update(state="ok", message="", retry_at="")
        _save(state_dir, data)


def block_reason(state_dir: str | Path, provider: str, daily_limit: int = 0) -> str:
    """Why calls to `provider` are blocked right now ('' = allowed). Never contacts the provider."""
    s = provider_status(state_dir, provider)
    state = s.get("state", "ok")
    if daily_limit and int(s.get("requests_today", 0)) >= daily_limit:
        return (f"{provider}: daily request cap reached ({s.get('requests_today')}/{daily_limit}, "
                "ai.daily_request_limit). Resets at local midnight, or raise the cap.")
    if state not in BLOCKING:
        return ""
    retry_at = s.get("retry_at", "")
    if retry_at:
        try:
            if datetime.fromisoformat(retry_at) <= _now():
                return ""                       # the provider's own reset time has passed
        except ValueError:
            pass
    elif state == "rate_limited":
        return ""
    when = f" Retry after {retry_at} (UTC)." if retry_at else " Fix the cause, then reset with `ti2dac ai-status --reset` or the AI page."
    return f"{provider}: {state.replace('_', ' ')}. {s.get('message', '')}".strip() + when


def human_wait(retry_at: str) -> str:
    try:
        secs = (datetime.fromisoformat(retry_at) - _now()).total_seconds()
    except (ValueError, TypeError):
        return ""
    if secs <= 0:
        return "now"
    h, m = int(secs // 3600), int(secs % 3600 // 60)
    return f"{h}h {m}m" if h else f"{m}m"


def key_status(provider: str) -> str:
    """Where credentials would come from (never the key itself)."""
    if provider == "gemini":
        for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            if os.environ.get(var):
                return f"{var} is set"
        return "not configured"
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        if os.environ.get(var):
            return f"{var} is set"
    if os.environ.get("ANTHROPIC_PROFILE") or (Path.home() / ".config" / "anthropic").is_dir():
        return "`ant auth login` profile found"
    return "not configured"
