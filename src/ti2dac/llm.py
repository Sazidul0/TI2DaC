"""Claude API wrapper: structured output, refusal fallback, provider failover, response cache, token accounting."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from pathlib import Path
from typing import TypeVar

import anthropic
from anthropic import transform_schema
from pydantic import BaseModel, ValidationError

from . import aistatus, obs, redact
from .config import Settings, StageConfig
from .models import Usage
from .prompts import PROMPT_VERSION

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

# Models that accept the server-side `fallbacks: "default"` parameter.
FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"

# USD per 1M tokens: (input, output, cache_read), Anthropic list prices. Cache writes (5-minute TTL) bill at
# 1.25x input. Haiku 5.5's price is for prompts up to 100K tokens (ours are far smaller). Add or override
# models (e.g. a paid Gemini tier) with ai.prices; unknown models are reported as unpriced. Estimates only.
PRICES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20),
    "claude-sonnet-5-5": (2.0, 10.0, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-1": (10.0, 50.0, 0.25),
    "claude-opus-5": (5.0, 25.0, 0.50),
    "claude-opus-4-8": (5.0, 25.0, 0.50),     # a server-side fallback target
}
# A refusal before any output is billed only in these categories; any other (or null) category is free.
_BILLED_PRE_OUTPUT = {"bio", "frontier_llm", "reasoning_extraction"}
_TOKEN_KEYS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")


class LLMError(Exception):
    pass


class LLMRefusal(LLMError):
    pass


class LLMOutage(LLMError):
    """Provider unreachable or failing server-side after retries (connection error, timeout, 5xx/529)."""


class LLMLimitError(LLMError):
    """Provider limit, quota or credential problem: AI calls are paused (see aistatus)."""

    def __init__(self, message: str, state: str = "blocked"):
        super().__init__(message)
        self.state = state


_QUOTA_HINTS = ("per day", "perday", "free_tier", "quota", "credit balance", "spend limit", "usage limit",
                "billing", "exceeded your current")


# (model, schema) pairs Anthropic refused to compile into an output grammar ("compiled grammar is too large").
# The limit is not published; such schemas are asked for as plain JSON and validated here instead.
_NO_GRAMMAR: set[tuple[str, str]] = set()


def _grammar_too_large(message: str) -> bool:
    m = (message or "").lower()
    return "grammar" in m and ("too large" in m or "too complex" in m)


def _json_instruction(schema: type[BaseModel]) -> str:
    return ("\n\nReply with exactly one JSON object that conforms to this JSON Schema, and nothing else "
            "(no prose, no code fences):\n" + json.dumps(schema.model_json_schema(), separators=(",", ":")))


def _json_object(text: str) -> str:
    """The JSON object in a reply that was not grammar-constrained (models sometimes add fences or a preamble)."""
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if 0 <= start < end else text


def _is_quota(message: str) -> bool:
    """Long-lived limit (daily quota, credit, spend cap) as opposed to a per-minute rate limit."""
    m = (message or "").lower()
    if ("per minute" in m or "perminute" in m) and "per day" not in m and "perday" not in m:
        return False
    return any(h in m for h in _QUOTA_HINTS)


def _quota_summary(message: str) -> str:
    """Google's quota errors are several paragraphs; keep the limit and the model it applies to."""
    m = re.search(r"limit: (\d+), model: ([\w.-]+)", message or "")
    if not m:
        return " ".join((message or "").split())[:300]
    period = " per day" if "per day" in message.lower() else " per minute" if "per minute" in message.lower() else ""
    tier = " (free tier)" if "free_tier" in message.lower() or "free tier" in message.lower() else ""
    return (f"Google quota of {m[1]} requests{period} for {m[2]} used up{tier}. "
            "Each Gemini model has its own quota; another model or a paid key can continue.")


def _is_transport_error(e: Exception) -> bool:
    """Network-level failure from an HTTP stack (DNS, TLS, reset, timeout), not an API answer."""
    return isinstance(e, (OSError, TimeoutError)) or type(e).__module__.split(".")[0] in ("httpx", "httpcore", "httpx2")


def _stream_error_type(e) -> str:
    """Error type of an SSE `error` event: it arrives after the 200 response, so the status code says nothing."""
    body = getattr(e, "body", None)
    err = body.get("error") if isinstance(body, dict) else None
    return str(err.get("type", "")) if isinstance(err, dict) else ""


def _header_seconds(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _retry_delay(err) -> int | None:
    """Seconds from a Gemini 429 RetryInfo detail ('retryDelay': '37s'), if present."""
    m = re.search(r"retryDelay['\"]?\s*:\s*['\"](\d+)(?:\.\d+)?s", str(getattr(err, "details", "")) + str(err))
    return min(int(m.group(1)) + 2, 120) if m else None


def _schema_errors(e: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, x['loc'])) or '(root)'}: {x['msg']}" for x in e.errors()[:8])[:1500]


def price(model: str, overrides: dict | None = None) -> tuple[float, float, float] | None:
    p = (overrides or {}).get(model) or PRICES.get(model)
    return (float(p[0]), float(p[1]), float(p[2])) if p else None


def attempt_cost(a: dict, p: tuple[float, float, float]) -> float:
    return (a["input_tokens"] * p[0] + a["output_tokens"] * p[1] + a["cache_read_tokens"] * p[2]
            + a["cache_write_tokens"] * p[0] * 1.25) / 1e6


def estimate_cost(usage: Usage, overrides: dict | None = None) -> float:
    """USD estimate. Stages carry their cost priced per call at the model that answered; run records written
    before that (no cost_usd) are priced at the stage's model. Unpriced models add nothing (see unpriced_models)."""
    return round(sum(float(s["cost_usd"]) if "cost_usd" in s else _legacy_stage_cost(s, overrides)
                     for s in usage.by_stage.values()), 4)


def _legacy_stage_cost(stage: dict, overrides: dict | None) -> float:
    p = price(str(stage.get("model_price_key", "")), overrides)
    return attempt_cost({k: int(stage.get(k, 0)) for k in _TOKEN_KEYS}, p) if p else 0.0


def anthropic_attempts(msg, requested: str) -> tuple[list[dict], bool]:
    """Billable attempts in one Messages response, and whether a fallback model served it.

    With server-side fallback, `usage.iterations` holds one entry per model that ran (top-level usage covers
    only the attempt that answered), each billed at its own model's rates. A hop that declined before any
    output is billed only in _BILLED_PRE_OUTPUT categories; the `fallback` content blocks carry each
    hop's category, in order."""
    def attempt(u, model, billed: bool) -> dict:
        return {"model": model or requested, "input_tokens": u.input_tokens or 0, "output_tokens": u.output_tokens or 0,
                "cache_read_tokens": u.cache_read_input_tokens or 0,
                "cache_write_tokens": u.cache_creation_input_tokens or 0, "billed": billed}

    def billed(u, category) -> bool:
        return (u.output_tokens or 0) > 0 or category in _BILLED_PRE_OUTPUT

    final_cat = getattr(getattr(msg, "stop_details", None), "category", None)
    refused = msg.stop_reason == "refusal"
    its = [i for i in (getattr(msg.usage, "iterations", None) or []) if i.type in ("message", "fallback_message")]
    if not its:
        return [attempt(msg.usage, getattr(msg, "model", None), not refused or billed(msg.usage, final_cat))], False
    triggers = [getattr(getattr(b, "trigger", None), "category", None) for b in msg.content if b.type == "fallback"]
    out = []
    for n, it in enumerate(its):
        if n == len(its) - 1:
            ok = not refused or billed(it, final_cat)
        else:
            ok = billed(it, triggers.pop(0) if triggers else None)
        out.append(attempt(it, getattr(it, "model", None), ok))
    return out, any(i.type == "fallback_message" for i in its)


def verify_key(provider: str, key: str) -> tuple[bool, str]:
    """Check a key by listing models: no tokens and no generation quota are used. Returns (ok, message)."""
    if provider == "gemini":
        try:
            from google import genai
            from google.genai import errors as gerrors
            from google.genai import types
        except ImportError:
            return False, "the google-genai package is not installed: pip install 'ti2dac[gemini]'"
        try:
            client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=15_000))   # must outlive the pager
            next(iter(client.models.list(config={"page_size": 1})), None)
            return True, "Google AI Studio accepted the key"
        except gerrors.APIError as e:
            return False, f"Google rejected the key ({e.code}): {(e.message or '')[:200]}"
        except Exception as e:   # DNS, proxy, TLS: the key may still be fine
            return False, f"could not reach Google AI Studio: {type(e).__name__}: {str(e)[:200]}"
    try:
        anthropic.Anthropic(api_key=key, max_retries=0, timeout=15).models.list(limit=1)
        return True, "Anthropic accepted the key"
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as e:
        return False, f"Anthropic rejected the key ({e.status_code})"
    except anthropic.APIConnectionError as e:
        return False, f"could not reach Anthropic: {str(e)[:200]}"
    except anthropic.APIStatusError as e:
        return False, f"Anthropic returned {e.status_code}: {str(e.message)[:200]}"


class LLM:
    def __init__(self, settings: Settings, usage: Usage | None = None, tlp: str | None = None):
        self.settings = settings
        self.usage = usage or Usage()
        # Effective TLP of the report being processed: failover only goes to a provider allowed to receive it.
        self.tlp = tlp
        self._lock = threading.Lock()
        self._calls = threading.local()   # per-thread attempts of the call in flight, for its ai.call event
        self._client: anthropic.Anthropic | None = None
        self._gclient = None
        self._gone: dict[str, str] = {}    # model -> why the provider said it does not exist for this key
        self.cache_dir = Path(settings.cache_dir) / "llm"

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            # Credentials come from the environment (ANTHROPIC_API_KEY or an `ant auth login` profile).
            self._client = anthropic.Anthropic(max_retries=2, timeout=600)
        return self._client

    # ------------------------------------------------------------------ cache
    def _key(self, cfg: StageConfig, system: str, user: str, schema: type[BaseModel]) -> str:
        blob = json.dumps([PROMPT_VERSION, cfg.model, cfg.effort, system, user, schema.model_json_schema()],
                          sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _cache_get(self, key: str) -> str | None:
        p = self.cache_dir / key[:2] / f"{key}.json"
        return p.read_text() if self.settings.ai.response_cache and p.is_file() else None

    def _cache_put(self, key: str, text: str) -> None:
        if not self.settings.ai.response_cache:
            return
        p = self.cache_dir / key[:2] / f"{key}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    # ------------------------------------------------------------------ accounting
    def _stage(self, stage: str) -> dict:
        return self.usage.by_stage.setdefault(stage, {"calls": 0, "cached_calls": 0, "input_tokens": 0, "output_tokens": 0,
                                                      "cache_read_tokens": 0, "cache_write_tokens": 0, "cost_usd": 0.0})

    def _record_cached(self, stage: str, cfg: StageConfig) -> None:
        with self._lock:
            s = self._stage(stage)
            s.setdefault("model_price_key", cfg.model)
            s["cached_calls"] += 1
            self.usage.cached_calls += 1

    def _record(self, stage: str, provider: str, attempts: list[dict], served_by_fallback: bool = False) -> None:
        """One API call; `attempts` are the model runs it billed (several when a fallback model took over)."""
        cost, unpriced = 0.0, set()
        with self._lock:
            s = self._stage(stage)
            if "cost_usd" not in s:   # stage from a run recorded before per-call pricing
                s["cost_usd"] = round(_legacy_stage_cost(s, self.settings.ai.prices), 6)
            s["calls"] += 1
            self.usage.calls += 1
            for a in attempts:
                for k in _TOKEN_KEYS:
                    s[k] += a[k]
                    setattr(self.usage, k, getattr(self.usage, k) + a[k])
                p = price(a["model"], self.settings.ai.prices)
                if p is None:
                    unpriced.add(a["model"])
                elif a["billed"]:
                    cost += attempt_cost(a, p)
            s["model_price_key"] = attempts[-1]["model"]
            s["cost_usd"] = round(float(s["cost_usd"]) + cost, 6)
            if served_by_fallback:
                s["fallback_calls"] = int(s.get("fallback_calls", 0)) + 1
                self.usage.fallback_calls += 1
            if unpriced:
                self.usage.unpriced_models = sorted(set(self.usage.unpriced_models) | unpriced)
            self.usage.estimated_cost_usd = estimate_cost(self.usage, self.settings.ai.prices)
        self._calls.attempts = getattr(self._calls, "attempts", []) + attempts
        self._calls.cost = getattr(self._calls, "cost", 0.0) + cost
        self._calls.fallback = getattr(self._calls, "fallback", False) or served_by_fallback
        tok = {k: sum(a[k] for a in attempts) for k in _TOKEN_KEYS}
        aistatus.add_usage(self.settings.state_dir, provider, tok["input_tokens"] + tok["cache_write_tokens"],
                           tok["output_tokens"], tok["cache_read_tokens"], cost)

    # ------------------------------------------------------------------ call
    def structured(self, stage: str, system: str, user: str, schema: type[T]) -> T:
        cfg: StageConfig = getattr(self.settings.ai, stage)
        key = self._key(cfg, system, user, schema)
        hit = self._cache_get(key)
        if hit is not None:
            try:
                obj = schema.model_validate_json(hit)
                self._record_cached(stage, cfg)
                obs.event("ai.call", stage=stage, provider=self.settings.ai.provider, model=cfg.model, outcome="cached",
                          latency_ms=0, cost_usd=0.0)
                return obj
            except ValidationError:
                pass   # schema changed since caching; fall through to a fresh call

        text, used = self._call(stage, cfg, system, user, schema)
        try:
            obj = schema.model_validate_json(text)
        except ValidationError as e:
            # One corrective re-ask that tells the model what failed; a second failure is reported, not looped.
            obs.event("ai.schema_retry", logging.WARNING, stage=stage, model=used.model, errors=_schema_errors(e)[:500])
            with self._lock:
                self.usage.schema_retries += 1
            fix = (f"{user}\n\n<previous_answer_rejected>\nYour previous answer did not validate against the required "
                   f"JSON schema: {_schema_errors(e)}\nAnswer again with JSON that matches the schema exactly.\n"
                   "</previous_answer_rejected>")
            text, used = self._call(stage, cfg, system, fix, schema)
            try:
                obj = schema.model_validate_json(text)
            except ValidationError as e2:
                raise LLMError(f"{stage}: response did not match the schema after one corrective retry: "
                               f"{_schema_errors(e2)}") from e2
        # Cached under the model that answered: a failover answer is not replayed as the primary model's.
        self._cache_put(key if used is cfg else self._key(used, system, user, schema), text)
        return obj

    def _call(self, stage: str, cfg: StageConfig, system: str, user: str,
              schema: type[BaseModel]) -> tuple[str, StageConfig]:
        """Primary provider; on an outage, the configured failover provider. Returns (text, config used)."""
        provider = self.settings.ai.provider
        try:
            return self._call_provider(provider, stage, cfg, system, user, schema), cfg
        except LLMOutage as e:
            alt = self._failover(stage)
            if alt is None:
                raise
            fprovider, fcfg = alt
            obs.event("ai.failover", logging.WARNING, stage=stage, from_provider=provider, to_provider=fprovider,
                      to_model=fcfg.model, reason=str(e)[:300])
            text = self._call_provider(fprovider, stage, fcfg, system, user, schema)
            with self._lock:
                self.usage.failover_calls += 1
            return text, fcfg

    def _call_provider(self, provider: str, stage: str, cfg: StageConfig, system: str, user: str,
                       schema: type[BaseModel]) -> str:
        self._calls.attempts, self._calls.cost, self._calls.fallback, self._calls.requests = [], 0.0, False, 0
        t0, outcome = time.monotonic(), "ok"
        try:
            self._gate(stage, provider)
            if cfg.model in self._gone:
                raise LLMError(f"{stage}: {cfg.model} is not available to this key, no request sent "
                               f"(earlier answer: {self._gone[cfg.model]}). Choose another model.")
            if provider == "gemini":
                text = self._call_gemini(stage, cfg, system, user, schema)
            else:
                text = self._call_anthropic(stage, cfg, system, user, schema)
            aistatus.record_ok(self.settings.state_dir, provider)
            return text
        except LLMLimitError as e:
            outcome = "paused" if e.state == "blocked" else e.state   # "blocked": refused locally, nothing sent
            raise
        except LLMRefusal:
            outcome = "refused"
            raise
        except LLMOutage:
            outcome = "outage"
            raise
        except LLMError as e:
            outcome = "truncated" if "truncated" in str(e) else "error"
            raise
        except Exception:
            outcome = "crash"
            raise
        finally:
            self._call_event(stage, provider, cfg, outcome, time.monotonic() - t0)

    def _call_event(self, stage: str, provider: str, cfg: StageConfig, outcome: str, seconds: float) -> None:
        """One ai.call event per provider call: the AI request and token/cost metric stream."""
        attempts = getattr(self._calls, "attempts", [])
        obs.event("ai.call", logging.INFO if outcome == "ok" else logging.WARNING, stage=stage, provider=provider,
                  model=cfg.model, served_by=attempts[-1]["model"] if attempts else "", outcome=outcome,
                  latency_ms=round(seconds * 1000), attempts=len(attempts), requests=getattr(self._calls, "requests", 0), fallback=getattr(self._calls, "fallback", False),
                  cost_usd=round(getattr(self._calls, "cost", 0.0), 6),
                  **{k: sum(a[k] for a in attempts) for k in _TOKEN_KEYS})

    def _failover(self, stage: str) -> tuple[str, StageConfig] | None:
        ai = self.settings.ai
        fp = ai.failover_provider
        if not fp or fp == ai.provider:
            return None
        if not self.tlp or not redact.tlp_allowed(self.tlp, ai.allowed_tlp.get(fp, [])):
            log.warning("%s: no failover to %s: TLP:%s may not be sent there (ai.allowed_tlp)",
                        stage, fp, (self.tlp or "unknown").upper())
            return None
        cfg: StageConfig = getattr(ai, stage)
        model = ai.failover_model or (ai.gemini_model if fp == "gemini" else StageConfig().model)
        return fp, StageConfig(model=model, effort=cfg.effort, max_tokens=cfg.max_tokens)

    # ------------------------------------------------------------------ limits
    def _gate(self, stage: str, provider: str | None = None) -> None:
        """Refuse locally (no request sent) while the provider is limited or our daily cap is reached."""
        reason = aistatus.block_reason(self.settings.state_dir, provider or self.settings.ai.provider,
                                       self.settings.ai.daily_request_limit)
        if reason:
            raise LLMLimitError(f"{stage}: AI paused, no request sent. {reason}")

    def _sent(self, provider: str) -> None:
        aistatus.count_request(self.settings.state_dir, provider)
        self._calls.requests = getattr(self._calls, "requests", 0) + 1   # HTTP requests, retries included

    def _block(self, stage: str, provider: str, state: str, message: str, retry_after_s: float | None) -> LLMLimitError:
        aistatus.record_block(self.settings.state_dir, provider, state, message, retry_after_s)
        log.warning("%s: %s (%s); further AI calls paused", stage, state, message[:160])
        return LLMLimitError(f"{stage}: {provider} {state.replace('_', ' ')}: {message[:300]}", state=state)

    def _outage(self, stage: str, provider: str, message: str) -> LLMOutage:
        aistatus.update(self.settings.state_dir, provider, state="unavailable", message=f"{stage}: {message[:300]}")
        return LLMOutage(f"{stage}: {message}")

    # ------------------------------------------------------------------ providers
    def _call_anthropic(self, stage: str, cfg: StageConfig, system: str, user: str, schema: type[BaseModel]) -> str:
        constrained = (cfg.model, schema.__name__) not in _NO_GRAMMAR
        kwargs: dict = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            # Frozen system prompt marked cacheable: repeated stage-2 calls in a run reuse it.
            "system": [{"type": "text", "text": system if constrained else system + _json_instruction(schema),
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": transform_schema(schema)}} if constrained else {},
        }
        if cfg.effort:
            kwargs["output_config"]["effort"] = cfg.effort
        if not kwargs["output_config"]:
            del kwargs["output_config"]
        if self.settings.ai.server_side_fallback and cfg.model in FALLBACK_MODELS:
            kwargs["betas"] = [_FALLBACK_BETA]
            kwargs["fallbacks"] = "default"

        self._sent("anthropic")
        try:
            with self.client.beta.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()
        except anthropic.AuthenticationError as e:
            raise self._block(stage, "anthropic", "auth_error", "Anthropic rejected the API key (ANTHROPIC_API_KEY / `ant auth login`)", None) from e
        except anthropic.PermissionDeniedError as e:
            raise self._block(stage, "anthropic", "auth_error", f"permission denied: {e.message}", None) from e
        except TypeError as e:   # the SDK raises TypeError when no credentials are configured at all
            if "authentication" not in str(e).lower():
                raise
            raise self._block(stage, "anthropic", "auth_error", "No Anthropic credentials found: set ANTHROPIC_API_KEY (or run "
                              "`ant auth login`), use TI2DAC_PROVIDER=gemini with GEMINI_API_KEY, or run with --no-ai", None) from e
        except anthropic.RateLimitError as e:
            # The SDK has already retried (max_retries, honouring retry-after); stop here.
            retry_after = _header_seconds(e.response.headers.get("retry-after")) if e.response is not None else None
            state = "quota_exhausted" if _is_quota(e.message) else "rate_limited"
            raise self._block(stage, "anthropic", state, e.message, retry_after or (None if state == "quota_exhausted" else 60)) from e
        except anthropic.BadRequestError as e:
            if _is_quota(e.message):   # e.g. "credit balance is too low", workspace spend limit reached
                raise self._block(stage, "anthropic", "quota_exhausted", e.message, None) from e
            if constrained and _grammar_too_large(e.message):   # rejected before any output: nothing billed
                _NO_GRAMMAR.add((cfg.model, schema.__name__))
                obs.event("ai.unconstrained", logging.WARNING, stage=stage, model=cfg.model, schema=schema.__name__,
                          reason=e.message[:200])
                return self._call_anthropic(stage, cfg, system, user, schema)
            raise LLMError(f"{stage}: bad request: {e.message}") from e
        except anthropic.NotFoundError as e:
            self._gone[cfg.model] = e.message[:200]
            raise LLMError(f"{stage}: model {cfg.model} not found: {e.message}") from e
        except anthropic.APIStatusError as e:
            if e.status_code >= 500 or _stream_error_type(e) in ("overloaded_error", "api_error"):
                # 500/529 overloaded after the SDK's own retries, or the same reported mid-stream
                raise self._outage(stage, "anthropic", f"Anthropic API unavailable ({e.status_code}): {e.message}") from e
            raise LLMError(f"{stage}: API error {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:   # includes APITimeoutError
            raise self._outage(stage, "anthropic", f"cannot reach the Anthropic API: {e}") from e
        except Exception as e:
            # The SDK only wraps errors of the initial request; a connection dropped mid-stream surfaces raw.
            if not _is_transport_error(e):
                raise
            raise self._outage(stage, "anthropic", f"connection lost mid-response: {type(e).__name__}: {str(e)[:200]}") from e

        attempts, by_fallback = anthropic_attempts(msg, cfg.model)
        self._record(stage, "anthropic", attempts, by_fallback)
        if by_fallback:
            log.info("%s: declined by %s, answered by fallback model %s", stage, cfg.model, attempts[-1]["model"])
        if msg.stop_reason == "refusal":
            details = msg.stop_details
            cat = getattr(details, "category", None) if details else None
            aistatus.update(self.settings.state_dir, "anthropic", state="refused", message=f"{stage}: category={cat}")
            raise LLMRefusal(f"{stage}: model declined (category={cat}). Security-research orgs can apply to "
                             "Anthropic's Cyber Verification Program; otherwise rephrase or review the report.")
        if msg.stop_reason == "max_tokens":
            raise LLMError(f"{stage}: output truncated at max_tokens={cfg.max_tokens}; raise ai.{stage}.max_tokens")
        log.debug("%s: request %s, usage %s", stage, getattr(msg, "_request_id", "?"), msg.usage)
        text = next((b.text for b in msg.content if b.type == "text"), "")
        return text if constrained else _json_object(text)

    def _call_gemini(self, stage: str, cfg: StageConfig, system: str, user: str, schema: type[BaseModel]) -> str:
        try:
            from google import genai
            from google.genai import errors as gerrors
            from google.genai import types
        except ImportError as e:
            raise LLMError("provider 'gemini' needs the google-genai package: pip install 'ti2dac[gemini]'") from e
        if self._gclient is None:
            # Key from GEMINI_API_KEY / GOOGLE_API_KEY. Generous timeout: free-tier latency can be minutes.
            try:
                self._gclient = genai.Client(http_options=types.HttpOptions(timeout=600_000, retry_options=None))
            except ValueError as e:   # no key in the environment
                raise self._block(stage, "gemini", "auth_error", f"no Gemini API key (GEMINI_API_KEY): {e}", None) from e
        level = {"low": "LOW", "medium": "MEDIUM"}.get(cfg.effort, "HIGH") if cfg.effort else None
        max_tokens = cfg.max_tokens
        for truncation_retry in range(2):
            resp = self._gemini_request(stage, cfg, system, user, schema, level, max_tokens, types, gerrors)
            cand = (resp.candidates or [None])[0]
            reason = getattr(getattr(cand, "finish_reason", None), "name", "") if cand else "NO_CANDIDATE"
            if reason != "MAX_TOKENS" or truncation_retry:
                break
            # Gemini counts thinking tokens against max_output_tokens: retry once with more room, less thinking.
            log.warning("%s: Gemini output truncated (thoughts=%s); retrying with more tokens and lower thinking",
                        stage, getattr(resp.usage_metadata, "thoughts_token_count", "?"))
            level = {"HIGH": "MEDIUM", "MEDIUM": "LOW"}.get(level or "", "LOW")
            max_tokens = min(max_tokens * 2, 65536)
        if reason in ("SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "NO_CANDIDATE") or (
                resp.prompt_feedback and resp.prompt_feedback.block_reason):
            aistatus.update(self.settings.state_dir, "gemini", state="refused", message=f"{stage}: {reason}")
            raise LLMRefusal(f"{stage}: Gemini blocked the response (finish_reason={reason or resp.prompt_feedback.block_reason})")
        if reason == "MAX_TOKENS":
            raise LLMError(f"{stage}: output truncated at max_tokens={max_tokens}; raise ai.{stage}.max_tokens")
        return resp.text or ""

    def _gemini_request(self, stage, cfg, system, user, schema, level, max_tokens, types, gerrors):
        config = types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            response_json_schema=schema.model_json_schema(),
            max_output_tokens=max_tokens,
            thinking_config=types.ThinkingConfig(thinking_level=level) if level else None,
        )
        for attempt in range(3):            # at most 2 retries, and only for short, transient limits
            self._gate(stage, "gemini")
            self._sent("gemini")
            try:
                resp = self._gclient.models.generate_content(model=cfg.model, contents=user, config=config)
                break
            except gerrors.ClientError as e:
                msg = e.message or str(e)
                if e.code == 429:
                    delay = _retry_delay(e)
                    if _is_quota(msg) or (delay or 0) > 300:
                        # Daily / free-tier quota: retrying cannot succeed and only looks like abuse. Stop now.
                        raise self._block(stage, "gemini", "quota_exhausted", f"{cfg.model}: {_quota_summary(msg)}", delay) from e
                    if attempt < 2:
                        wait = min(delay or 15 * (attempt + 1), 60)
                        log.warning("%s: Gemini rate limit, one retry in %ss", stage, wait)
                        time.sleep(wait)
                        continue
                    raise self._block(stage, "gemini", "rate_limited", f"{cfg.model}: {msg}", delay or 60) from e
                if e.code in (401, 403) or "api key not valid" in msg.lower() or "api_key_invalid" in msg.lower():
                    raise self._block(stage, "gemini", "auth_error", f"Gemini rejected the API key (GEMINI_API_KEY): {msg}", None) from e
                if e.code == 404:   # retired or unknown model: every later call with it would fail the same way
                    self._gone[cfg.model] = msg[:200]
                raise LLMError(f"{stage}: Gemini error {e.code}: {msg}") from e
            except gerrors.ServerError as e:
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                raise self._outage(stage, "gemini", f"Gemini server error {e.code}: {e.message}") from e
            except Exception as e:
                if not _is_transport_error(e):
                    raise
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                raise self._outage(stage, "gemini", f"cannot reach Gemini: {type(e).__name__}: {str(e)[:200]}") from e
        self._record_gemini(stage, cfg, resp.usage_metadata)
        return resp

    def _record_gemini(self, stage: str, cfg: StageConfig, u) -> None:
        cached = (u.cached_content_token_count or 0) if u else 0
        self._record(stage, "gemini", [{
            "model": cfg.model, "billed": True, "cache_write_tokens": 0, "cache_read_tokens": cached,
            "input_tokens": (u.prompt_token_count or 0) - cached if u else 0,
            # Gemini bills thinking as output
            "output_tokens": ((u.candidates_token_count or 0) + (u.thoughts_token_count or 0)) if u else 0,
        }])
