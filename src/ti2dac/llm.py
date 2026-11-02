"""Claude API wrapper: structured output, refusal fallback, response cache, token accounting."""
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

from . import aistatus
from .config import Settings, StageConfig
from .models import Usage
from .prompts import PROMPT_VERSION

log = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)

# Models that accept the server-side `fallbacks: "default"` parameter.
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"

# USD per 1M tokens: (input, output, cache_read). Cache writes bill at 1.25x input. Estimates only.
PRICES = {
    "claude-opus-5-5": (4.0, 20.0, 0.20),
    "claude-sonnet-5-5": (2.0, 10.0, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-1": (10.0, 50.0, 0.25),
    "claude-opus-5": (5.0, 25.0, 0.50),
}


class LLMError(Exception):
    pass


class LLMRefusal(LLMError):
    pass


class LLMLimitError(LLMError):
    """Provider limit, quota or credential problem: AI calls are paused (see aistatus)."""

    def __init__(self, message: str, state: str = "blocked"):
        super().__init__(message)
        self.state = state


_QUOTA_HINTS = ("per day", "perday", "free_tier", "quota", "credit balance", "spend limit", "usage limit",
                "billing", "exceeded your current")


def _is_quota(message: str) -> bool:
    """Long-lived limit (daily quota, credit, spend cap) as opposed to a per-minute rate limit."""
    m = (message or "").lower()
    if ("per minute" in m or "perminute" in m) and "per day" not in m and "perday" not in m:
        return False
    return any(h in m for h in _QUOTA_HINTS)


def _header_seconds(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _retry_delay(err) -> int | None:
    """Seconds from a Gemini 429 RetryInfo detail ('retryDelay': '37s'), if present."""
    m = re.search(r"retryDelay['\"]?\s*:\s*['\"](\d+)(?:\.\d+)?s", str(getattr(err, "details", "")) + str(err))
    return min(int(m.group(1)) + 2, 120) if m else None


def estimate_cost(usage: Usage) -> float:
    """USD estimate for models with a known price; unknown models (e.g. Gemini free tier) count as 0."""
    total = 0.0
    for stage in usage.by_stage.values():
        p = PRICES.get(str(stage.get("model_price_key", "")), (0.0, 0.0, 0.0))
        total += (stage.get("input_tokens", 0) * p[0] + stage.get("output_tokens", 0) * p[1]
                  + stage.get("cache_read_tokens", 0) * p[2] + stage.get("cache_write_tokens", 0) * p[0] * 1.25) / 1e6
    return round(total, 4)


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
    def __init__(self, settings: Settings, usage: Usage | None = None):
        self.settings = settings
        self.usage = usage or Usage()
        self._lock = threading.Lock()
        self._client: anthropic.Anthropic | None = None
        self._gclient = None
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
    def _record(self, stage: str, cfg: StageConfig, msg=None, cached: bool = False) -> None:
        with self._lock:
            s = self.usage.by_stage.setdefault(stage, {"calls": 0, "cached_calls": 0, "input_tokens": 0,
                                                        "output_tokens": 0, "cache_read_tokens": 0,
                                                        "cache_write_tokens": 0})
            s["model_price_key"] = cfg.model  # type: ignore[assignment]
            if cached:
                s["cached_calls"] += 1
                self.usage.cached_calls += 1
                return
            u = msg.usage
            vals = {
                "input_tokens": u.input_tokens or 0,
                "output_tokens": u.output_tokens or 0,
                "cache_read_tokens": u.cache_read_input_tokens or 0,
                "cache_write_tokens": u.cache_creation_input_tokens or 0,
            }
            s["calls"] += 1
            self.usage.calls += 1
            for k, v in vals.items():
                s[k] += v
            self.usage.input_tokens += vals["input_tokens"]
            self.usage.output_tokens += vals["output_tokens"]
            self.usage.cache_read_tokens += vals["cache_read_tokens"]
            self.usage.cache_write_tokens += vals["cache_write_tokens"]
            price = PRICES.get(cfg.model, (0.0, 0.0, 0.0))     # unknown models (e.g. Gemini) count as $0
            cost = (vals["input_tokens"] * price[0] + vals["output_tokens"] * price[1] + vals["cache_read_tokens"] * price[2]
                    + vals["cache_write_tokens"] * price[0] * 1.25) / 1e6
        aistatus.add_usage(self.settings.state_dir, self.settings.ai.provider, vals["input_tokens"] + vals["cache_write_tokens"],
                           vals["output_tokens"], vals["cache_read_tokens"], cost)

    # ------------------------------------------------------------------ call
    def structured(self, stage: str, system: str, user: str, schema: type[T]) -> T:
        cfg: StageConfig = getattr(self.settings.ai, stage)
        key = self._key(cfg, system, user, schema)
        hit = self._cache_get(key)
        if hit is not None:
            try:
                obj = schema.model_validate_json(hit)
                self._record(stage, cfg, cached=True)
                return obj
            except ValidationError:
                pass   # schema changed since caching; fall through to a fresh call

        self._gate(stage)
        if self.settings.ai.provider == "gemini":
            text = self._call_gemini(stage, cfg, system, user, schema)
        else:
            text = self._call_anthropic(stage, cfg, system, user, schema)
        aistatus.record_ok(self.settings.state_dir, self.settings.ai.provider)
        try:
            obj = schema.model_validate_json(text)
        except ValidationError as e:
            raise LLMError(f"{stage}: response did not match schema: {e}") from e
        self._cache_put(key, text)
        return obj

    # ------------------------------------------------------------------ limits
    def _gate(self, stage: str) -> None:
        """Refuse locally (no request sent) while the provider is limited or our daily cap is reached."""
        reason = aistatus.block_reason(self.settings.state_dir, self.settings.ai.provider,
                                       self.settings.ai.daily_request_limit)
        if reason:
            raise LLMLimitError(f"{stage}: AI paused, no request sent. {reason}")

    def _sent(self) -> None:
        aistatus.count_request(self.settings.state_dir, self.settings.ai.provider)

    def _block(self, stage: str, state: str, message: str, retry_after_s: float | None) -> LLMLimitError:
        aistatus.record_block(self.settings.state_dir, self.settings.ai.provider, state, message, retry_after_s)
        log.warning("%s: %s (%s); further AI calls paused", stage, state, message[:160])
        return LLMLimitError(f"{stage}: {self.settings.ai.provider} {state.replace('_', ' ')}: {message[:300]}", state=state)

    # ------------------------------------------------------------------ providers
    def _call_anthropic(self, stage: str, cfg: StageConfig, system: str, user: str, schema: type[BaseModel]) -> str:
        kwargs: dict = {
            "model": cfg.model,
            "max_tokens": cfg.max_tokens,
            # Frozen system prompt marked cacheable: repeated stage-2 calls in a run reuse it.
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": transform_schema(schema)}},
        }
        if cfg.effort:
            kwargs["output_config"]["effort"] = cfg.effort
        if self.settings.ai.server_side_fallback and cfg.model in _FALLBACK_MODELS:
            kwargs["betas"] = [_FALLBACK_BETA]
            kwargs["fallbacks"] = "default"

        self._sent()
        try:
            with self.client.beta.messages.stream(**kwargs) as stream:
                msg = stream.get_final_message()
        except anthropic.AuthenticationError as e:
            raise self._block(stage, "auth_error", "Anthropic rejected the API key (ANTHROPIC_API_KEY / `ant auth login`)", None) from e
        except anthropic.PermissionDeniedError as e:
            raise self._block(stage, "auth_error", f"permission denied: {e.message}", None) from e
        except TypeError as e:   # the SDK raises TypeError when no credentials are configured at all
            if "authentication" not in str(e).lower():
                raise
            raise self._block(stage, "auth_error", "No Anthropic credentials found: set ANTHROPIC_API_KEY (or run "
                              "`ant auth login`), use TI2DAC_PROVIDER=gemini with GEMINI_API_KEY, or run with --no-ai", None) from e
        except anthropic.RateLimitError as e:
            # The SDK has already retried (max_retries, honouring retry-after); stop here.
            retry_after = _header_seconds(e.response.headers.get("retry-after")) if e.response is not None else None
            state = "quota_exhausted" if _is_quota(e.message) else "rate_limited"
            raise self._block(stage, state, e.message, retry_after or (None if state == "quota_exhausted" else 60)) from e
        except anthropic.BadRequestError as e:
            if _is_quota(e.message):   # e.g. "credit balance is too low", workspace spend limit reached
                raise self._block(stage, "quota_exhausted", e.message, None) from e
            raise LLMError(f"{stage}: bad request: {e.message}") from e
        except anthropic.APIStatusError as e:
            raise LLMError(f"{stage}: API error {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:
            raise LLMError(f"{stage}: cannot reach the Anthropic API: {e}") from e

        self._record(stage, cfg, msg)
        if msg.stop_reason == "refusal":
            details = msg.stop_details
            cat = getattr(details, "category", None) if details else None
            aistatus.update(self.settings.state_dir, "anthropic", state="refused", message=f"{stage}: category={cat}")
            raise LLMRefusal(f"{stage}: model declined (category={cat}). Security-research orgs can apply to "
                             "Anthropic's Cyber Verification Program; otherwise rephrase or review the report.")
        if msg.stop_reason == "max_tokens":
            raise LLMError(f"{stage}: output truncated at max_tokens={cfg.max_tokens}; raise ai.{stage}.max_tokens")
        log.debug("%s: request %s, usage %s", stage, getattr(msg, "_request_id", "?"), msg.usage)
        return next((b.text for b in msg.content if b.type == "text"), "")

    def _call_gemini(self, stage: str, cfg: StageConfig, system: str, user: str, schema: type[BaseModel]) -> str:
        try:
            from google import genai
            from google.genai import errors as gerrors
            from google.genai import types
        except ImportError as e:
            raise LLMError("provider 'gemini' needs the google-genai package: pip install 'ti2dac[gemini]'") from e
        if self._gclient is None:
            # Key from GEMINI_API_KEY / GOOGLE_API_KEY. Generous timeout: free-tier latency can be minutes.
            self._gclient = genai.Client(http_options=types.HttpOptions(timeout=600_000, retry_options=None))
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
            self._gate(stage)
            self._sent()
            try:
                resp = self._gclient.models.generate_content(model=cfg.model, contents=user, config=config)
                break
            except gerrors.ClientError as e:
                msg = e.message or str(e)
                if e.code == 429:
                    delay = _retry_delay(e)
                    if _is_quota(msg) or (delay or 0) > 300:
                        # Daily / free-tier quota: retrying cannot succeed and only looks like abuse. Stop now.
                        raise self._block(stage, "quota_exhausted", f"{cfg.model}: {msg}", delay) from e
                    if attempt < 2:
                        wait = min(delay or 15 * (attempt + 1), 60)
                        log.warning("%s: Gemini rate limit, one retry in %ss", stage, wait)
                        time.sleep(wait)
                        continue
                    raise self._block(stage, "rate_limited", f"{cfg.model}: {msg}", delay or 60) from e
                if e.code in (401, 403) or "api key not valid" in msg.lower() or "api_key_invalid" in msg.lower():
                    raise self._block(stage, "auth_error", f"Gemini rejected the API key (GEMINI_API_KEY): {msg}", None) from e
                raise LLMError(f"{stage}: Gemini error {e.code}: {msg}") from e
            except gerrors.ServerError as e:
                if attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                raise LLMError(f"{stage}: Gemini server error {e.code}: {e.message}") from e
        self._record_gemini(stage, cfg, resp.usage_metadata)
        return resp

    def _record_gemini(self, stage: str, cfg: StageConfig, u) -> None:
        class _U:   # adapt Gemini usage to the Anthropic-shaped accounting
            input_tokens = (u.prompt_token_count or 0) - (u.cached_content_token_count or 0) if u else 0
            output_tokens = ((u.candidates_token_count or 0) + (u.thoughts_token_count or 0)) if u else 0
            cache_read_input_tokens = (u.cached_content_token_count or 0) if u else 0
            cache_creation_input_tokens = 0

        self._record(stage, cfg, type("M", (), {"usage": _U})())
