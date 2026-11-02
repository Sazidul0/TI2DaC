"""AI limit handling: stop on quota, short retries only on rate limits, pause shared via ai_status.json."""
from __future__ import annotations

import time
from types import SimpleNamespace

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient
from google.genai import errors as gerrors

from ti2dac import aistatus
from ti2dac.llm import LLM, LLMLimitError
from ti2dac.models import TranslationDraft

OK_JSON = TranslationDraft(query="q", notes="n", confidence="high").model_dump_json()


def _gemini_ok():
    return SimpleNamespace(text=OK_JSON, prompt_feedback=None,
                           candidates=[SimpleNamespace(finish_reason=SimpleNamespace(name="STOP"))],
                           usage_metadata=SimpleNamespace(prompt_token_count=10, cached_content_token_count=0,
                                                          candidates_token_count=5, thoughts_token_count=0))


def _gemini_429(message, retry="48622s"):
    return gerrors.ClientError(429, {"error": {"code": 429, "message": message, "status": "RESOURCE_EXHAUSTED",
                                               "details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo",
                                                            "retryDelay": retry}]}})


class FakeGemini:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), 0
        self.models = self

    def generate_content(self, **kw):
        self.calls += 1
        out = self.outcomes.pop(0) if self.outcomes else _gemini_ok()
        if isinstance(out, Exception):
            raise out
        return out


@pytest.fixture
def gemini(settings, monkeypatch):
    settings.ai.provider = "gemini"
    for st in (settings.ai.analyze, settings.ai.generate, settings.ai.repair, settings.ai.translate):
        st.model = "gemini-flash-latest"
    monkeypatch.setattr(time, "sleep", lambda s: None)

    def make(outcomes):
        llm = LLM(settings)
        llm._gclient = FakeGemini(outcomes)
        return llm
    return make


def _ask(llm, n=0):
    return llm.structured("translate", "system", f"user {n}", TranslationDraft)


def test_daily_quota_stops_immediately_and_pauses_everyone(settings, gemini):
    llm = gemini([_gemini_429("Quota exceeded for metric: generate_content_free_tier_requests, limit: 20 per day")])
    with pytest.raises(LLMLimitError, match="quota exhausted"):
        _ask(llm)
    assert llm._gclient.calls == 1, "a daily quota must never be retried"
    st = aistatus.provider_status(settings.state_dir, "gemini")
    assert st["state"] == "quota_exhausted" and st["retry_at"] and st["requests_today"] == 1
    # a NEW client in another process/run is refused locally: nothing is sent
    other = gemini([])
    with pytest.raises(LLMLimitError, match="no request sent"):
        _ask(other, 1)
    assert other._gclient.calls == 0


def test_per_minute_rate_limit_retries_briefly_then_succeeds(settings, gemini):
    llm = gemini([_gemini_429("Quota exceeded for metric: requests per minute", retry="2s"), _gemini_ok()])
    assert _ask(llm).query == "q" and llm._gclient.calls == 2
    assert aistatus.provider_status(settings.state_dir, "gemini")["state"] == "ok"


def test_persistent_rate_limit_gives_up_after_two_retries(settings, gemini):
    llm = gemini([_gemini_429("too many requests per minute", retry="5s")] * 5)
    with pytest.raises(LLMLimitError, match="rate limited"):
        _ask(llm)
    assert llm._gclient.calls == 3
    assert aistatus.provider_status(settings.state_dir, "gemini")["state"] == "rate_limited"


def test_pause_lifts_when_retry_time_passes_and_reset_clears(settings, gemini):
    aistatus.record_block(settings.state_dir, "gemini", "rate_limited", "x", retry_after_s=-1)   # already expired
    assert aistatus.block_reason(settings.state_dir, "gemini") == ""
    aistatus.record_block(settings.state_dir, "gemini", "auth_error", "bad key", None)
    assert "auth error" in aistatus.block_reason(settings.state_dir, "gemini")
    aistatus.reset(settings.state_dir, "gemini")
    assert aistatus.block_reason(settings.state_dir, "gemini") == ""


def test_own_daily_cap_stops_before_the_provider_limit(settings, gemini):
    settings.ai.daily_request_limit = 2
    llm = gemini([])
    _ask(llm, 1)
    _ask(llm, 2)
    with pytest.raises(LLMLimitError, match="daily request cap"):
        _ask(llm, 3)
    assert llm._gclient.calls == 2


def test_cache_hits_do_not_count_or_get_blocked(settings, gemini):
    settings.ai.response_cache = True
    llm = gemini([])
    _ask(llm)
    aistatus.record_block(settings.state_dir, "gemini", "quota_exhausted", "used up", 3600)
    assert _ask(llm).query == "q"          # served from cache although the provider is paused
    assert llm._gclient.calls == 1


def _anthropic_error(cls, status, message, headers=None):
    resp = httpx.Response(status, headers=headers or {}, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
                          json={"type": "error", "error": {"message": message}})
    return cls(message, response=resp, body=None)


@pytest.mark.parametrize("err,state", [
    (lambda: _anthropic_error(anthropic.RateLimitError, 429, "rate limit of 50 requests per minute", {"retry-after": "20"}), "rate_limited"),
    (lambda: _anthropic_error(anthropic.BadRequestError, 400, "Your credit balance is too low to access the API"), "quota_exhausted"),
    (lambda: _anthropic_error(anthropic.AuthenticationError, 401, "invalid x-api-key"), "auth_error"),
])
def test_anthropic_limits_are_classified(settings, err, state):
    llm = LLM(settings)

    def boom(**kw):
        raise err()
    llm._client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(stream=boom)))
    with pytest.raises(LLMLimitError):
        _ask(llm)
    assert aistatus.provider_status(settings.state_dir, "anthropic")["state"] == state


def test_quota_mid_run_keeps_finished_rules_and_sends_nothing_more(settings, report_file, monkeypatch):
    from ti2dac import pipeline
    from ti2dac.feedback import Store

    from .conftest import FakeLLM

    class QuotaAfterAnalysis(FakeLLM):
        def structured(self, stage, system, user, schema):
            if stage == "generate":
                self._gate(stage)
                aistatus.record_block(settings.state_dir, "anthropic", "quota_exhausted", "credit balance is too low", None)
                raise LLMLimitError("generate: quota", state="quota_exhausted")
            return super().structured(stage, system, user, schema)

    fake = QuotaAfterAnalysis(settings)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a: fake)
    record, _ = pipeline.run(str(report_file), settings, store=Store(settings.db_path), actor="alice")
    assert record.packages == [] and any("not generated" in w for w in record.warnings)
    assert "quota exhausted" in aistatus.block_reason(settings.state_dir, "anthropic")


def test_web_shows_pause_and_does_not_start_ai_jobs(settings):
    from ti2dac.web.app import create_app

    client = TestClient(create_app(settings))
    page = client.get("/")
    assert "No API key configured" in page.text or "AI on" in page.text
    aistatus.record_block(settings.state_dir, "anthropic", "quota_exhausted", "credit balance is too low", 7200)
    page = client.get("/")
    assert "AI requests are paused" in page.text and "credit balance is too low" in page.text
    r = client.post("/runs", data={"url": "https://example.org/report", "count": "1"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/ai?blocked=1"
    assert client.get("/ai?blocked=1").status_code == 200
    assert client.get("/api/ai-status").json()["state"] == "quota_exhausted"
    assert client.post("/ai/reset", follow_redirects=False).status_code == 303      # local single-user = admin
    assert client.get("/api/ai-status").json()["state"] == "ok"


def test_dotenv_is_loaded_but_real_environment_wins(tmp_path, monkeypatch):
    from ti2dac.config import load_dotenv

    env = tmp_path / ".env"
    env.write_text("# keys\nGEMINI_API_KEY='from-file'\nexport TI2DAC_PROVIDER=gemini\nANTHROPIC_API_KEY=file\n")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("TI2DAC_PROVIDER", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "real")
    load_dotenv(env)
    import os
    assert os.environ["GEMINI_API_KEY"] == "from-file" and os.environ["TI2DAC_PROVIDER"] == "gemini"
    assert os.environ["ANTHROPIC_API_KEY"] == "real"


def test_token_usage_is_tracked_and_shown(settings, gemini):
    from ti2dac.web.app import create_app

    llm = gemini([])
    _ask(llm, 1)
    _ask(llm, 2)
    st = aistatus.provider_status(settings.state_dir, "gemini")
    assert st["input_tokens_today"] == 20 and st["output_tokens_today"] == 10 and st["output_tokens_total"] == 10
    client = TestClient(create_app(settings))
    assert "30 tokens today" in client.get("/").text
    ai = client.get("/ai").text
    assert "Tokens today" in ai and "20 input" in ai
