"""Operational logging, security events and health checks."""
from __future__ import annotations

import base64
import json
import logging
import os
import time

import pytest
from fastapi.testclient import TestClient

from ti2dac import health, obs
from ti2dac.feedback import Store

from .test_ai_limits import _ask, _gemini_ok, gemini  # noqa: F401  (gemini is a fixture)


def _events(caplog, name):
    return [r for r in caplog.records if getattr(r, "event", "") == name]


@pytest.fixture(autouse=True)
def _capture(caplog):
    caplog.set_level(logging.INFO, logger="ti2dac.events")


def test_each_ai_call_is_one_metric_event(settings, gemini, caplog):
    settings.ai.response_cache = True
    llm = gemini([])
    _ask(llm)
    _ask(llm)                                   # second time from the cache
    calls = _events(caplog, "ai.call")
    assert [c.outcome for c in calls] == ["ok", "cached"]
    ok = calls[0]
    assert ok.provider == "gemini" and ok.model == "gemini-flash-latest" and ok.input_tokens == 10 and ok.output_tokens == 5
    assert ok.latency_ms >= 0 and ok.attempts == 1


def test_failed_ai_calls_are_logged_with_their_outcome(settings, gemini, caplog):
    from ti2dac.llm import LLMRefusal

    blocked = _gemini_ok()
    blocked.candidates[0].finish_reason.name = "SAFETY"
    with pytest.raises(LLMRefusal):
        _ask(gemini([blocked]))
    (ev,) = _events(caplog, "ai.call")
    assert ev.outcome == "refused" and ev.levelno == logging.WARNING


def test_outage_event_counts_the_retried_requests(settings, gemini, caplog):
    import httpx

    from ti2dac.llm import LLMOutage

    with pytest.raises(LLMOutage):
        _ask(gemini([httpx.ConnectError("reset")] * 3))
    (ev,) = _events(caplog, "ai.call")
    assert ev.outcome == "outage" and ev.requests == 3 and ev.attempts == 0   # sent three times, nothing answered


def test_json_lines_carry_context_and_never_keys(settings, tmp_path):
    settings.log.dir = str(tmp_path / "logs")
    path = obs.setup(settings, component="web")
    try:
        obs.run_id.set("run-1")
        obs.event("test.event", note="key sk-ant-api03-abcdefghijklmnop and AIzaSyA1234567890123456789012", n=3)
        for h in logging.getLogger().handlers:
            h.flush()
        line = json.loads(path.read_text().strip().splitlines()[-1])
    finally:
        obs.run_id.set("")
        settings.log.max_mb = 0
        obs.setup(settings)                     # detach the file handler again
    assert line["event"] == "test.event" and line["component"] == "web" and line["run_id"] == "run-1" and line["n"] == 3
    assert "sk-ant" not in line["note"] and "AIza" not in line["note"] and line["note"].count("[SECRET]") == 2
    assert oct(os.stat(path).st_mode)[-3:] == "600"


def test_audit_entries_are_forwarded(settings, caplog):
    Store(settings.db_path).audit("alice", "review.set", {"run_id": "r", "note": "x" * 1000})
    (ev,) = _events(caplog, "audit")
    assert ev.action == "review.set" and ev.actor == "alice" and len(ev.details["note"]) == 300


def _web(settings, with_user=True):
    from ti2dac.users import Users
    from ti2dac.web.app import create_app

    if with_user:
        Users(settings.state_dir).add("bob", "correct-horse-battery", "analyst")
    return TestClient(create_app(settings))


def _auth(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


def test_security_events(settings, caplog):
    client = _web(settings)
    assert client.get("/").status_code == 401
    assert not _events(caplog, "audit")         # a browser's first request without credentials is not an attack
    assert client.get("/", headers=_auth("bob", "wrong")).status_code == 401
    assert client.post("/ai/reset", headers=_auth("bob", "correct-horse-battery")).status_code == 403
    assert client.post("/ai/reset", headers={**_auth("bob", "correct-horse-battery"),
                                             "Origin": "https://evil.example"}).status_code == 403
    actions = [(e.action, e.actor) for e in _events(caplog, "audit")]
    assert actions == [("auth.failed", "bob"), ("access.denied", "bob"), ("csrf.refused", "bob")]
    store = Store(settings.db_path)
    assert {e["action"] for e in store.audit_entries()} == {"auth.failed", "access.denied", "csrf.refused"}


def test_requests_are_logged_with_a_request_id(settings, caplog):
    client = _web(settings, with_user=False)
    r = client.get("/ai", headers={"X-Request-ID": "abc123"})
    assert r.headers["X-Request-ID"] == "abc123"
    (ev,) = [e for e in _events(caplog, "http.request") if e.path == "/ai"]
    assert ev.status == 200 and ev.method == "GET" and ev.duration_ms >= 0
    assert client.get("/static/style.css").status_code in (200, 404) and \
        not [e for e in _events(caplog, "http.request") if e.path.startswith("/static")]


def test_healthz_needs_no_login_and_fails_on_a_broken_database(settings, monkeypatch):
    client = _web(settings)
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["checks"]["database"]["status"] == "ok"
    assert r.json()["checks"]["ai_provider"]["status"] == "warn" or os.environ.get("ANTHROPIC_API_KEY")
    monkeypatch.setattr(Store, "health", lambda self: (False, "quick_check: corrupt"))
    r = client.get("/healthz")
    assert r.status_code == 503 and r.json()["status"] == "fail"


def test_disk_and_stuck_job_checks(settings, monkeypatch):
    store = Store(settings.db_path)
    store.job_create("old", "report.pdf", "alice")
    with store._conn() as c:
        c.execute("UPDATE jobs SET created_at='2000-01-01T00:00:00+00:00' WHERE id='old'")
    settings.health.min_free_mb = 10 ** 12     # more than any disk has
    result = health.check(settings, store)
    assert result["checks"]["jobs"]["stuck"] == 1 and result["checks"]["disk_state"]["status"] == "fail"
    assert result["status"] == "fail"


def test_web_jobs_report_start_and_finish(settings, caplog, report_file):
    settings.ai.enabled = False
    client = _web(settings, with_user=False)
    r = client.post("/runs", files={"file": ("op.md", report_file.read_bytes(), "text/markdown")},
                    data={"count": "1"}, follow_redirects=False)
    assert r.status_code == 303
    for _ in range(100):
        if _events(caplog, "job.finish"):
            break
        time.sleep(0.05)
    (fin,) = _events(caplog, "job.finish")
    (start,) = _events(caplog, "job.start")
    assert fin.status == "done" and fin.run_id and start.actor
    (run,) = _events(caplog, "run.finish")
    assert run.rules == 0 and run.ai is False and run.behaviours >= 1


def test_pipeline_failures_are_events(settings, caplog, monkeypatch):
    from ti2dac import pipeline

    with pytest.raises(Exception):
        pipeline.run(str(settings.state_dir) + "/missing-report.md", settings)
    (ev,) = _events(caplog, "run.failed")
    assert ev.error_type and ev.duration_s >= 0
