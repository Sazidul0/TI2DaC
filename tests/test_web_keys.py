"""API keys managed from the web UI, and the self-hosted API reference."""
from __future__ import annotations

import os
import stat

from fastapi.testclient import TestClient

from ti2dac import aistatus
from ti2dac.users import Users
from ti2dac.web import app as web

KEY = "sk-ant-api03-" + "x" * 40 + "WXYZ"


def _client(settings, tmp_path, monkeypatch, ok=True):
    env = tmp_path / ".env"
    env.write_text("# local secrets\nTI2DAC_AUTHOR=SOC\n")
    monkeypatch.setenv("TI2DAC_ENV_FILE", str(env))
    for var in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)   # also restores whatever the test sets
    checked = []
    monkeypatch.setattr(web, "verify_key", lambda p, k: (checked.append((p, k)) or (ok, "checked")))
    return TestClient(web.create_app(settings)), env, checked


def test_save_test_remove_key(settings, tmp_path, monkeypatch):
    client, env, checked = _client(settings, tmp_path, monkeypatch)
    aistatus.record_block(settings.state_dir, "anthropic", "auth_error", "bad key", None)

    r = client.post("/ai/key", data={"provider": "anthropic", "action": "save", "key": KEY}, follow_redirects=False)
    assert r.status_code == 303 and checked == [("anthropic", KEY)]
    assert f"ANTHROPIC_API_KEY={KEY}" in env.read_text() and "TI2DAC_AUTHOR=SOC" in env.read_text(), "other lines kept"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600 and os.environ["ANTHROPIC_API_KEY"] == KEY
    assert aistatus.provider_status(settings.state_dir, "anthropic")["state"] == "ok", "a working key clears the auth pause"

    page = client.get("/ai").text
    assert "…WXYZ" in page and KEY not in page and "from .env" in page
    assert KEY not in client.get("/feedback").text, "the audit log never holds the key"
    assert KEY not in client.get("/api/ai-status").text

    client.post("/ai/key", data={"provider": "anthropic", "action": "remove"})
    assert "ANTHROPIC_API_KEY" not in env.read_text() and "ANTHROPIC_API_KEY" not in os.environ


def test_key_validation_and_permissions(settings, tmp_path, monkeypatch):
    client, env, checked = _client(settings, tmp_path, monkeypatch)
    for bad in ("short", KEY + "\nTI2DAC_NO_AI=1", KEY + " #x", '"' + KEY + '"'):
        assert client.post("/ai/key", data={"provider": "anthropic", "action": "save", "key": bad}).status_code == 400
    assert client.post("/ai/key", data={"provider": "openai", "action": "save", "key": KEY}).status_code == 400
    assert "ANTHROPIC_API_KEY" not in env.read_text() and checked == []

    # a key exported in the shell is not ours to delete
    monkeypatch.setenv("GEMINI_API_KEY", "AIza" + "y" * 35)
    assert client.post("/ai/key", data={"provider": "gemini", "action": "remove"}).status_code == 409
    assert "from environment" in client.get("/ai").text

    users = Users(settings.state_dir)
    users.add("ann", "admin password 123", "admin")
    users.add("carl", "analyst password 123", "analyst")
    client = TestClient(web.create_app(settings))
    data = {"provider": "anthropic", "action": "save", "key": KEY}
    assert client.post("/ai/key", data=data, auth=("carl", "analyst password 123")).status_code == 403
    assert "Only admins can add or change keys" in client.get("/ai", auth=("carl", "analyst password 123")).text
    assert client.post("/ai/key", data=data, auth=("ann", "admin password 123"), headers={"origin": "https://evil.example"}).status_code == 403


def test_failed_check_still_saves(settings, tmp_path, monkeypatch):
    client, env, _ = _client(settings, tmp_path, monkeypatch, ok=False)
    client.post("/ai/key", data={"provider": "gemini", "action": "save", "key": "AIza" + "z" * 35})
    assert "GEMINI_API_KEY=" in env.read_text() and "Saved, but the check failed" in client.get("/ai").text


def test_api_reference(settings, tmp_path, monkeypatch):
    client, *_ = _client(settings, tmp_path, monkeypatch)
    page = client.get("/api")
    assert page.status_code == 200 and "/api/runs/{run_id}" in page.text and "curl" in page.text
    assert client.get("/api/docs", follow_redirects=False).headers["location"] == "/api"
    paths = client.get("/openapi.json").json()["paths"]
    assert "/api/jobs/{jid}" in paths and "/" not in paths and "/ai" not in paths, "HTML pages stay out of the API schema"
