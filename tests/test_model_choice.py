"""Choosing the provider and models from the web AI page / `ti2dac model`."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from ti2dac import modelchoice
from ti2dac.config import STAGES, load_settings, model_choice_path


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in ("TI2DAC_PROVIDER", "TI2DAC_MODEL", "TI2DAC_CONFIG"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TI2DAC_ENV_FILE", str(tmp_path / "none.env"))
    monkeypatch.chdir(tmp_path)   # no ti2dac.yaml here


def _all(model):
    return {k: model for k in STAGES}


def test_saved_choice_overrides_yaml_and_environment_overrides_both(settings, monkeypatch):
    models = {**_all("claude-opus-5-5"), "translate": "claude-haiku-5-5"}
    new = modelchoice.choose(settings, "anthropic", models, "alice")
    assert new.ai.translate.model == "claude-haiku-5-5" and settings.ai.translate.model == "claude-opus-5-5"   # old object untouched
    monkeypatch.setenv("TI2DAC_STATE_DIR", settings.state_dir)
    assert load_settings().ai.translate.model == "claude-haiku-5-5"
    monkeypatch.setenv("TI2DAC_MODEL", "claude-sonnet-5-5")
    assert {getattr(load_settings().ai, k).model for k in STAGES} == {"claude-sonnet-5-5"}


def test_switching_provider_keeps_each_providers_models(settings):
    s = modelchoice.choose(settings, "anthropic", _all("claude-sonnet-5-5"), "alice")
    s = modelchoice.choose(s, "gemini", _all("gemini-flash-latest"), "alice")
    assert s.ai.provider == "gemini" and s.ai.generate.model == "gemini-flash-latest"
    assert modelchoice.current(s, "anthropic") == _all("claude-sonnet-5-5")     # remembered for switching back
    s = modelchoice.choose(s, "anthropic", modelchoice.current(s, "anthropic"), "alice")
    assert s.ai.provider == "anthropic" and s.ai.analyze.model == "claude-sonnet-5-5"


def test_unknown_or_cross_provider_models_are_rejected(settings):
    with pytest.raises(ValueError, match="knows"):
        modelchoice.choose(settings, "anthropic", _all("claude-made-up"), "alice")
    with pytest.raises(ValueError, match="knows"):
        modelchoice.choose(settings, "anthropic", _all("gemini-flash-latest"), "alice")
    assert not model_choice_path(settings.state_dir).exists()


def test_fetched_model_list_adds_choices(settings, monkeypatch):
    monkeypatch.setattr(modelchoice, "_list_anthropic", lambda: [{"id": "claude-opus-5-5", "name": "Claude Opus 5.5"},
                                                                  {"id": "claude-new-6", "name": "Claude New 6"}])
    ok, msg = modelchoice.refresh(settings, "anthropic")
    assert ok and "2 models" in msg
    ids = {m["id"]: m for m in modelchoice.available(settings, "anthropic")}
    assert "claude-new-6" in ids and ids["claude-new-6"]["price"] == "price unknown"
    assert ids["claude-haiku-5-5"]["unlisted"] and not ids["claude-opus-5-5"]["unlisted"]
    assert modelchoice.choose(settings, "anthropic", _all("claude-new-6"), "alice").ai.generate.model == "claude-new-6"


def test_web_ai_page_switches_model_live(settings):
    from ti2dac.web.app import create_app

    client = TestClient(create_app(settings))
    page = client.get("/ai").text
    assert 'id="models"' in page and "Use Gemini (Google AI Studio)" in page and "Different model per stage" in page
    r = client.post("/ai/models", data={"provider": "anthropic", "model": "claude-sonnet-5-5",
                                        "stage_generate": "claude-opus-5-5"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/ai#models"
    status = client.get("/api/ai-status").json()
    assert status["models"] == {"analyze": "claude-sonnet-5-5", "generate": "claude-opus-5-5",
                                "repair": "claude-sonnet-5-5", "translate": "claude-sonnet-5-5"}
    assert "Saved: Claude (Anthropic) is the active provider" in client.get("/ai").text
    client.post("/ai/models", data={"provider": "gemini", "model": "gemini-flash-latest"})
    assert client.get("/api/ai-status").json()["provider"] == "gemini"
    assert json.loads(model_choice_path(settings.state_dir).read_text())["provider"] == "gemini"
    client.post("/ai/models", data={"provider": "anthropic", "model": "not-a-model"})
    assert client.get("/api/ai-status").json()["provider"] == "gemini"            # rejected, nothing changed
    assert "not a Claude (Anthropic) model" in client.get("/ai").text


def test_cli_model_command(settings, monkeypatch, tmp_path):
    from ti2dac.cli import app

    monkeypatch.setenv("TI2DAC_STATE_DIR", settings.state_dir)
    runner = CliRunner()
    r = runner.invoke(app, ["model", "claude-haiku-5-5", "--stage", "translate"])
    assert r.exit_code == 0, r.output
    assert "translate=claude-haiku-5-5" in r.output and "generate=claude-opus-5-5" in r.output
    r = runner.invoke(app, ["model"])
    assert "claude-fable-5-1" in r.output and "in use:" in r.output
    assert runner.invoke(app, ["model", "nope-1"]).exit_code == 1
