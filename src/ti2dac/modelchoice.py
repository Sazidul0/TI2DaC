"""Choosing the AI provider and models from the web AI page or `ti2dac model`.

The choice lives in <state_dir>/ai_models.json (see config.read_model_choice) and overrides ti2dac.yaml;
TI2DAC_PROVIDER / TI2DAC_MODEL in the environment still override it. Only models from the built-in catalog
or from the provider's own model list (fetched with the key, no tokens used) can be chosen.
"""
from __future__ import annotations

import copy
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .config import ENV_MODEL_VARS, PROVIDERS, STAGES, Settings, apply_ai_env, apply_model_choice, model_choice_path, \
    read_model_choice, write_model_choice
from .llm import FALLBACK_MODELS, price

# Built-in choices, shown even before the provider's list has been fetched. Notes are what matters for this
# tool: security reports trip safety classifiers, and refusal fallback only exists on some models.
CATALOG: dict[str, list[dict]] = {
    "anthropic": [
        {"id": "claude-opus-5-5", "name": "Claude Opus 5.5",
         "note": "Default. Strong rule writing at a moderate price."},
        {"id": "claude-sonnet-5-5", "name": "Claude Sonnet 5.5",
         "note": "Half the price of Opus 5.5. A good fit for analysis, repair and translation."},
        {"id": "claude-haiku-5-5", "name": "Claude Haiku 5.5",
         "note": "Cheapest. No refusal fallback: a declined security report is skipped with nothing to catch it."},
        {"id": "claude-fable-5-1", "name": "Claude Fable 5.1",
         "note": "Most capable, 2.5x the price of Opus 5.5 and slower. Its classifiers target most cybersecurity "
                 "content, so expect refusals (answered by the fallback model). Needs 30-day data retention."},
        {"id": "claude-opus-5", "name": "Claude Opus 5",
         "note": "Previous Opus. Costs more than Opus 5.5."},
    ],
    "gemini": [
        {"id": "gemini-flash-latest", "name": "Gemini Flash (latest)",
         "note": "Free-tier testing. Google may use free-tier prompts, so only TLP:CLEAR/GREEN reports are sent."},
    ],
}
PROVIDER_LABELS = {"anthropic": "Claude (Anthropic)", "gemini": "Gemini (Google AI Studio)"}


def _cache_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "model_list.json"


def _cached(state_dir: str | Path) -> dict:
    try:
        data = json.loads(_cache_path(state_dir).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def available(settings: Settings, provider: str) -> list[dict]:
    """Catalog models first, then other models from the provider's fetched list. Never contacts the provider."""
    out = [dict(m, listed=True) for m in CATALOG[provider]]
    known = {m["id"] for m in out}
    live = [m for m in _cached(settings.state_dir).get(provider, {}).get("models", [])
            if provider != "gemini" or not _NOT_TEXT.search(m["id"])]   # lists fetched before the filter existed
    for m in live:
        if m["id"] not in known:
            out.append({"id": m["id"], "name": m.get("name") or m["id"], "note": "", "listed": True})
            known.add(m["id"])
    live_ids = {m["id"] for m in live}
    for m in out:
        p = price(m["id"], settings.ai.prices)
        m["price"] = f"${p[0]:g} / ${p[1]:g} per 1M tokens" if p else "price unknown"
        m["fallback"] = m["id"] in FALLBACK_MODELS
        # Fetched lists say what this key can use; a catalog model missing from a fetched list may not work.
        m["unlisted"] = bool(live_ids) and m["id"] not in live_ids
    return out


def fetched_at(settings: Settings, provider: str) -> str:
    return _cached(settings.state_dir).get(provider, {}).get("fetched_at", "")


def refresh(settings: Settings, provider: str) -> tuple[bool, str]:
    """Fetch the models this key can use (a model listing: no tokens, no generation quota)."""
    try:
        models = _list_anthropic() if provider == "anthropic" else _list_gemini()
    except Exception as e:   # network, auth, missing package: keep the catalog and say why
        return False, f"could not fetch the {PROVIDER_LABELS[provider]} model list: {type(e).__name__}: {str(e)[:200]}"
    data = _cached(settings.state_dir)
    data[provider] = {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "models": models}
    p = _cache_path(settings.state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(p)
    return True, f"{len(models)} models available to this key"


def _list_anthropic() -> list[dict]:
    import anthropic

    client = anthropic.Anthropic(max_retries=0, timeout=15)
    return [{"id": m.id, "name": m.display_name} for m in client.models.list(limit=100) if m.id.startswith("claude")]


# Gemini models that answer generateContent but cannot write rules (speech, images, robotics, computer use)
_NOT_TEXT = re.compile(r"tts|image|nano-banana|robotics|computer-use|transcribe|live|audio|embedding")


def _list_gemini() -> list[dict]:
    from google import genai
    from google.genai import types

    client = genai.Client(http_options=types.HttpOptions(timeout=15_000))
    out = []
    for m in client.models.list():
        mid = (m.name or "").removeprefix("models/")
        if mid.startswith("gemini") and "generateContent" in (m.supported_actions or []) \
                and not _NOT_TEXT.search(mid):
            out.append({"id": mid, "name": m.display_name or mid})
    return out


def current(settings: Settings, provider: str) -> dict[str, str]:
    """Models per stage that `provider` would use: live settings when it is active, else its saved or default choice."""
    if provider == settings.ai.provider:
        return {k: getattr(settings.ai, k).model for k in STAGES}
    saved = (read_model_choice(settings.state_dir).get("models") or {}).get(provider) or {}
    default = settings.ai.gemini_model if provider == "gemini" else CATALOG["anthropic"][0]["id"]
    return {k: saved.get(k) or default for k in STAGES}


def env_locks() -> list[str]:
    return [v for v in ENV_MODEL_VARS if os.environ.get(v)]


def choose(settings: Settings, provider: str, models: dict[str, str], actor: str) -> Settings:
    """Validate and save a choice; returns a NEW settings object with it applied (running jobs keep the old one)."""
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}")
    if set(models) != set(STAGES):
        raise ValueError(f"a model is needed for every stage: {', '.join(STAGES)}")
    allowed = {m["id"] for m in available(settings, provider)}
    bad = sorted({m for m in models.values() if m not in allowed})
    if bad:
        raise ValueError(f"not a {PROVIDER_LABELS[provider]} model ti2dac knows: {', '.join(bad)}. "
                         "Refresh the model list if it is new.")
    write_model_choice(settings.state_dir, provider, models, actor)
    return reload(settings)


def reload(settings: Settings) -> Settings:
    """A NEW settings object with the saved choice re-applied (running jobs keep the old one)."""
    new = copy.deepcopy(settings)
    apply_model_choice(new, read_model_choice(settings.state_dir))
    apply_ai_env(new)
    return new


def saved_mtime(settings: Settings) -> float:
    """When the choice was last saved (by any process), 0 if never."""
    try:
        return model_choice_path(settings.state_dir).stat().st_mtime
    except OSError:
        return 0.0
