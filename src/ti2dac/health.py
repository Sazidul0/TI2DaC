"""Health checks for `/healthz` and `ti2dac health`: database, disk space, log file, AI provider, stuck jobs.

Status per check: ok, warn (works, needs attention) or fail (ti2dac cannot work properly). Messages carry no
secrets or report content, because /healthz is reachable without login for uptime checkers.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from . import aistatus

_RANK = {"ok": 0, "warn": 1, "fail": 2}


def _disk(path: Path, min_free_mb: int) -> dict:
    p = path
    while not p.exists() and p != p.parent:   # not created yet: measure the volume it will live on
        p = p.parent
    free_mb = shutil.disk_usage(p).free // (1024 * 1024)
    status = "fail" if free_mb < min_free_mb / 4 else "warn" if free_mb < min_free_mb else "ok"
    return {"status": status, "free_mb": int(free_mb), "message": f"{free_mb:,} MB free (warn below {min_free_mb:,} MB)"}


def check(settings, store) -> dict:
    checks: dict[str, dict] = {}
    ok, msg = store.health()
    checks["database"] = {"status": "ok" if ok else "fail", "message": msg}
    for name, path in (("disk_state", Path(settings.state_dir)), ("disk_output", Path(settings.output_dir))):
        try:
            checks[name] = _disk(path, settings.health.min_free_mb)
        except OSError as e:
            checks[name] = {"status": "fail", "message": f"{type(e).__name__}: {e}"}
    if settings.ai.enabled:
        prov = settings.ai.provider
        blocked = aistatus.block_reason(settings.state_dir, prov, settings.ai.daily_request_limit)
        state = aistatus.provider_status(settings.state_dir, prov).get("state", "ok")
        no_key = aistatus.key_status(prov) == "not configured"
        # warn, not fail: everything except AI drafting keeps working while the provider is paused or down
        checks["ai_provider"] = {"status": "warn" if blocked or no_key or state == "unavailable" else "ok",
                                 "provider": prov, "state": "no key" if no_key else state}
    stuck = store.stuck_jobs(settings.health.stuck_job_minutes)
    checks["jobs"] = {"status": "warn" if stuck else "ok", "stuck": len(stuck),
                      "message": f"{len(stuck)} job(s) running longer than {settings.health.stuck_job_minutes} min"
                      if stuck else "no stuck jobs"}
    overall = max((c["status"] for c in checks.values()), key=_RANK.__getitem__)
    return {"status": overall, "checks": checks}
