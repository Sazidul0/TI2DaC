"""Web UI + JSON API.

Security posture (internal tool):
  * binds to loopback by default; refuses other interfaces unless users/credentials are configured
  * HTTP Basic auth against local users with roles (`ti2dac user add`), or the single
    TI2DAC_WEB_USER / TI2DAC_WEB_PASSWORD admin; put SSO in front for production
  * four-eyes approval: only approvers approve, and never a version they authored
  * state-changing requests must carry a same-origin Origin/Referer (CSRF protection)
  * Jinja autoescaping on; uploads are size-capped and never executed
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt
from markupsafe import Markup
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from .. import __version__, aistatus, attack, health, modelchoice, obs
from ..config import STAGES, Settings, env_file, env_source, set_env_secret
from ..feedback import ARTIFACTS, CATEGORIES, REVIEW_STATES, SEVERITIES, TEST_RESULTS, Store, target_status
from ..llm import LLM, verify_key
from ..render import load_record, rule_filename
from ..sigma_tools import conversion_problem
from ..targets import LLM_TARGET_LABELS, TARGETS
from ..users import Users
from . import jobs as jobs_mod

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_MD = MarkdownIt("commonmark", {"html": False}).enable("table")   # raw HTML in generated docs is escaped
TEMPLATES.env.filters["md"] = lambda s: Markup(_MD.render(s or ""))


def _tok(n) -> str:
    """12345 -> 12.3K, 1234567 -> 1.23M"""
    n = int(n or 0)
    return f"{n / 1e6:.2f}M" if n >= 1_000_000 else f"{n / 1e3:.1f}K" if n >= 1000 else str(n)


TEMPLATES.env.filters["tok"] = _tok

KEY_VARS = {"anthropic": ("ANTHROPIC_API_KEY", "Claude (Anthropic)"), "gemini": ("GEMINI_API_KEY", "Gemini (Google AI Studio)")}
# API keys are URL-safe tokens; anything else (spaces, quotes, newlines) could corrupt or inject into .env
_KEY_RE = re.compile(r"[A-Za-z0-9_\-.]{20,400}")
_LOOPBACK = ("127.0.0.1", "localhost", "::1", "testserver")


class _Security(BaseHTTPMiddleware):
    def __init__(self, app, users: Users, user: str | None, password: str | None, store: Store):
        super().__init__(app)
        self.users, self.user, self.password, self.store = users, user, password, store

    @staticmethod
    def _claimed_user(request: Request) -> str:
        try:
            return base64.b64decode(request.headers["authorization"][6:]).decode().partition(":")[0][:64]
        except Exception:
            return "(unreadable)"

    def _authenticate(self, request: Request) -> tuple[str, str] | None:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return None
        try:
            u, _, p = base64.b64decode(auth[6:]).decode().partition(":")
        except Exception:
            return None
        if self.users.any():
            role = self.users.authenticate(u, p)
            return (u, role) if role else None
        if secrets.compare_digest(u, self.user or "") and secrets.compare_digest(p, self.password or ""):
            return u, "admin"
        return None

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id", "")
        obs.request_id.set(rid if re.fullmatch(r"[A-Za-z0-9_\-]{1,64}", rid) else uuid.uuid4().hex[:16])
        t0, path = time.monotonic(), request.url.path
        client = request.client.host if request.client else ""
        request.state.user, request.state.role = "", ""
        resp = await self._dispatch(request, call_next, client)
        resp.headers["X-Request-ID"] = obs.request_id.get()
        if not path.startswith("/static/") and path != "/healthz":
            obs.event("http.request", logging.WARNING if resp.status_code >= 500 else logging.INFO,
                      method=request.method, path=path, status=resp.status_code, user=request.state.user,
                      client=client, duration_ms=round((time.monotonic() - t0) * 1000))
        return resp

    async def _dispatch(self, request: Request, call_next, client: str):
        if request.url.path == "/healthz":   # for uptime checkers: no login, no details that need one
            return await call_next(request)
        if self.users.any() or (self.user and self.password):
            who = await run_in_threadpool(self._authenticate, request)   # PBKDF2 takes ~0.1s: keep it off the event loop
            if who is None:
                if request.headers.get("authorization"):   # a wrong login, not a browser's first unauthenticated request
                    await run_in_threadpool(self.store.audit, self._claimed_user(request), "auth.failed",
                                            {"client": client, "path": request.url.path}, logging.WARNING)
                return PlainTextResponse("authentication required", 401, {"WWW-Authenticate": 'Basic realm="ti2dac"'})
            request.state.user, request.state.role = who
        else:   # local single-user mode (loopback only, enforced by `ti2dac serve`)
            request.state.user, request.state.role = os.environ.get("USER", "analyst"), "admin"
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin") or request.headers.get("referer")
            if origin and urlparse(origin).netloc != request.headers.get("host"):
                await run_in_threadpool(self.store.audit, request.state.user, "csrf.refused",
                                        {"client": client, "path": request.url.path,
                                         "origin": urlparse(origin).netloc[:200]}, logging.WARNING)
                return PlainTextResponse("cross-origin request refused", 403)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        return resp


def create_app(settings: Settings) -> FastAPI:
    app = FastAPI(title="ti2dac", version=__version__, docs_url=None, redoc_url=None,
                  description="Threat intel → Sigma → multi-SIEM detection packages. HTTP Basic auth when users are configured.")
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    store = Store(settings.db_path)
    app.add_middleware(_Security, users=Users(settings.state_dir), user=os.environ.get("TI2DAC_WEB_USER"),
                       password=os.environ.get("TI2DAC_WEB_PASSWORD"), store=store)
    attack.set_override_dir(settings.state_dir)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        if exc.status_code == 403:   # a signed-in user tried something their role does not allow
            store.audit(getattr(request.state, "user", ""), "access.denied",
                        {"path": request.url.path, "method": request.method, "reason": str(exc.detail)[:200],
                         "role": getattr(request.state, "role", "")}, logging.WARNING)
        return await http_exception_handler(request, exc)
    store.interrupt_running_jobs()   # jobs from a previous process cannot still be running
    jobs = jobs_mod.Jobs(store)
    app.state.jobs = jobs
    key_checks: dict[str, dict] = {}   # provider -> last key check shown on the AI page (never the key)
    model_msgs: dict[str, dict] = {}   # provider -> last model save / list refresh result
    choice_seen = [modelchoice.saved_mtime(settings)]

    @app.middleware("http")
    async def _sync_model_choice(request: Request, call_next):
        """Pick up a model choice saved outside this process (`ti2dac model`, another server worker)."""
        nonlocal settings
        m = modelchoice.saved_mtime(settings)
        if m != choice_seen[0]:
            choice_seen[0], settings = m, modelchoice.reload(settings)
        return await call_next(request)

    def run_dir(run_id: str) -> Path:
        p = store.run_path(run_id)
        path = Path(p) if p else Path(settings.output_dir) / run_id
        if not (path / "run.json").is_file():
            raise HTTPException(404, "unknown run")
        return path

    def rerender(record, path: Path) -> None:
        jobs_mod.rerender(settings, store, record, path)

    def run_lock(run_id: str):
        return jobs_mod.run_lock(settings, run_id)

    def ai_info() -> dict:
        prov = settings.ai.provider
        st = aistatus.provider_status(settings.state_dir, prov)
        return {
            "provider": prov, "enabled": settings.ai.enabled, "state": st.get("state", "ok"),
            "message": st.get("message", ""), "retry_at": st.get("retry_at", ""),
            "wait": aistatus.human_wait(st.get("retry_at", "")) if st.get("retry_at") else "",
            "requests_today": st.get("requests_today", 0), "limit": settings.ai.daily_request_limit,
            "last_success": st.get("last_success", ""), "key": aistatus.key_status(prov),
            "in_today": st.get("input_tokens_today", 0), "out_today": st.get("output_tokens_today", 0),
            "cache_today": st.get("cache_read_tokens_today", 0), "cost_today": st.get("cost_today_usd", 0),
            "in_total": st.get("input_tokens_total", 0), "out_total": st.get("output_tokens_total", 0),
            "cost_total": st.get("cost_total_usd", 0),
            "blocked": aistatus.block_reason(settings.state_dir, prov, settings.ai.daily_request_limit)
            if settings.ai.enabled else "",
            "models": {k: getattr(settings.ai, k).model for k in ("analyze", "generate", "repair", "translate")},
        }

    def ai_blocked() -> str:
        return aistatus.block_reason(settings.state_dir, settings.ai.provider, settings.ai.daily_request_limit) \
            if settings.ai.enabled else ""

    def ctx(request: Request, **kw):
        return {"request": request, "user": request.state.user, "role": request.state.role, "version": __version__,
                "ai_enabled": settings.ai.enabled, "ai": ai_info(), **kw}

    def start_job(fn, kw: dict, label: str, actor: str) -> str:
        return jobs.start(fn, kw, settings, label, actor)

    # ------------------------------------------------------------------ pages
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index(request: Request, deleted: str = ""):
        runs = store.list_runs()[:100]
        for r in runs:   # per-run AI usage and rule counts from the run record
            try:
                data = json.loads((Path(r["path"]) / "run.json").read_text())
            except (OSError, ValueError, TypeError):
                data = {}
            pkgs = data.get("packages") or []
            r["usage"] = data.get("usage") or {}
            r["created_by"] = data.get("created_by") or ""
            r["behaviours"] = len(data.get("behaviours") or [])
            r["rules"] = len(pkgs)
            r["approved"] = sum(p.get("review_status") == "approved" for p in pkgs)
            r["kind"] = (data.get("report") or {}).get("kind", "")
            r["tlp"] = (data.get("report") or {}).get("tlp_effective", "")
        siems = [(TARGETS[t].label, TARGETS[t].language, False) for t in settings.targets if t in TARGETS]
        siems += [(*LLM_TARGET_LABELS.get(t, (t, "")), True) for t in settings.llm_targets]
        return TEMPLATES.TemplateResponse(request, "index.html", ctx(request, runs=runs, jobs=store.list_jobs(5), deleted=deleted,
                                                                     siems=siems))

    @app.post("/runs")
    async def create_run(request: Request, url: str = Form(""), count: int = Form(3), select: str = Form(""),
                         doc_type: str = Form("auto"), file: UploadFile | None = File(None)):
        """Start an analysis from an uploaded report (`file`) or a public `url`. Redirects to the job (`/jobs/{id}`)."""
        raw, filename = None, None
        if file is not None and file.filename:
            raw = await file.read(settings.fetch.max_bytes + 1)
            if len(raw) > settings.fetch.max_bytes:
                raise HTTPException(413, "report too large")
            filename = file.filename
        elif not url.strip():
            raise HTTPException(400, "upload a report or give a URL")
        elif not re.match(r"^https?://", url.strip(), re.IGNORECASE):   # anything else is a path on this server (LFI)
            raise HTTPException(400, "the URL must start with http:// or https://")
        source = filename or url.strip()
        explicit = [x for x in select.replace(" ", "").split(",") if x] or None
        if ai_blocked():
            return RedirectResponse("/ai?blocked=1", 303)

        kw = {"source": source, "raw": raw, "filename": filename, "count": max(1, min(count, 10)), "explicit": explicit,
              "incident": {"incident": True, "threat-intel": False}.get(doc_type), "actor": request.state.user}
        return RedirectResponse(f"/jobs/{start_job(jobs_mod.new_run, kw, source, request.state.user)}", 303)

    @app.get("/jobs/{jid}", response_class=HTMLResponse, include_in_schema=False)
    def job_page(request: Request, jid: str):
        job = store.get_job(jid)
        if job is None:
            raise HTTPException(404, "unknown job")
        if job["status"] == "done" and job["run_id"] and store.run_path(job["run_id"]):   # the run may be deleted
            return RedirectResponse(f"/runs/{job['run_id']}", 303)
        return TEMPLATES.TemplateResponse(request, "job.html", ctx(request, job=job, can_stop=jobs.can_stop(jid)))

    @app.post("/jobs/{jid}/stop")
    def stop_job(request: Request, jid: str):
        """Stop a running job (the user who started it, approvers and admins). Nothing it did not finish is kept."""
        job = store.get_job(jid)
        if job is None:
            raise HTTPException(404, "unknown job")
        if request.state.user != job["actor"] and request.state.role not in ("approver", "admin"):
            raise HTTPException(403, "only the user who started the job, an approver or an admin can stop it")
        if not jobs.stop(jid, request.state.user):
            raise HTTPException(409, "this job is not running in a worker that can be stopped")
        store.audit(request.state.user, "job.stop", {"job_id": jid, "label": job["label"][:200]}, logging.WARNING)
        return RedirectResponse(f"/jobs/{jid}", 303)

    @app.get("/runs/{run_id}", response_class=HTMLResponse, include_in_schema=False)
    def run_page(request: Request, run_id: str, fb: int = 0):
        path = run_dir(run_id)
        notice = store.get_feedback(fb) if fb else None   # outcome of the feedback just submitted
        if notice and notice["run_id"] != run_id:
            notice = None
        record = load_record(path)
        results = store.test_results(run_id)
        status = {p.slug: {q.target: (target_status(results, q.target, p.version)[0] or
                                      (conversion_problem(q.error) if q.error else "not-tested")) for q in p.queries}
                  for p in record.packages}
        return TEMPLATES.TemplateResponse(request, "run.html", ctx(
            request, r=record, status=status, results=results, feedback=store.list_feedback(run_id),
            artifacts=ARTIFACTS, categories=CATEGORIES, severities=SEVERITIES, test_results=TEST_RESULTS,
            review_states=REVIEW_STATES, rule_filename=rule_filename, notice=notice,
            sim_readme={p.slug: (path / "simulations" / p.slug / "README.md").read_text()
                        for p in record.packages if (path / "simulations" / p.slug / "README.md").is_file()},
            ads={p.slug: (path / "documentation" / f"{p.slug}-ads.md").read_text()
                 for p in record.packages if (path / "documentation" / f"{p.slug}-ads.md").is_file()},
        ))

    @app.post("/runs/{run_id}/delete")
    def delete_run(request: Request, run_id: str):
        """Delete a run: its output folder (rules, queries, source report), feedback, test results and the
        lessons learned from it. Admins, or the user who created the run. Cannot be undone."""
        path = run_dir(run_id)
        record = load_record(path)
        if request.state.role != "admin" and request.state.user != record.created_by:
            raise HTTPException(403, "only an admin or the user who created this run can delete it")
        if store.running_jobs_for(run_id):
            raise HTTPException(409, "a job is still working on this run; wait for it or stop it first")
        root = Path(settings.output_dir).resolve()
        if root not in path.resolve().parents:   # the registry's path must not point outside the output folder
            raise HTTPException(409, f"run folder {path} is outside the output folder; delete it by hand")
        with run_lock(run_id):
            store.delete_run(run_id, request.state.user)
            shutil.rmtree(path, ignore_errors=True)
        return RedirectResponse("/?deleted=" + run_id, 303)

    @app.post("/runs/{run_id}/generate")
    def generate_more(request: Request, run_id: str, select: str = Form(...)):
        """Generate rules for more behaviours of a run, e.g. `select=B4,B7`. Runs as a background job."""
        if not settings.ai.enabled:
            raise HTTPException(400, "AI is disabled")
        if ai_blocked():
            return RedirectResponse("/ai?blocked=1", 303)
        path = run_dir(run_id)
        ids = [x.strip().upper() for x in select.split(",") if x.strip()]

        kw = {"run_id": run_id, "path": str(path), "behaviour_ids": ids, "actor": request.state.user}
        return RedirectResponse(f"/jobs/{start_job(jobs_mod.generate_more, kw, f'{run_id}: generate {ids}', request.state.user)}", 303)

    @app.post("/runs/{run_id}/rules/{slug}/feedback")
    def add_feedback(request: Request, run_id: str, slug: str, artifact: str = Form(...), category: str = Form(...),
                     severity: str = Form("medium"), comment: str = Form(""), correction: str = Form(""),
                     target: str = Form("")):
        """Record feedback on a rule; a valid `correction` (full Sigma YAML) becomes the next rule version."""
        from ..pipeline import apply_correction

        path = run_dir(run_id)
        applies = bool(correction.strip()) and artifact == "sigma_rule"
        if applies and ai_blocked():   # applying a correction translates SIEM query gaps with AI
            return RedirectResponse("/ai?blocked=1", 303)
        with run_lock(run_id):
            record = load_record(path)
            pkg = next((p for p in record.packages if p.slug == slug), None)
            if pkg is None:
                raise HTTPException(404, "unknown rule")
            try:
                fid = store.add_feedback(reviewer=request.state.user, run_id=run_id, slug=slug, rule_id=pkg.rule_id,
                                         rule_version=pkg.version, artifact=artifact, category=category, severity=severity,
                                         comment=comment, correction=correction, target=target)
            except ValueError as e:
                raise HTTPException(400, str(e))
            if applies:
                try:
                    new = apply_correction(record, slug, settings, corrected_yaml=correction,
                                           llm=LLM(settings, record.usage, tlp=record.report.tlp_effective) if settings.ai.enabled else None,
                                           actor=request.state.user)
                    store.resolve_feedback(fid, "applied", f"{slug} -> v{new.version}", request.state.user)
                    store.add_lesson(store.get_feedback(fid), new.behaviour.technique_id, new.draft.sigma.logsource.product,
                                     new.draft.sigma.logsource.category or new.draft.sigma.logsource.service,
                                     tlp=record.report.tlp_effective)
                    rerender(record, path)
                except ValueError as e:
                    store.resolve_feedback(fid, "open", f"correction rejected: {e}", request.state.user)
        return RedirectResponse(f"/runs/{run_id}?fb={fid}#{slug}", 303)

    @app.post("/feedback/{fid}/apply")
    def apply_feedback(request: Request, fid: int):
        """Let the AI rewrite the rule from open feedback; the result is a new draft version."""
        fb = store.get_feedback(fid)
        if not fb:
            raise HTTPException(404)
        if fb["status"] != "open":
            raise HTTPException(409, f"feedback #{fid} is already {fb['status']}")
        if not settings.ai.enabled:
            raise HTTPException(400, "AI is disabled; submit a corrected rule instead")
        if ai_blocked():
            return RedirectResponse("/ai?blocked=1", 303)
        path = run_dir(fb["run_id"])
        user = request.state.user
        kw = {"fid": fid, "path": str(path), "actor": user}
        return RedirectResponse(f"/jobs/{start_job(jobs_mod.apply_feedback, kw, f'apply feedback #{fid}', user)}", 303)

    @app.post("/feedback/{fid}/resolve")
    def resolve_feedback(request: Request, fid: int, status: str = Form(...), note: str = Form(""),
                         lesson: int = Form(0)):
        """Close feedback as `applied` (fixed elsewhere), `rejected` or `wontfix`; `lesson=1` keeps the comment as a lesson."""
        fb = store.get_feedback(fid)
        if not fb:
            raise HTTPException(404)
        try:
            store.resolve_feedback(fid, status, note, request.state.user)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if lesson and status == "applied":   # fixed outside the tool, but the advice is still reusable
            record = load_record(run_dir(fb["run_id"]))
            pkg = next((p for p in record.packages if p.slug == fb["slug"]), None)
            if pkg is not None:
                ls = pkg.draft.sigma.logsource
                store.add_lesson(fb, pkg.behaviour.technique_id, ls.product, ls.category or ls.service,
                                 tlp=record.report.tlp_effective)
        return RedirectResponse(f"/runs/{fb['run_id']}#{fb['slug']}", 303)

    @app.post("/runs/{run_id}/rules/{slug}/test")
    def add_test(request: Request, run_id: str, slug: str, target: str = Form(...), result: str = Form(...),
                 fp_count: int = Form(0), evidence: str = Form(""), environment: str = Form("")):
        """Record a lab test or alert disposition for one SIEM target (or `all`)."""
        path = run_dir(run_id)
        with run_lock(run_id):
            record = load_record(path)
            pkg = next((p for p in record.packages if p.slug == slug), None)
            if pkg is None or target not in {q.target for q in pkg.queries} | {"all"}:
                raise HTTPException(400, "unknown rule or target")
            try:
                store.add_test_result(tester=request.state.user, run_id=run_id, slug=slug, rule_version=pkg.version,
                                      target=target, result=result, fp_count=fp_count, evidence=evidence, environment=environment)
            except ValueError as e:
                raise HTTPException(400, str(e))
            rerender(record, path)
        return RedirectResponse(f"/runs/{run_id}#{slug}", 303)

    @app.post("/runs/{run_id}/rules/{slug}/review")
    def set_review(request: Request, run_id: str, slug: str, status: str = Form(...), note: str = Form("")):
        """Set the review status. Approval needs the approver role and a reviewer other than the author."""
        from ..pipeline import review_problem
        from ..sigma_tools import set_status

        if status not in REVIEW_STATES:
            raise HTTPException(400, "bad status")
        path = run_dir(run_id)
        with run_lock(run_id):
            record = load_record(path)
            pkg = next((p for p in record.packages if p.slug == slug), None)
            if pkg is None:
                raise HTTPException(404)
            if "approved" in (status, pkg.review_status) and request.state.role not in ("approver", "admin"):
                raise HTTPException(403, "only users with the approver role can approve rules or change an approved rule")
            problem = review_problem(pkg, status, request.state.user)
            if problem:
                raise HTTPException(409, problem)
            pkg.review_status = status  # type: ignore[assignment]
            pkg.rule_yaml = set_status(pkg.rule_yaml, "test" if status == "approved" else "experimental")
            store.set_review(run_id, slug, status, request.state.user, note)
            rerender(record, path)
        return RedirectResponse(f"/runs/{run_id}#{slug}", 303)

    @app.get("/runs/{run_id}/download")
    def download(run_id: str):
        """Shareable package (zip): rules, queries, simulations, docs. Never includes source/ or evidence/."""
        path = run_dir(run_id)
        tmp = Path(settings.state_dir) / "exports"
        tmp.mkdir(parents=True, exist_ok=True)
        # The shareable package never includes source/ (original report, redaction map) or evidence/ (raw logs),
        # whatever the document type: TLP-marked threat intel can be just as restricted as an incident report.
        import zipfile

        fd, name = tempfile.mkstemp(suffix=".zip", dir=tmp)   # one file per request: downloads may overlap
        archive = Path(name)
        try:
            with os.fdopen(fd, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
                for f in sorted(path.rglob("*")):
                    rel = f.relative_to(path)
                    if f.is_file() and rel.parts[0] not in ("source", "evidence"):
                        zf.write(f, rel.as_posix())
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
        return FileResponse(archive, filename=f"{run_id}.zip", media_type="application/zip",
                            background=BackgroundTask(archive.unlink, missing_ok=True))

    @app.get("/runs/{run_id}/files/{rel:path}")
    def raw_file(run_id: str, rel: str):
        """One generated file of a run as plain text, e.g. `rules/rule-001-....yml`. Never source/ or evidence/."""
        base = run_dir(run_id).resolve()
        target = (base / rel).resolve()
        if base not in target.parents or not target.is_file() or target.relative_to(base).parts[0] in ("source", "evidence"):
            raise HTTPException(404)
        return PlainTextResponse(target.read_text(errors="replace"))

    @app.get("/ai", response_class=HTMLResponse, include_in_schema=False)
    def ai_page(request: Request, blocked: int = 0):
        keys = []
        for prov, (var, label) in KEY_VARS.items():
            val = os.environ.get(var, "")
            keys.append({"provider": prov, "label": label, "var": var, "source": env_source(var),
                         "tail": f"…{val[-4:]}" if len(val) >= 12 else "", "active": prov == settings.ai.provider,
                         "check": key_checks.get(prov)})
        insecure = request.url.scheme == "http" and (request.url.hostname or "") not in _LOOPBACK
        choice = modelchoice.read_model_choice(settings.state_dir)
        blocks = []
        for prov, label in modelchoice.PROVIDER_LABELS.items():
            cur = modelchoice.current(settings, prov)
            main = cur["generate"]
            blocks.append({"provider": prov, "label": label, "active": prov == settings.ai.provider,
                           "models": modelchoice.available(settings, prov), "main": main,
                           "stages": {k: ("" if v == main else v) for k, v in cur.items()},
                           "effort": {k: getattr(settings.ai, k).effort for k in STAGES},
                           "fetched_at": modelchoice.fetched_at(settings, prov), "key_set": bool(os.environ.get(KEY_VARS[prov][0])),
                           "msg": model_msgs.get(prov)})
        return TEMPLATES.TemplateResponse(request, "ai.html", ctx(
            request, just_blocked=bool(blocked), keys=keys, env_path=str(env_file().resolve()), insecure=insecure,
            model_blocks=blocks, model_locks=modelchoice.env_locks(), model_choice=choice, stages=STAGES))

    @app.post("/ai/models")
    async def ai_models(request: Request):
        """Choose the provider and the model for every stage (admins only). Applies to jobs started from now on."""
        nonlocal settings
        if request.state.role != "admin":
            raise HTTPException(403, "only admins can change the AI model")
        form = await request.form()
        provider, main = str(form.get("provider", "")), str(form.get("model", ""))
        models = {k: str(form.get(f"stage_{k}") or main) for k in STAGES}
        try:
            settings = modelchoice.choose(settings, provider, models, request.state.user)
        except ValueError as e:
            model_msgs[provider] = {"ok": False, "message": str(e), "by": request.state.user, "at": datetime.now().strftime("%H:%M:%S")}
            return RedirectResponse("/ai#models", 303)
        store.audit(request.state.user, "ai.models.set", {"provider": provider, "models": models})
        msg = f"Saved: {modelchoice.PROVIDER_LABELS[provider]} is the active provider. New jobs use it; running jobs finish as they started."
        if modelchoice.env_locks():
            msg += f" Note: {', '.join(modelchoice.env_locks())} in the server environment still override this choice."
        model_msgs.clear()
        model_msgs[provider] = {"ok": True, "message": msg, "by": request.state.user, "at": datetime.now().strftime("%H:%M:%S")}
        return RedirectResponse("/ai#models", 303)

    @app.post("/ai/models/refresh")
    def ai_models_refresh(request: Request, provider: str = Form(...)):
        """Fetch the models the provider's key can use (no tokens). Admins only."""
        if request.state.role != "admin":
            raise HTTPException(403, "only admins can refresh the model list")
        if provider not in KEY_VARS:
            raise HTTPException(400, "unknown provider")
        ok, msg = modelchoice.refresh(settings, provider)
        model_msgs[provider] = {"ok": ok, "message": msg, "by": request.state.user, "at": datetime.now().strftime("%H:%M:%S")}
        return RedirectResponse("/ai#models", 303)

    @app.post("/ai/key")
    def ai_key(request: Request, provider: str = Form(...), action: str = Form(...), key: str = Form("")):
        """Save, test or remove a provider API key (admins only). Saved to the server's .env, never to the database."""
        nonlocal settings
        if request.state.role != "admin":
            raise HTTPException(403, "only admins can manage API keys")
        if provider not in KEY_VARS or action not in ("save", "test", "remove"):
            raise HTTPException(400, "unknown provider or action")
        var, user = KEY_VARS[provider][0], request.state.user
        key = key.strip()
        if action == "save":
            if not _KEY_RE.fullmatch(key):
                raise HTTPException(400, "that does not look like an API key (20-400 letters, digits, '-', '_' or '.')")
            set_env_secret(var, key)
            store.audit(user, "ai.key.set", {"provider": provider, "key_tail": key[-4:]})
            ok, msg = verify_key(provider, key)
            msg = ("Saved. " if ok else "Saved, but the check failed: ") + msg
            if ok:   # the model picker can now offer what this key can use
                listed, _ = modelchoice.refresh(settings, provider)
                msg += " Choose its model under Model below." if listed else ""
            active = settings.ai.provider
            if ok and provider != active and aistatus.key_status(active) == "not configured" and not modelchoice.env_locks():
                # The active provider cannot run at all; a working key for the other one should just work.
                try:
                    settings = modelchoice.choose(settings, provider, modelchoice.current(settings, provider), user)
                except ValueError as e:
                    msg += f" It was not made the active provider: {e}"
                else:
                    store.audit(user, "ai.models.set", {"provider": provider, "models": modelchoice.current(settings, provider),
                                                        "reason": f"{active} has no key"})
                    msg += (f" {KEY_VARS[provider][1]} is now the active provider, because {KEY_VARS[active][1]} has no key."
                            " Change it under Model below.")
        elif action == "test":
            if not os.environ.get(var):
                raise HTTPException(400, f"no {var} to test")
            ok, msg = verify_key(provider, os.environ[var])
        else:
            if env_source(var) != ".env":
                raise HTTPException(409, f"{var} is not set in {env_file()}; remove it where it is defined")
            set_env_secret(var, None)
            store.audit(user, "ai.key.remove", {"provider": provider})
            ok, msg = None, "Removed from .env."
        if provider == "gemini" and os.environ.get("GOOGLE_API_KEY") and os.environ.get("GOOGLE_API_KEY") != os.environ.get(var):
            msg += " Note: GOOGLE_API_KEY is also set and the Google client prefers it."
        if ok and aistatus.provider_status(settings.state_dir, provider).get("state") == "auth_error":
            aistatus.reset(settings.state_dir, provider)   # the pause was caused by the old key
            msg += " The auth-error pause was cleared."
        key_checks[provider] = {"ok": ok, "message": msg, "by": user, "at": datetime.now().strftime("%H:%M:%S")}
        return RedirectResponse("/ai#keys", 303)

    @app.post("/ai/reset")
    def ai_reset(request: Request):
        """Clear an AI pause after fixing its cause (admins only)."""
        if request.state.role != "admin":
            raise HTTPException(403, "only admins can clear an AI pause")
        aistatus.reset(settings.state_dir, settings.ai.provider)
        store.audit(request.state.user, "ai.reset", {"provider": settings.ai.provider})
        return RedirectResponse("/ai", 303)

    @app.get("/healthz")
    def healthz():
        """Database, disk space, AI provider and stuck jobs. No login needed; 503 when a check fails."""
        result = health.check(settings, store)
        return JSONResponse(result, status_code=503 if result["status"] == "fail" else 200)

    @app.get("/api/ai-status")
    def api_ai_status():
        """Provider, pause state, request counts and token usage. The key itself is never returned."""
        return ai_info()

    @app.get("/feedback", response_class=HTMLResponse, include_in_schema=False)
    def feedback_page(request: Request, status: str | None = None):
        return TEMPLATES.TemplateResponse(request, "feedback.html", ctx(
            request, items=store.list_feedback(status=status), lessons=store.list_lessons(),
            audit=store.audit_entries(100), categories=CATEGORIES, status=status or ""))

    @app.post("/lessons/{lid}/toggle")
    def toggle_lesson(request: Request, lid: int, active: int = Form(...)):
        """Enable (`active=1`) or disable (`active=0`) a lesson."""
        store.set_lesson_active(lid, bool(active), request.state.user)
        return RedirectResponse("/feedback#lessons", 303)

    @app.get("/feedback/export.jsonl")
    def export_feedback():
        """All feedback as JSON Lines, with the current rule attached (evaluation dataset)."""
        tmp = Path(settings.state_dir) / "exports"
        tmp.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(suffix=".jsonl", dir=tmp)   # one file per request: exports may overlap
        os.close(fd)
        out = Path(name)
        try:
            store.export_jsonl(out)
        except BaseException:
            out.unlink(missing_ok=True)
            raise
        return FileResponse(out, filename="feedback.jsonl", media_type="application/x-ndjson",
                            background=BackgroundTask(out.unlink, missing_ok=True))

    @app.get("/api", response_class=HTMLResponse, include_in_schema=False)
    def api_page(request: Request):
        spec = app.openapi()
        schemas = spec.get("components", {}).get("schemas", {})
        groups: dict[str, list] = {"json": [], "actions": [], "files": []}
        for path, ops in spec["paths"].items():
            for method, op in ops.items():
                fields = [{"name": p["name"], "where": p["in"], "required": p.get("required", False),
                           "type": p.get("schema", {}).get("type", "")} for p in op.get("parameters", [])]
                for body in (op.get("requestBody", {}).get("content") or {}).values():
                    sch = schemas.get(body.get("schema", {}).get("$ref", "").rsplit("/", 1)[-1], {})
                    for name, prop in sch.get("properties", {}).items():
                        typ = prop.get("type") or next((a.get("format") or a.get("type") for a in prop.get("anyOf", [])
                                                        if a.get("type") != "null"), "")
                        fields.append({"name": name, "where": "file" if typ == "binary" else "form",
                                       "required": name in sch.get("required", []), "type": typ})
                group = "json" if path.startswith("/api/") else "actions" if method == "post" else "files"
                groups[group].append({"method": method.upper(), "path": path, "fields": fields,
                                      "doc": (op.get("description") or op.get("summary") or "").strip()})
        runs, jobs = store.list_runs(), store.list_jobs(1)
        samples = {"run_id": runs[0]["run_id"] if runs else "", "jid": jobs[0]["id"] if jobs else ""}
        return TEMPLATES.TemplateResponse(request, "api.html", ctx(
            request, groups=groups, samples=samples, base=str(request.base_url).rstrip("/"),
            needs_auth=Users(settings.state_dir).any() or bool(os.environ.get("TI2DAC_WEB_PASSWORD"))))

    @app.get("/api/docs", include_in_schema=False)
    def api_docs_redirect():
        return RedirectResponse("/api", 307)

    # ------------------------------------------------------------------ JSON API (SOAR / CI integration)
    @app.get("/api/runs")
    def api_runs():
        """All runs, newest first."""
        return store.list_runs()

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str):
        """The full run record: report metadata, behaviours, rules, queries, usage and warnings."""
        return JSONResponse(load_record(run_dir(run_id)).model_dump(mode="json"))

    @app.get("/api/jobs/{jid}")
    def api_job(jid: str):
        """Background job status and progress log; `run_id` is set when it is done."""
        job = store.get_job(jid)
        if job is None:
            raise HTTPException(404)
        return job

    return app
