"""Background jobs of the web UI: what they do, and where they run.

By default every job runs in its own worker process (`jobs.isolation: process`). A report that makes the
pipeline hang, spin or blow up its memory then only takes down that worker: the UI keeps answering, the job
can be stopped, and it is stopped after `jobs.timeout_minutes`. (A runaway regex holds the GIL, which froze
the whole server when jobs were threads.) State lives in SQLite and run folders, which both sides share;
run.json edits are serialised with a file lock. Workers log through the server's handlers.
"""
from __future__ import annotations

import logging
import logging.handlers
import multiprocessing
import os
import re
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path

from .. import attack, obs, pipeline, wazuh
from ..config import Settings
from ..feedback import Store
from ..ingest import IngestError
from ..llm import LLM, LLMError
from ..locks import file_lock
from ..render import load_record, render

Progress = Callable[[str], None]


# --------------------------------------------------------------------------- run.json under concurrency
def run_lock(settings: Settings, run_id: str):
    """Serialises load-modify-rerender of one run.json (requests, job threads and job workers)."""
    return file_lock(Path(settings.state_dir) / "locks" / (re.sub(r"[^\w.-]", "_", run_id) + ".lock"))


def rerender(settings: Settings, store: Store, record, path: Path) -> None:
    render(record, path, test_results=store.test_results(record.run_id))
    store.register_run(record, str(path))


def snapshot(record) -> dict:
    return {"packages": {p.slug: p.model_dump_json() for p in record.packages},
            "usage": record.usage.model_dump(), "warnings": list(record.warnings)}


def _add_delta(now, mine, before):
    """now + (mine - before) for counters, recursively; other values: the job's."""
    if isinstance(mine, bool) or not isinstance(mine, (int, float, dict)):
        return mine
    if isinstance(mine, dict):
        now, before = now if isinstance(now, dict) else {}, before if isinstance(before, dict) else {}
        return {k: _add_delta(now.get(k, 0), mine[k], before.get(k, 0)) if k in mine else now[k]
                for k in {**now, **mine}}
    return (now if isinstance(now, (int, float)) else 0) + mine - (before if isinstance(before, (int, float)) else 0)


def merge_meanwhile(settings: Settings, record, path: Path, before: dict) -> None:
    """A job's record was loaded minutes ago. Keep what happened on disk while it ran: approvals, reviews and
    corrections of rules the job did not change, rules another job added, chains an analyst defined, and
    the other job's AI usage. Existing rules keep their slugs; the job's new rules get the next free ones.
    Call with the run lock held."""
    disk = load_record(path)
    old = before["packages"]
    current = {p.slug: p for p in disk.packages}
    kept = []
    for p in record.packages:
        if p.slug not in old:
            continue   # the job's new rules go after everything on disk
        now = current.get(p.slug)
        kept.append(now if now is not None and p.model_dump_json() == old[p.slug] != now.model_dump_json() else p)
    others = [p for p in disk.packages if p.slug not in old]   # added by another job meanwhile
    have = {p.behaviour.id for p in kept + others}
    mine = []
    for p in record.packages:
        if p.slug in old:
            continue
        if p.behaviour.id in have:   # two jobs generated the same behaviour: the first one stays
            record.warnings.append(f"{p.behaviour.id}: generated twice at the same time; kept the earlier rule")
            continue
        have.add(p.behaviour.id)
        mine.append(p)
    used, n = {p.slug for p in kept + others}, len(kept) + len(others)
    for p in mine:   # a concurrent job numbered its rules from the same start
        n += 1
        while f"rule-{n:03d}" in used:
            n += 1
        p.slug = f"rule-{n:03d}"
        used.add(p.slug)
    record.packages = kept + others + mine
    record.chains = disk.chains   # jobs only rebuild chains; definitions come from people
    record.warnings = list(dict.fromkeys(disk.warnings + [w for w in record.warnings if w not in before["warnings"]]))
    record.usage = type(record.usage).model_validate(
        _add_delta(disk.usage.model_dump(), record.usage.model_dump(), before["usage"]))
    record.usage.unpriced_models = sorted({*disk.usage.unpriced_models, *record.usage.unpriced_models})
    wazuh.resolve_slot_collisions(record.packages)
    pipeline.rebuild_chains(record, settings)   # chains embed their steps' rule YAML


# --------------------------------------------------------------------------- the jobs
def new_run(settings: Settings, store: Store, progress: Progress, *, source: str, raw: bytes | None,
            filename: str | None, count: int, explicit: list[str] | None, incident: bool | None, actor: str) -> str:
    record, loaded = pipeline.run(source, settings, count=count, explicit=explicit, raw=raw, filename=filename,
                                  store=store, progress=progress, actor=actor, incident=incident)
    path = Path(settings.output_dir) / record.run_id
    render(record, path, raw=loaded.raw, filename=loaded.filename, test_results=store.test_results(record.run_id),
           redaction_map=loaded.redaction_map, embedded_events=loaded.embedded_events)
    store.register_run(record, str(path))
    store.audit(actor, "run.create", {"run_id": record.run_id, "source": source})
    return record.run_id


def generate_more(settings: Settings, store: Store, progress: Progress, *, run_id: str, path: str,
                  behaviour_ids: list[str], actor: str) -> str:
    record = load_record(Path(path))
    before = snapshot(record)
    pipeline.check_tlp_for_run(record, settings)
    pipeline.generate(record, settings, LLM(settings, record.usage, tlp=record.report.tlp_effective), store, progress,
                      behaviour_ids=behaviour_ids, actor=actor)
    with run_lock(settings, run_id):
        merge_meanwhile(settings, record, Path(path), before)
        rerender(settings, store, record, Path(path))
    return run_id


def apply_feedback(settings: Settings, store: Store, progress: Progress, *, fid: int, path: str, actor: str) -> str:
    fb = store.get_feedback(fid)
    record = load_record(Path(path))
    before = snapshot(record)
    text = f"[{fb['category']}] {fb['comment']}" + (f" (SIEM: {fb['target']})" if fb["target"] else "")
    new = pipeline.apply_correction(record, fb["slug"], settings, feedback_text=text,
                                    llm=LLM(settings, record.usage, tlp=record.report.tlp_effective),
                                    progress=progress, actor=actor)
    store.resolve_feedback(fid, "applied", f"{fb['slug']} -> v{new.version} (AI)", actor)
    store.add_lesson(fb, new.behaviour.technique_id, new.draft.sigma.logsource.product,
                     new.draft.sigma.logsource.category or new.draft.sigma.logsource.service,
                     tlp=record.report.tlp_effective)
    with run_lock(settings, fb["run_id"]):
        merge_meanwhile(settings, record, Path(path), before)
        rerender(settings, store, record, Path(path))
    return fb["run_id"]


# --------------------------------------------------------------------------- running one
def execute(jid: str, fn: Callable[..., str], kw: dict, settings: Settings, store: Store, label: str, actor: str) -> None:
    """Run one job to its end and record the outcome; never raises."""
    def progress(msg: str) -> None:
        try:
            store.job_log(jid, msg)
        except Exception:   # a missed progress line must not fail a long AI job
            obs.log.exception("job %s: cannot log progress", jid)

    t0, status, run_id, error = time.monotonic(), "done", None, None
    try:
        obs.job_id.set(jid)
        obs.event("job.start", label=label[:200], actor=actor)
        run_id = fn(settings, store, progress, **kw)
    except (LLMError, ValueError, IngestError) as e:
        status, error = "failed", str(e)
    except MemoryError:
        status, error = "failed", (f"ran out of memory (jobs.memory_mb = {settings.jobs.memory_mb}); "
                                   "the report is probably too large or malformed")
    except Exception as e:  # surface unexpected failures to the operator
        status, error = "failed", f"{type(e).__name__}: {e}"
        obs.log.exception("job %s crashed", jid)
        progress(traceback.format_exc(limit=3))
    for attempt in range(3):   # a job left "running" looks stuck forever
        try:
            store.job_finish(jid, status, run_id=run_id, error=error)
            break
        except Exception:
            obs.log.exception("job %s: cannot record its end (attempt %d)", jid, attempt + 1)
            time.sleep(1)
    try:
        obs.event("job.finish", logging.WARNING if status == "failed" else logging.INFO, status=status,
                  run_id=run_id or "", error=(error or "")[:500], duration_s=round(time.monotonic() - t0, 1))
    except Exception:
        obs.log.exception("job %s: cannot log its end", jid)


class _Stamp(logging.Filter):
    """The server formats the worker's records; the run/job ids are context variables of this process."""

    def filter(self, record: logging.LogRecord) -> bool:
        for var in (obs.run_id, obs.job_id):
            if var.get() and not hasattr(record, var.name):
                setattr(record, var.name, var.get())
        return True


def _worker(jid: str, fn: Callable[..., str], kw: dict, settings: Settings, label: str, actor: str,
            log_queue, parent: int) -> None:
    """Entry point of a job's worker process."""
    if settings.jobs.memory_mb > 0:   # a decompression bomb fails this job with MemoryError, not the host
        try:
            import resource

            cap = settings.jobs.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        except (ImportError, ValueError, OSError):
            pass

    def orphaned() -> None:   # the server was killed: do not keep spending AI calls for nobody
        while os.getppid() == parent:
            time.sleep(2)
        os._exit(1)

    threading.Thread(target=orphaned, daemon=True).start()
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.handlers.QueueHandler(log_queue)
    handler.addFilter(_Stamp())
    root.addHandler(handler)
    root.setLevel(getattr(logging, settings.log.level.upper(), logging.INFO))
    for noisy in ("httpx", "httpx2", "httpcore", "anthropic", "google_genai", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    attack.set_override_dir(settings.state_dir)
    execute(jid, fn, kw, settings, Store(settings.db_path), label, actor)


class _Forward(logging.Handler):
    """Hands a worker's record to this process's logging, so it reaches the same file/syslog/stderr."""

    def emit(self, record: logging.LogRecord) -> None:
        logging.getLogger(record.name).handle(record)


class Jobs:
    """Starts, watches and stops background jobs. State is persisted so it survives page reloads and restarts."""

    def __init__(self, store: Store):
        self.store = store
        self._procs: dict[str, multiprocessing.process.BaseProcess] = {}
        self._stopped: dict[str, str] = {}   # job id -> who stopped it
        self._lock = threading.Lock()
        self._mp = multiprocessing.get_context("spawn")   # fork would copy the server's threads' locks
        self._queue = None
        self._listener: logging.handlers.QueueListener | None = None

    def start(self, fn: Callable[..., str], kw: dict, settings: Settings, label: str, actor: str) -> str:
        """`fn(settings, store, progress, **kw) -> run_id` must be a module-level function (workers import it)."""
        jid = uuid.uuid4().hex[:12]
        self.store.job_create(jid, label, actor)
        if settings.jobs.isolation != "process":
            threading.Thread(target=execute, args=(jid, fn, kw, settings, self.store, label, actor), daemon=True).start()
            return jid
        with self._lock:
            if self._listener is None:
                self._queue = self._mp.Queue()
                self._listener = logging.handlers.QueueListener(self._queue, _Forward())
                self._listener.start()
            proc = self._mp.Process(target=_worker, name=f"ti2dac-job-{jid}", daemon=True,
                                    args=(jid, fn, kw, settings, label, actor, self._queue, os.getpid()))
            proc.start()
            self._procs[jid] = proc
        threading.Thread(target=self._watch, args=(jid, proc, settings.jobs.timeout_minutes * 60), daemon=True).start()
        return jid

    def can_stop(self, jid: str) -> bool:
        with self._lock:
            proc = self._procs.get(jid)
        return proc is not None and proc.is_alive()

    def stop(self, jid: str, by: str) -> bool:
        with self._lock:
            proc = self._procs.get(jid)
            if proc is None or not proc.is_alive():
                return False
            self._stopped[jid] = by
        self._kill(proc)
        job = self.store.get_job(jid)
        if job is not None and job["status"] == "running":   # recorded now, so the page shows it at once
            self.store.job_log(jid, f"stopped by {by}")
            self.store.job_finish(jid, "failed", error=f"stopped by {by}")
        return True

    @staticmethod
    def _kill(proc) -> None:
        proc.terminate()   # SIGTERM ends the worker even while a regex holds its GIL
        proc.join(5)
        if proc.is_alive():
            proc.kill()
            proc.join(5)

    def _watch(self, jid: str, proc, timeout_s: float) -> None:
        proc.join(timeout_s)
        reason = ""
        if proc.is_alive():
            self._kill(proc)
            reason = f"stopped after {timeout_s / 60:g} minutes (jobs.timeout_minutes)"
        with self._lock:
            self._procs.pop(jid, None)
            by = self._stopped.pop(jid, None)
        if by is not None:
            reason = f"stopped by {by}"
        elif not reason and proc.exitcode:
            reason = f"the job's worker process ended unexpectedly (exit code {proc.exitcode})"
            if proc.exitcode == -9:
                reason += "; the system probably ran out of memory"
        try:
            job = self.store.get_job(jid)
            if job is not None and job["status"] == "running":   # the worker could not record its own end
                self.store.job_log(jid, reason or "the job's worker process ended without a result")
                self.store.job_finish(jid, "failed", error=reason or "the job's worker process ended without a result")
            obs.event("job.stopped" if reason else "job.exit", logging.WARNING if reason else logging.DEBUG,
                      job_id=jid, reason=reason, exitcode=proc.exitcode)
        except Exception:
            obs.log.exception("job %s: cannot record how its worker ended", jid)

    def shutdown(self) -> None:
        with self._lock:
            procs = list(self._procs.values())
        for p in procs:
            self._kill(p)
        if self._listener is not None:
            self._listener.stop()
