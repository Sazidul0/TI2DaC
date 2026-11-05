"""Web jobs in worker processes (jobs.isolation: process): a runaway report must not take the server with it."""
from __future__ import annotations

import logging
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

# The hex-dump filter that froze the whole web server on a real PDF (exponential backtracking).
_RUNAWAY = re.compile(r"^(?:\s*(?:0x)?[0-9a-f]{2,}[\s:,]*){8,}$", re.I)


# Job functions are imported by the worker by name, so they live at module level.
def _runaway_regex(settings, store, progress):
    progress("matching")
    _RUNAWAY.match("ab" * 40 + "!")
    return "never"


def _eat_memory(settings, store, progress):
    progress("allocating")
    return str(len(bytearray(64 * 1024 ** 3)))


def _memory_cap(settings, store, progress):
    import resource

    return str(resource.getrlimit(resource.RLIMIT_AS)[0])


def _crash(settings, store, progress):
    os._exit(3)


def _client(settings):
    from ti2dac.web.app import create_app

    return TestClient(create_app(settings))


def _wait(client, jid: str, *, until=lambda j: j["status"] != "running", timeout: float = 60) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        job = client.get(f"/api/jobs/{jid}").json()
        if until(job):
            return job
        time.sleep(0.1)
    raise AssertionError(f"job {jid}: {client.get(f'/api/jobs/{jid}').json()}")


def _start(client, fn, settings) -> str:
    return client.app.state.jobs.start(fn, {}, settings, f"test {fn.__name__}", "alice")


@pytest.fixture
def worker_settings(settings, monkeypatch):
    settings.jobs.isolation = "process"
    settings.ai.enabled = False
    monkeypatch.setenv("USER", "alice")   # local single-user mode
    return settings


def test_runaway_job_leaves_the_server_responsive_and_can_be_stopped(worker_settings):
    client = _client(worker_settings)
    jid = _start(client, _runaway_regex, worker_settings)
    _wait(client, jid, until=lambda j: "matching" in j["log"])
    t0 = time.monotonic()
    assert client.get("/healthz").status_code in (200, 503) and time.monotonic() - t0 < 2
    assert "Stop job" in client.get(f"/jobs/{jid}").text
    r = client.post(f"/jobs/{jid}/stop", follow_redirects=False)
    assert r.status_code == 303
    job = client.get(f"/api/jobs/{jid}").json()
    assert job["status"] == "failed" and job["error"] == "stopped by alice"
    assert client.post(f"/jobs/{jid}/stop", follow_redirects=False).status_code == 409
    client.app.state.jobs.shutdown()


def test_job_running_past_its_time_limit_is_stopped(worker_settings):
    worker_settings.jobs.timeout_minutes = 0.05   # 3 s
    client = _client(worker_settings)
    job = _wait(client, _start(client, _runaway_regex, worker_settings))
    assert job["status"] == "failed" and "jobs.timeout_minutes" in job["error"]
    client.app.state.jobs.shutdown()


def test_memory_blowup_fails_only_the_job(worker_settings):
    worker_settings.jobs.memory_mb = 2048
    client = _client(worker_settings)
    job = _wait(client, _start(client, _eat_memory, worker_settings))
    assert job["status"] == "failed" and "ran out of memory" in job["error"]
    job = _wait(client, _start(client, _memory_cap, worker_settings))   # the cap is the worker's own
    assert job["status"] == "done" and job["run_id"] == str(2048 * 1024 ** 2)
    client.app.state.jobs.shutdown()


def test_crashed_worker_marks_its_job_failed(worker_settings):
    client = _client(worker_settings)
    job = _wait(client, _start(client, _crash, worker_settings))
    assert job["status"] == "failed" and "exit code 3" in job["error"]
    client.app.state.jobs.shutdown()


def test_real_run_in_a_worker_logs_through_the_server(worker_settings, report_file, caplog):
    client = _client(worker_settings)
    with caplog.at_level(logging.INFO):
        r = client.post("/runs", files={"file": (report_file.name, report_file.read_bytes(), "text/markdown")},
                        follow_redirects=False)
        jid = r.headers["location"].rsplit("/", 1)[1]
        job = _wait(client, jid)
        client.app.state.jobs.shutdown()   # stops the log listener after the worker's last records
    assert job["status"] == "done" and job["run_id"], job
    assert client.get(f"/runs/{job['run_id']}").status_code == 200
    started = [rec for rec in caplog.records if getattr(rec, "event", "") == "job.start"]
    assert started and started[0].job_id == jid and started[0].process != os.getpid()
