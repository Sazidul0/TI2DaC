"""Regression tests for web UI / ingestion hardening (no API calls)."""
from __future__ import annotations

import http.server
import io
import socket
import sqlite3
import threading
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ti2dac import ingest, pipeline
from ti2dac.config import FetchConfig
from ti2dac.feedback import Store
from ti2dac.render import load_record, render
from ti2dac.users import Users

from .conftest import FakeLLM

PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def _run(settings, report_file, monkeypatch, actor="alice"):
    fake = FakeLLM(settings)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a, **k: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, actor=actor)
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename)
    store.register_run(record, str(out))
    return record, out


def _client(settings):
    from ti2dac.web.app import create_app

    return TestClient(create_app(settings))


def _wait_job(client, jid: str) -> dict:
    for _ in range(100):
        job = client.get(f"/api/jobs/{jid}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {jid} still running")


# --------------------------------------------------------------------------- web: ingestion source
@pytest.mark.parametrize("url", ["/etc/passwd", "~/.ssh/id_rsa", "file:///etc/passwd", ".env"])
def test_web_run_refuses_local_paths(settings, url):
    client = _client(settings)
    r = client.post("/runs", data={"url": url}, follow_redirects=False)
    assert r.status_code == 400 and "http" in r.json()["detail"]
    assert client.get("/api/jobs/x").status_code == 404 and not Store(settings.db_path).list_jobs()


# --------------------------------------------------------------------------- auth
def test_successful_login_is_cached_and_password_change_invalidates_it(settings, monkeypatch):
    import ti2dac.users as users_mod

    calls = []
    real = users_mod.verify_password
    monkeypatch.setattr(users_mod, "verify_password", lambda p, h: calls.append(1) or real(p, h))
    u = Users(settings.state_dir)
    u.add("dave", "first long password", "analyst")
    assert [u.authenticate("dave", "first long password") for _ in range(5)] == ["analyst"] * 5
    assert len(calls) == 1
    assert u.authenticate("dave", "wrong password") is None and len(calls) == 2   # misses are never cached
    u.add("dave", "second long password", "approver")
    assert u.authenticate("dave", "first long password") is None
    assert u.authenticate("dave", "second long password") == "approver"


def test_wrong_password_is_still_401_and_audited(settings):
    Users(settings.state_dir).add("dave", "first long password", "analyst")
    client = _client(settings)
    assert client.get("/", auth=("dave", "not the password")).status_code == 401
    assert client.get("/", auth=("dave", "first long password")).status_code == 200
    assert [a["action"] for a in Store(settings.db_path).audit_entries()].count("auth.failed") == 1


# --------------------------------------------------------------------------- hostile documents
def _docx(pad: int) -> bytes:
    import docx

    b = io.BytesIO()
    docx.Document().save(b)
    zin, out = zipfile.ZipFile(io.BytesIO(b.getvalue())), io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for it in zin.infolist():
            data = zin.read(it.filename)
            if it.filename == "word/document.xml":
                i = data.index(b"<w:body>") + len(b"<w:body>")
                data = data[:i] + b"<w:p><w:r><w:t>hello world</w:t></w:r></w:p>" + b"<w:p/>" * pad + data[i:]
            zo.writestr(it, data)
    return out.getvalue()


def test_docx_bomb_is_refused_before_parsing(monkeypatch):
    monkeypatch.setattr(ingest, "_DOCX_MAX_XML", 1024 * 1024)
    assert "hello world" in ingest._docx_to_text(_docx(10))[0]
    raw = _docx(400_000)   # ~2.4 MB of XML from a few KB upload
    assert len(raw) < 100_000
    with pytest.raises(ingest.IngestError, match="zip bomb"):
        ingest._docx_to_text(raw)


def _pdf(pages: int) -> bytes:
    from pypdf import PdfWriter

    w, b = PdfWriter(), io.BytesIO()
    for _ in range(pages):
        w.add_blank_page(width=200, height=200)
    w.write(b)
    return b.getvalue()


def test_pdf_extraction_stops_at_page_cap_and_time_budget(monkeypatch):
    monkeypatch.setattr(ingest, "_PDF_MAX_PAGES", 2)
    text, _ = ingest._pdf_to_text(_pdf(5))
    assert "[page 2]" in text and "[page 3]" not in text and "stopped at page 2 of 5: 2-page limit" in text
    monkeypatch.setattr(ingest, "_PDF_MAX_PAGES", 500)
    monkeypatch.setattr(ingest, "_PDF_BUDGET_S", -1)
    assert "time limit" in ingest._pdf_to_text(_pdf(5))[0]


# --------------------------------------------------------------------------- URL fetching
def test_slow_drip_download_hits_overall_deadline(monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()

    def drip():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
        try:
            for _ in range(20):
                c.sendall(b"x")
                time.sleep(0.2)
        except OSError:
            pass
        c.close()

    threading.Thread(target=drip, daemon=True).start()
    monkeypatch.setattr(ingest, "_check_host", lambda h, cfg: None)
    monkeypatch.setattr(ingest, "_check_ip", lambda a, h: None)
    t = time.monotonic()
    with pytest.raises(ingest.IngestError, match="took longer"):
        ingest.fetch_url(f"http://127.0.0.1:{srv.getsockname()[1]}/", FetchConfig(timeout_s=0.3))
    assert time.monotonic() - t < 2.5   # 4 x timeout_s, not 20 x 0.2s
    srv.close()


def test_dns_rebinding_peer_is_checked_before_the_request_is_sent(monkeypatch):
    for v in PROXY_VARS:
        monkeypatch.delenv(v, raising=False)
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(ingest, "_check_host", lambda h, cfg: None)   # first lookup said "public"
    with pytest.raises(ingest.IngestError, match="non-public address 127.0.0.1"):
        ingest.fetch_url(f"http://127.0.0.1:{srv.server_address[1]}/internal", FetchConfig())
    srv.shutdown()
    assert hits == []


def test_dns_lookup_has_a_timeout(monkeypatch):
    monkeypatch.setattr(ingest, "_DNS_TIMEOUT_S", 0.2)
    monkeypatch.setattr(ingest.socket, "getaddrinfo", lambda *a: time.sleep(2))
    t = time.monotonic()
    with pytest.raises(ingest.IngestError, match="timed out"):
        ingest._check_host("slow.example", FetchConfig())
    assert time.monotonic() - t < 1.5


# --------------------------------------------------------------------------- run.json lost updates / jobs
def test_approval_made_while_a_job_runs_survives_the_jobs_rerender(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch, actor="alice")
    monkeypatch.setenv("USER", "bob")   # local single-user mode: bob, admin
    entered, gate = threading.Event(), threading.Event()

    def slow_generate(rec, *a, **k):
        entered.set()
        assert gate.wait(10)
        return []

    monkeypatch.setattr(pipeline, "generate", slow_generate)
    monkeypatch.setattr(pipeline, "check_tlp_for_run", lambda *a: None)
    monkeypatch.setattr("ti2dac.web.jobs.LLM", lambda *a, **k: None)
    client = _client(settings)
    r = client.post(f"/runs/{record.run_id}/generate", data={"select": "B3"}, follow_redirects=False)
    jid = r.headers["location"].rsplit("/", 1)[1]
    assert entered.wait(10)
    slug = record.packages[0].slug
    r = client.post(f"/runs/{record.run_id}/rules/{slug}/review", data={"status": "approved"}, follow_redirects=False)
    assert r.status_code == 303 and load_record(out).packages[0].review_status == "approved"
    gate.set()
    assert _wait_job(client, jid)["status"] == "done"
    pkg = load_record(out).packages[0]
    assert pkg.review_status == "approved" and "status: test" in pkg.rule_yaml


def test_concurrent_generate_jobs_keep_each_others_rules_and_usage(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch, actor="alice")
    n, calls = len(record.packages), record.usage.calls
    entered = {"B7": threading.Event(), "B8": threading.Event()}
    gate = {"B7": threading.Event(), "B8": threading.Event()}

    def fake_generate(rec, *a, behaviour_ids, **k):   # both jobs number their new rule from the same start
        bid = behaviour_ids[0]
        entered[bid].set()
        assert gate[bid].wait(10)
        new = rec.packages[0].model_copy(deep=True)
        new.behaviour.id, new.slug = bid, f"rule-{len(rec.packages) + 1:03d}"
        rec.packages.append(new)
        rec.usage.calls += 1
        return [new]

    monkeypatch.setattr(pipeline, "generate", fake_generate)
    monkeypatch.setattr(pipeline, "check_tlp_for_run", lambda *a: None)
    monkeypatch.setattr("ti2dac.web.jobs.LLM", lambda *a, **k: None)
    client = _client(settings)
    jids = {}
    for bid in ("B7", "B8"):
        r = client.post(f"/runs/{record.run_id}/generate", data={"select": bid}, follow_redirects=False)
        jids[bid] = r.headers["location"].rsplit("/", 1)[1]
        assert entered[bid].wait(10)
    for bid in ("B7", "B8"):
        gate[bid].set()
        assert _wait_job(client, jids[bid])["status"] == "done"
    final = load_record(out)
    slugs = [p.slug for p in final.packages]
    assert len(final.packages) == n + 2 and len(set(slugs)) == len(slugs)
    assert {"B7", "B8"} <= {p.behaviour.id for p in final.packages}
    assert final.usage.calls == calls + 2


def test_job_is_marked_failed_even_when_the_job_log_write_fails(settings, report_file, monkeypatch):
    record, _ = _run(settings, report_file, monkeypatch)

    def boom(*a, **k):
        raise RuntimeError("boom")

    def locked(self, jid, line):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(pipeline, "generate", boom)
    monkeypatch.setattr(pipeline, "check_tlp_for_run", lambda *a: None)
    monkeypatch.setattr("ti2dac.web.jobs.LLM", lambda *a, **k: None)
    monkeypatch.setattr(Store, "job_log", locked)
    client = _client(settings)
    r = client.post(f"/runs/{record.run_id}/generate", data={"select": "B3"}, follow_redirects=False)
    job = _wait_job(client, r.headers["location"].rsplit("/", 1)[1])
    assert job["status"] == "failed" and job["error"] == "RuntimeError: boom"


# --------------------------------------------------------------------------- review, files, feedback
def test_analyst_cannot_move_an_approved_rule(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch, actor="alice")
    users = Users(settings.state_dir)
    users.add("bob", "another long password", "approver")
    users.add("carol", "analyst password 123", "analyst")
    client = _client(settings)
    url = f"/runs/{record.run_id}/rules/{record.packages[0].slug}/review"
    assert client.post(url, data={"status": "reviewed"}, auth=("carol", "analyst password 123"),
                       follow_redirects=False).status_code == 303   # analysts still review drafts
    assert client.post(url, data={"status": "approved"}, auth=("bob", "another long password"),
                       follow_redirects=False).status_code == 303
    for status in ("draft", "rejected", "reviewed"):
        assert client.post(url, data={"status": status}, auth=("carol", "analyst password 123")).status_code == 403
    assert load_record(out).packages[0].review_status == "approved"
    assert client.post(url, data={"status": "draft"}, auth=("bob", "another long password"),
                       follow_redirects=False).status_code == 303


def test_raw_file_never_serves_evidence_or_source(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    (out / "evidence").mkdir(exist_ok=True)
    (out / "evidence" / "raw.log").write_text("secret log line")
    (out / "source" / "nested").mkdir(parents=True, exist_ok=True)
    (out / "source" / "nested" / "x.txt").write_text("original")
    client = _client(settings)
    base = f"/runs/{record.run_id}/files"
    assert client.get(f"{base}/evidence/raw.log").status_code == 404
    assert client.get(f"{base}/source/nested/x.txt").status_code == 404
    rule = next((out / "rules").glob("*.yml")).relative_to(out).as_posix()
    assert client.get(f"{base}/{rule}").status_code == 200


def test_downloads_use_per_request_temp_files_that_are_removed(settings, report_file, monkeypatch):
    record, _ = _run(settings, report_file, monkeypatch)
    client = _client(settings)
    a, b = client.get(f"/runs/{record.run_id}/download"), client.get(f"/runs/{record.run_id}/download")
    assert a.status_code == b.status_code == 200 and zipfile.ZipFile(io.BytesIO(a.content)).namelist()
    assert client.get("/feedback/export.jsonl").status_code == 200
    assert list((Path(settings.state_dir) / "exports").iterdir()) == []


def test_correction_is_refused_while_ai_is_paused(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    monkeypatch.setattr("ti2dac.aistatus.block_reason", lambda *a, **k: "paused: quota")
    client = _client(settings)
    pkg = record.packages[0]
    r = client.post(f"/runs/{record.run_id}/rules/{pkg.slug}/feedback", follow_redirects=False,
                    data={"artifact": "sigma_rule", "category": "false_positive", "correction": pkg.rule_yaml})
    assert r.status_code == 303 and r.headers["location"] == "/ai?blocked=1"
    assert Store(settings.db_path).list_feedback(record.run_id) == []
    assert load_record(out).packages[0].version == pkg.version


def test_warning_a_job_resolved_does_not_come_back_from_disk(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch, actor="alice")
    record.warnings.append("B9 (T1105) not generated: generate: bad request")
    from ti2dac.render import save_record

    save_record(record, out)

    def fake_generate(rec, *a, **k):
        rec.warnings.remove("B9 (T1105) not generated: generate: bad request")
        rec.warnings.append("new note")
        return []

    monkeypatch.setattr(pipeline, "generate", fake_generate)
    monkeypatch.setattr(pipeline, "check_tlp_for_run", lambda *a: None)
    monkeypatch.setattr("ti2dac.web.jobs.LLM", lambda *a, **k: None)
    client = _client(settings)
    r = client.post(f"/runs/{record.run_id}/generate", data={"select": "B9"}, follow_redirects=False)
    assert _wait_job(client, r.headers["location"].rsplit("/", 1)[1])["status"] == "done"
    warnings = load_record(out).warnings
    assert "new note" in warnings and not any(w.startswith("B9 (T1105) not generated") for w in warnings)


# --------------------------------------------------------------------------- deleting a run
def test_deleting_a_run_removes_its_folder_rows_and_lessons(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch, actor="alice")
    keep, _ = _run(settings, report_file, monkeypatch, actor="alice")   # a second run of the same report stays
    store = Store(settings.db_path)
    slug = record.packages[0].slug
    fid = store.add_feedback(reviewer="alice", run_id=record.run_id, slug=slug, rule_id="x", rule_version=1,
                             artifact="sigma_rule", category="too_broad_fp", severity="low", comment="quotes the report")
    store.add_lesson(store.get_feedback(fid), "T1053.005", "windows", "process_creation", tlp="clear")
    store.add_test_result(tester="alice", run_id=record.run_id, slug=slug, rule_version=1, target="splunk", result="fired")
    users = Users(settings.state_dir)
    users.add("carol", "analyst password 123", "analyst")
    users.add("alice", "creator password 123", "analyst")
    users.add("root", "admin password 12345", "admin")
    client = _client(settings)
    url = f"/runs/{record.run_id}/delete"

    assert client.post(url, auth=("carol", "analyst password 123")).status_code == 403   # not hers
    with store._conn() as c:   # a job still working on the run
        c.execute("INSERT INTO jobs(id, created_at, actor, label, status) VALUES ('j1', '', 'alice', ?, 'running')",
                  (f"{record.run_id}: generate ['B4']",))
    assert client.post(url, auth=("root", "admin password 12345")).status_code == 409
    with store._conn() as c:
        c.execute("UPDATE jobs SET status='done' WHERE id='j1'")
    assert "Delete run" in client.get(f"/runs/{record.run_id}", auth=("alice", "creator password 123")).text

    r = client.post(url, auth=("alice", "creator password 123"), follow_redirects=False)   # the creator may
    assert r.status_code == 303 and "deleted=" in r.headers["location"]
    assert not out.exists() and store.run_path(record.run_id) is None
    assert not store.list_feedback(record.run_id) and not store.test_results(record.run_id)
    assert not store.list_lessons()
    assert client.get(f"/runs/{record.run_id}", auth=("root", "admin password 12345")).status_code == 404
    assert store.run_path(keep.run_id) and (Path(settings.output_dir) / keep.run_id).is_dir()
    assert any(e["action"] == "run.delete" for e in store.audit_entries())
    assert "Run deleted" in client.get(r.headers["location"], auth=("root", "admin password 12345")).text
