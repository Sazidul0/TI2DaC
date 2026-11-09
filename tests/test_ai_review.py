"""AI review of a finished run (review.py): code checks, the review job, model choice, decisions, staleness."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import get_args

import pytest
from fastapi.testclient import TestClient

from ti2dac import pipeline, review
from ti2dac.feedback import CATEGORIES, Store
from ti2dac.llm import LLM
from ti2dac.models import (
    IOCSet, QueryResult, ReviewCategory, ReviewDraft, ReviewFindingDraft, RunReview,
)
from ti2dac.render import load_record, render
from ti2dac.web import jobs as jobs_mod

from .conftest import FakeLLM

VERIFIED_QUOTE = "They created a scheduled task with schtasks /create"


def _run(settings, report_file, monkeypatch):
    fake = FakeLLM(settings)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a, **k: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, actor="alice")
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename)
    store.register_run(record, str(out))
    return record, out


class FakeReviewer(LLM):
    """Stands in for the reviewer model; remembers the settings it was built with and what it was sent."""

    def __init__(self, settings, findings):
        super().__init__(settings)
        self.findings, self.calls = findings, []

    def structured(self, stage, system, user, schema):
        assert schema is ReviewDraft
        self.calls.append((stage, user))
        # real accounting path: priced at the model that answered
        self._record(stage, self.settings.ai.provider, [{
            "model": getattr(self.settings.ai, stage).model, "billed": True, "input_tokens": 1000,
            "output_tokens": 500, "cache_read_tokens": 0, "cache_write_tokens": 0}])
        return ReviewDraft(summary="Mostly sound; one rule misses a variant.", findings=self.findings)


def _f(**kw) -> ReviewFindingDraft:
    base = dict(area="rule", target="rule-001", siem="", category="too_narrow_fn", severity="high",
                problem="Misses the variant the report names.", report_quote="", suggested_fix="Add it.")
    return ReviewFindingDraft(**{**base, **kw})


def _client(settings):
    from ti2dac.web.app import create_app

    return TestClient(create_app(settings))


def _wait(client, location: str) -> dict:
    jid = location.rsplit("/", 1)[1]
    for _ in range(200):
        job = client.get(f"/api/jobs/{jid}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("review job still running")


def test_review_categories_match_feedback_taxonomy():
    assert set(get_args(ReviewCategory)) == set(CATEGORIES)


def test_evidence_check_ignores_private_use_glyphs():
    """Some PDF fonts map '-' and ':' to Private Use Area code points; a quote without them is still verbatim."""
    source = pipeline._norm("times set to 20260823 1525 UTC through NtSetInform\nationFile class 4")
    assert pipeline.verify_evidence("times set to 20260823 1525 UTC through NtSetInform", source)


# --------------------------------------------------------------------------- code checks
TEXT = """TON names webratxaye1.ton (wallet record), remoteadministratortoo
l.ton
Stage 2 queried remoteadministratortool.ton through tonapi.io.
Resolvers: dns.google, cloudflare-dns.co
m ; port 443. Also cloudflare-dns.com.
Unbacked code, or the mutex Global\\WEBR_V4CTHH
83SX7G.
It creates the mutex Global\\WEBR_V4CTHH83SX7G at start.
Packing RC4 (hex key 97a0f8684065cabd5349004813d52df9) then zlib.
SHA1 / MD5 2c3a7750607dc6f68132eb271c793686f9cc5c7f / a1abe03182a68ee490165b23720c5259
The sample sa1atik.cn
beacons every 14 s.
"""


def _record_with(settings, report_file, monkeypatch, **iocs):
    record, out = _run(settings, report_file, monkeypatch)
    record.iocs = IOCSet(**iocs)
    return record, out


def test_code_checks_find_cut_iocs_and_keys_listed_as_hashes(settings, report_file, monkeypatch):
    record, _ = _record_with(settings, report_file, monkeypatch,
                             domains=["l.ton", "cloudflare-dns.co", "sa1atik.cn", "webratxaye1.ton"],
                             mutexes=["Global\\WEBR_V4CTHH"],
                             md5=["97a0f8684065cabd5349004813d52df9", "a1abe03182a68ee490165b23720c5259"])
    found = {(f.target, f.problem.split("'")[1]) for f in review.code_checks(record, TEXT) if f.area == "ioc"}
    assert found == {("iocs.domains", "l.ton"), ("iocs.domains", "cloudflare-dns.co"),
                     ("iocs.mutexes", "Global\\WEBR_V4CTHH"), ("iocs.md5", "97a0f8684065cabd5349004813d52df9")}
    # a value at a line end whose joined form is not in the report ("sa1atik.cnbeacons") is not flagged,
    # and an MD5 the report labels as MD5 stays


def test_code_checks_flag_kql_literal_star_and_unused_selections(settings, report_file, monkeypatch):
    record, _ = _run(settings, report_file, monkeypatch)
    pkg = record.packages[0]
    pkg.queries = [
        QueryResult(target="defender_xdr", label="Defender XDR", language="KQL", method="pysigma",
                    query='DeviceRegistryEvents\n| where RegistryKey endswith "\\\\CurrentVersion\\\\Run*"'),
        QueryResult(target="sentinel_asim", label="ASIM", language="KQL", method="pysigma",
                    query='imProcessCreate | where TargetProcessName endswith "\\\\schtasks.exe" and '
                          'CommandLine matches regex ".*create.*"'),
        QueryResult(target="splunk", label="Splunk", language="SPL", method="pysigma", query='Image="*\\\\schtasks.exe"'),
    ]
    pkg.sigma_issues = ["high: DanglingDetectionIssue: Rule defines detection that is not referenced from condition "
                        "(detection_name=selection_user_writable_path)"]
    found = review.code_checks(record, "")
    assert [(f.area, f.siem) for f in found] == [("rule", ""), ("query", "defender_xdr")]
    assert "selection_user_writable_path" in found[0].problem and "Run*" in found[1].problem


# --------------------------------------------------------------------------- the review job through the web
def test_web_review_with_chosen_model(settings, report_file, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    record, out = _run(settings, report_file, monkeypatch)
    reviewer = FakeReviewer(settings, [
        _f(report_quote=VERIFIED_QUOTE),
        _f(target="rule-001/defender_xdr", area="query", category="translation_error", problem="Wrong table."),
        _f(report_quote="the actor used a kernel driver to disable EDR", problem="Invented."),
        _f(area="analysis", target="B9", category="missed_behaviour", problem="Missed something."),
        _f(area="ioc", target="iocs.domains", category="wrong_ioc", problem="evil-c2.com is cut."),
    ])
    built = {}

    def make(s, *a, **k):
        built["settings"] = s
        reviewer.settings = s
        return reviewer
    monkeypatch.setattr(jobs_mod, "LLM", make)
    client = _client(settings)

    page = client.get(f"/runs/{record.run_id}").text
    assert 'id="ai-review"' in page and "Not reviewed yet" in page and "ti2dac checks only" in page
    assert re.search(r'<option value="anthropic:claude-opus-5-5"\s+selected', page)          # the review stage's model
    assert "unavailable: no API key configured" in page                                       # Gemini: no key

    r = client.post(f"/runs/{record.run_id}/ai-review", data={"model": "anthropic:claude-sonnet-5-5"}, follow_redirects=False)
    assert r.status_code == 303
    assert _wait(client, r.headers["location"])["status"] == "done"
    s = built["settings"]
    assert (s.ai.provider, s.ai.review.model) == ("anthropic", "claude-sonnet-5-5")
    assert settings.ai.review.model == "claude-opus-5-5"            # the server's settings are untouched
    assert [c[0] for c in reviewer.calls] == ["review"]
    sent = reviewer.calls[0][1]
    assert "<report" in sent and '"slug":"rule-001"' in sent and "schtasks" in sent

    rv = load_record(out).review
    assert (rv.provider, rv.model) == ("anthropic", "claude-sonnet-5-5")
    by_problem = {f.problem: f for f in rv.findings}
    assert by_problem["Misses the variant the report names."].quote_verified
    q = by_problem["Wrong table."]
    assert (q.area, q.target, q.siem) == ("query", "rule-001", "defender_xdr")
    assert {f.note for f in rv.discarded} == {"report quote not found in the report",
                                              "a missed behaviour needs a quote from the report"}
    assert rv.versions == {p.slug: p.version for p in record.packages}
    assert rv.cost_usd == pytest.approx(0.007)   # sonnet: 1000 in x $2/M + 500 out x $10/M
    usage = load_record(out).usage                                      # counted in the run's AI usage
    assert usage.by_stage["review"]["calls"] == 1 and usage.by_stage["review"]["model_price_key"] == "claude-sonnet-5-5"
    assert usage.estimated_cost_usd == pytest.approx(record.usage.estimated_cost_usd + 0.007)
    assert "## AI review" in (out / "report-summary.md").read_text()
    assert "2 AI finding(s) discarded" in client.get(f"/runs/{record.run_id}").text
    index = client.get("/").text
    assert re.search(r"\d+ open</span>", index)


def test_decisions_feedback_warnings_and_dismissed_passed_on(settings, report_file, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    record, out = _run(settings, report_file, monkeypatch)
    reviewer = FakeReviewer(settings, [
        _f(report_quote=VERIFIED_QUOTE),
        _f(area="ioc", target="iocs.domains", category="wrong_ioc", problem="evil-c2.com is cut."),
        _f(area="simulation", target="rule-001", category="incomplete_cleanup", problem="Cleanup misses the task."),
    ])
    monkeypatch.setattr(jobs_mod, "LLM", lambda s, *a, **k: reviewer)
    client = _client(settings)
    r = client.post(f"/runs/{record.run_id}/ai-review", data={"model": "anthropic:claude-opus-5-5"}, follow_redirects=False)
    _wait(client, r.headers["location"])
    ids = {f.problem: f.id for f in load_record(out).review.findings}

    # accept a rule finding: feedback on rule-001
    client.post(f"/runs/{record.run_id}/ai-review/{ids['Misses the variant the report names.']}", data={"decision": "accepted"})
    # accept an IOC finding: a run warning; then reopen it: the warning goes again
    ioc = ids["evil-c2.com is cut."]
    client.post(f"/runs/{record.run_id}/ai-review/{ioc}", data={"decision": "accepted"})
    assert any(w.startswith(f"AI review {ioc} (accepted)") for w in load_record(out).warnings)
    client.post(f"/runs/{record.run_id}/ai-review/{ioc}", data={"decision": "open"})
    assert not any(w.startswith(f"AI review {ioc}") for w in load_record(out).warnings)
    # dismiss with a reason
    sim = ids["Cleanup misses the task."]
    client.post(f"/runs/{record.run_id}/ai-review/{sim}", data={"decision": "dismissed", "note": "the lab VM is reverted"})

    rv = load_record(out).review
    acc = next(f for f in rv.findings if f.problem.startswith("Misses"))
    assert acc.status == "accepted" and acc.feedback_id
    fb = Store(settings.db_path).get_feedback(acc.feedback_id)
    assert (fb["slug"], fb["artifact"], fb["category"], fb["status"]) == ("rule-001", "sigma_rule", "too_narrow_fn", "open")
    assert "claude-opus-5-5" in fb["comment"] and VERIFIED_QUOTE in fb["comment"]
    assert next(f for f in rv.findings if f.id == sim).status == "dismissed"

    # next review: dismissed findings go to the reviewer; identical findings keep their decision
    r = client.post(f"/runs/{record.run_id}/ai-review", data={"model": "anthropic:claude-opus-5-5"}, follow_redirects=False)
    assert _wait(client, r.headers["location"])["status"] == "done"
    assert "<dismissed>" in reviewer.calls[1][1] and "the lab VM is reverted" in reviewer.calls[1][1]
    again = {f.problem: f for f in load_record(out).review.findings}
    assert again["Cleanup misses the task."].status == "dismissed"
    assert again["Misses the variant the report names."].feedback_id == acc.feedback_id   # no second feedback item
    assert len(Store(settings.db_path).list_feedback(record.run_id)) == 1


def test_review_goes_out_of_date_when_a_rule_changes(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    client = _client(settings)
    r = client.post(f"/runs/{record.run_id}/ai-review", data={"model": "code"}, follow_redirects=False)
    assert _wait(client, r.headers["location"])["status"] == "done"
    rec = load_record(out)
    assert rec.review.provider == "" and review.status(rec.model_dump())["state"] in ("clean", "open")
    rec.packages[0].version += 1   # a new version, e.g. from applied feedback
    (out / "run.json").write_text(rec.model_dump_json())
    assert review.out_of_date(rec) == [f"{rec.packages[0].slug} v1 → v2"]
    assert "Out of date" in client.get(f"/runs/{record.run_id}").text
    assert "Out of date" in client.get("/").text


def test_review_request_guards(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    client = _client(settings)
    url = f"/runs/{record.run_id}/ai-review"
    assert client.post(url, data={"model": "anthropic:not-a-model"}).status_code == 400
    assert client.post(url, data={"model": "mistral:large"}).status_code == 400
    assert client.post(url, data={"model": "gemini:gemini-flash-latest"}).status_code == 400   # no key
    rec = load_record(out)
    rec.report.tlp_effective = "amber"
    (out / "run.json").write_text(rec.model_dump_json())
    monkeypatch.setenv("GEMINI_API_KEY", "AIza-test")
    r = client.post(url, data={"model": "gemini:gemini-flash-latest"})
    assert r.status_code == 403 and "TLP:AMBER" in r.json()["detail"]
    assert "unavailable: TLP:AMBER may not be sent to gemini" in client.get(f"/runs/{record.run_id}").text
    assert client.post(f"/runs/{record.run_id}/ai-review/F1", data={"decision": "accepted"}).status_code == 404


def test_other_jobs_keep_a_review_saved_meanwhile(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    loaded_by_job = load_record(out)
    before = jobs_mod.snapshot(loaded_by_job)
    disk = load_record(out)
    disk.review = RunReview(created_at="2026-11-08T00:00:00+00:00", versions=review.versions(disk))
    (out / "run.json").write_text(disk.model_dump_json())
    jobs_mod.merge_meanwhile(settings, loaded_by_job, out, before)
    assert loaded_by_job.review is not None


def test_review_needs_the_source_report(settings, report_file, monkeypatch):
    record, out = _run(settings, report_file, monkeypatch)
    (out / "source" / "SHA256SUMS").unlink()
    with pytest.raises(ValueError, match="no source report"):
        review.run_review(load_record(out), out, settings, None, "alice")
