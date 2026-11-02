"""End-to-end pipeline, feedback loop and web UI with a fake model (no API calls)."""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from ti2dac import pipeline
from ti2dac.feedback import Store
from ti2dac.ingest import load_report
from ti2dac.render import load_record, render

from .conftest import FakeLLM


def _run(settings, report_file, monkeypatch, **kw):
    fake = FakeLLM(settings, **kw)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, actor="alice")
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename)
    store.register_run(record, str(out))
    return record, out, store, fake


def test_end_to_end(settings, report_file, monkeypatch):
    record, out, store, fake = _run(settings, report_file, monkeypatch)

    stages = [c[0] for c in fake.calls]
    assert stages.count("analyze") == 1
    assert stages.count("generate") == 2            # B3 has unverifiable evidence + invalid technique -> not selected
    assert "repair" in stages                       # bad field triggered exactly the repair loop

    b = {x.id: x for x in record.behaviours}
    assert b["B1"].selected and b["B2"].selected and not b["B3"].selected
    assert not b["B3"].attack_valid and not any(b["B3"].evidence_verified)
    assert any("B3" in w for w in record.warnings)

    # report text sent to the model is condensed and IOC-free
    analyze_prompt = next(u for s, u in fake.calls if s == "analyze")
    assert "0f3a1d4e5b6c" not in analyze_prompt and "<report" in analyze_prompt

    task = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")
    assert task.sigma_status == "syntax-validated" and task.repair_attempts == 1
    assert "NotARealSigmaField" not in task.rule_yaml
    rule = yaml.safe_load(task.rule_yaml)
    assert rule["tags"] == ["attack.persistence", "attack.t1053.005"] and rule["id"] == task.rule_id
    assert sum(1 for q in task.queries if q.query) >= 10

    ps = next(p for p in record.packages if p.behaviour.technique_id == "T1059.001")
    assert ps.sim_blocked, "external download in simulation must be blocked"

    for rel in ["report-summary.md", "behaviour-analysis.yaml", "telemetry-requirements.yaml", "iocs.json",
                "validation/validation-matrix.md", "attack-navigator/layer.json", "FEEDBACK.md",
                f"documentation/{task.slug}-ads.md", f"simulations/{task.slug}/README.md",
                f"simulations/{task.slug}/simulate.ps1", f"simulations/{task.slug}/cleanup.ps1",
                f"simulations/{task.slug}/atomic-test.yaml", f"queries/{task.slug}/splunk.spl",
                f"queries/{task.slug}/sentinel_asim.kql", f"queries/{task.slug}/crowdstrike_cql.cql", "source/SHA256SUMS"]:
        assert (out / rel).is_file(), rel
    assert "TI2DAC_LAB" in (out / f"simulations/{task.slug}/simulate.ps1").read_text()
    assert "BLOCKED" in (out / f"simulations/{ps.slug}/simulate.ps1").read_text()
    assert load_record(out).run_id == record.run_id


def test_cached_reanalysis_costs_no_calls(settings, report_file, monkeypatch):
    """Second run with the response cache on is served entirely from cache."""
    settings.ai.response_cache = True
    from ti2dac import llm as llm_mod

    class Msg:  # minimal fake API message
        def __init__(self, text):
            self.content = [type("B", (), {"type": "text", "text": text})()]
            self.stop_reason, self.stop_details = "end_turn", None
            self.usage = type("U", (), {"input_tokens": 100, "output_tokens": 50,
                                        "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0})()

    from .conftest import analysis
    sent = []

    class Stream:
        def __init__(self, **kw):
            sent.append(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return Msg(analysis().model_dump_json())

    fake_client = type("C", (), {"beta": type("B", (), {"messages": type("M", (), {"stream": staticmethod(lambda **kw: Stream(**kw))})()})()})()
    loaded = load_report(str(report_file), settings.fetch)
    for _ in range(2):
        l = llm_mod.LLM(settings)
        l._client = fake_client
        pipeline.analyze(loaded, settings, l)
    assert len(sent) == 1
    kw = sent[0]
    assert kw["fallbacks"] == "default" and kw["output_config"]["format"]["type"] == "json_schema"
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert l.usage.cached_calls == 1


def test_feedback_correction_versioning_and_lessons(settings, report_file, monkeypatch):
    record, out, store, fake = _run(settings, report_file, monkeypatch)
    pkg = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")

    fid = store.add_feedback(reviewer="alice", run_id=record.run_id, slug=pkg.slug, rule_id=pkg.rule_id,
                             rule_version=pkg.version, artifact="sigma_rule", category="too_broad_fp", severity="medium",
                             comment="Fires on Intune management extension; filter its parent")
    corrected = yaml.safe_load(pkg.rule_yaml)
    corrected["detection"]["filter_main_intune"] = {"ParentImage|endswith": "\\AgentExecutor.exe"}
    new = pipeline.apply_correction(record, pkg.slug, settings, corrected_yaml=yaml.safe_dump(corrected, sort_keys=False))
    assert new.version == 2 and new.history[0]["version"] == "1" and new.rule_id == pkg.rule_id
    assert "AgentExecutor" in next(q.query for q in new.queries if q.target == "splunk")
    store.resolve_feedback(fid, "applied", "v2", "alice")
    store.add_lesson(store.get_feedback(fid), "T1053.005", "windows", "process_creation")

    # an invalid correction is refused and leaves v2 in place
    bad = yaml.safe_load(new.rule_yaml)
    bad["detection"]["condition"] = "selection_nope"
    try:
        pipeline.apply_correction(record, pkg.slug, settings, corrected_yaml=yaml.safe_dump(bad))
        raise AssertionError("invalid correction accepted")
    except ValueError:
        pass
    assert next(p for p in record.packages if p.slug == pkg.slug).version == 2

    # the applied feedback is now a lesson for this technique (prompt injection is tested below)
    assert store.relevant_lessons("T1053.005", "windows", "", 5)[0].startswith("[sigma_rule/too_broad_fp]")
    assert store.relevant_lessons("T1053", "windows", "", 5), "parent technique should match sub-technique lessons"


def test_lessons_reach_prompt(settings, report_file, monkeypatch):
    store = Store(settings.db_path)
    store.add_lesson({"id": 1, "artifact": "sigma_rule", "category": "wrong_field_name", "comment": "Use OriginalFileName too", "target": ""},
                     "T1053.005", "windows", "process_creation")
    _, _, _, fake = _run(settings, report_file, monkeypatch)
    prompt = next(u for s, u in fake.calls if s == "generate" and "T1053.005" in u)
    assert "Use OriginalFileName too" in prompt and "<feedback>" in prompt


def test_validation_matrix_from_test_results(settings, report_file, monkeypatch):
    record, out, store, _ = _run(settings, report_file, monkeypatch)
    pkg = record.packages[0]
    store.add_test_result(tester="bob", run_id=record.run_id, slug=pkg.slug, rule_version=1, target="splunk", result="fired", evidence="rec 42")
    store.add_test_result(tester="bob", run_id=record.run_id, slug=pkg.slug, rule_version=1, target="splunk", result="false_positive",
                          fp_count=2, evidence="SCCM")
    render(record, out, test_results=store.test_results(record.run_id))
    matrix = (out / "validation" / "validation-matrix.md").read_text()
    assert "tested-positive-and-negative" in matrix and "SCCM" in matrix


def test_web_ui(settings, report_file, monkeypatch):
    from ti2dac.web.app import create_app

    record, out, store, _ = _run(settings, report_file, monkeypatch)
    client = TestClient(create_app(settings))
    assert client.get("/").status_code == 200
    page = client.get(f"/runs/{record.run_id}")
    assert page.status_code == 200 and "Report a mistake" in page.text and "<script>alert" not in page.text
    slug = record.packages[0].slug
    r = client.post(f"/runs/{record.run_id}/rules/{slug}/feedback", follow_redirects=False,
                    data={"artifact": "query", "category": "translation_error", "severity": "low",
                          "comment": "<script>alert(1)</script> wrong table", "target": "splunk"})
    assert r.status_code == 303
    assert "&lt;script&gt;alert(1)" in client.get(f"/runs/{record.run_id}").text
    assert client.post(f"/runs/{record.run_id}/rules/{slug}/review", data={"status": "approved"},
                       headers={"origin": "https://evil.example"}).status_code == 403
    r = client.post(f"/runs/{record.run_id}/rules/{slug}/review", data={"status": "approved"}, follow_redirects=False)
    assert r.status_code == 303 and "status: test" in load_record(out).packages[0].rule_yaml
    assert client.get(f"/runs/{record.run_id}/files/../../../etc/passwd").status_code == 404
    assert client.get(f"/runs/{record.run_id}/download").status_code == 200


def test_web_basic_auth(settings, monkeypatch):
    from ti2dac.web.app import create_app

    monkeypatch.setenv("TI2DAC_WEB_USER", "soc")
    monkeypatch.setenv("TI2DAC_WEB_PASSWORD", "s3cret")
    client = TestClient(create_app(settings))
    assert client.get("/").status_code == 401
    assert client.get("/", auth=("soc", "wrong")).status_code == 401
    assert client.get("/", auth=("soc", "s3cret")).status_code == 200


def _pkg_for(sigma):
    from ti2dac import sigma_tools as st
    from ti2dac.models import Behaviour, DetectionPackage

    from .conftest import analysis, task_draft
    draft = task_draft()
    draft.sigma = sigma
    draft.test_events = []   # these tests exercise conversion only
    b = Behaviour(**analysis().behaviours[0].model_dump())
    y = st.render_rule(sigma, rule_id=st.stable_rule_id("x", sigma.title), author="t", references=[], tags=[])
    return DetectionPackage(rule_id="r", slug="rule-001", behaviour=b, draft=draft, rule_yaml=y)


def test_microsoft_gap_filled_by_ai_only_where_needed(settings):
    """pySigma's Kusto backend has no table for PowerShell 4104 rules: Sentinel/Defender get an AI query."""
    from ti2dac.models import Clause, FieldCondition, LogSource, Selection

    from .conftest import task_draft
    s = task_draft().sigma
    s.logsource = LogSource(product="windows", category="ps_script", service="")
    s.selections = [Selection(name="selection", clauses=[Clause(conditions=[
        FieldCondition(field="ScriptBlockText", modifiers=["contains", "all"], values=["FromBase64String", "IEX"])])])]
    s.condition = "selection"
    fake = FakeLLM(settings)
    pkg = pipeline.finalize_package(_pkg_for(s), None, settings, fake)
    by = {q.target: q for q in pkg.queries}
    assert by["splunk"].query and by["elastic_lucene"].query and by["crowdstrike_cql"].query
    assert by["sentinel_asim"].error and by["defender_xdr"].error
    assert by["sentinel_ai"].query and by["defender_ai"].query and "unverified" in by["sentinel_ai"].label
    assert "splunk_ai" not in by and "elastic_ai" not in by, "no tokens for families pySigma handled"
    sent = [u for st_, u in fake.calls if st_ == "translate"]
    assert len(sent) == 2 and any("SecurityEvent" in u and "Unable to determine table" in u for u in sent)


def test_unmapped_cloud_fields_are_flagged(settings):
    from ti2dac.models import Clause, FieldCondition, LogSource, Selection
    from ti2dac.render import _status_label

    from .conftest import task_draft
    s = task_draft().sigma
    s.logsource = LogSource(product="aws", category="", service="cloudtrail")
    s.selections = [Selection(name="selection", clauses=[Clause(conditions=[
        FieldCondition(field="eventSource", modifiers=[], values=["iam.amazonaws.com"]),
        FieldCondition(field="eventName", modifiers=[], values=["CreateAccessKey"])])])]
    s.condition = "selection"
    settings.ai_fill_gaps = []
    pkg = pipeline.finalize_package(_pkg_for(s), None, settings, None)
    lucene = next(q for q in pkg.queries if q.target == "elastic_lucene")
    # no field of the rule is mapped -> treated as unsupported (the AI gap translator would write a native query)
    assert lucene.query is None and "no field mapping" in lucene.error and "eventSource" in lucene.notes
    assert _status_label(pkg, [])["elastic_lucene"] == "unsupported field"


def test_js_shell_page_gets_actionable_error(tmp_path):
    import pytest

    from ti2dac.config import FetchConfig
    from ti2dac.ingest import IngestError
    p = tmp_path / "blog.html"
    p.write_text("<!doctype html><html><head><title>Blog</title><script>load()</script></head><body><div id=app></div></body></html>")
    with pytest.raises(IngestError, match="Save as PDF"):
        load_report(str(p), FetchConfig())


def test_backend_dropping_a_condition_is_surfaced():
    from ti2dac import sigma_tools as st
    y = ("title: t\nlogsource: {product: aws, service: cloudtrail}\ndetection:\n"
         "  sel: {eventSource: iam.amazonaws.com, eventName: CreateAccessKey}\n  condition: sel\n")
    q = st.convert(y, ["qradar_aql"])[0]
    assert q.query and "Backend warning" in q.notes and "removed" in q.notes



def test_native_field_names_are_not_flagged_and_dead_queries_are_replaced(settings):
    """From the live BlackSuit run: CrowdStrike CommandLine is a real Falcon field (no warning), while a
    registry rule the CrowdStrike pipeline cannot map at all must be AI-filled, not shipped as a dead query."""
    from ti2dac.models import Clause, FieldCondition, LogSource, Selection

    from .conftest import task_draft
    proc = pipeline.finalize_package(_pkg_for(task_draft().sigma), None, settings, None)
    cs = next(q for q in proc.queries if q.target == "crowdstrike_cql")
    assert cs.query and "CommandLine" not in cs.notes

    s = task_draft().sigma
    s.logsource = LogSource(product="windows", category="registry_set", service="")
    s.selections = [Selection(name="selection", clauses=[Clause(conditions=[
        FieldCondition(field="TargetObject", modifiers=["contains"], values=["\\Microsoft\\Windows\\CurrentVersion\\Run"]),
        FieldCondition(field="Details", modifiers=["contains"], values=["\\Users\\Public\\"])])])]
    s.condition = "selection"
    fake = FakeLLM(settings)
    reg = pipeline.finalize_package(_pkg_for(s), None, settings, fake)
    by = {q.target: q for q in reg.queries}
    assert by["crowdstrike_cql"].query is None and "no field mapping" in by["crowdstrike_cql"].error
    assert by["crowdstrike_ai"].query and any("CrowdStrike" in u for st_, u in fake.calls if st_ == "translate")


def test_logsource_lessons_reach_prompt(settings, report_file, monkeypatch):
    # a lesson from a different technique on the same log source (process_creation) must still be injected
    store = Store(settings.db_path)
    store.add_lesson({"id": 1, "artifact": "sigma_rule", "category": "too_broad_fp", "comment": "Exclude CCM parent", "target": ""},
                     "T1218.011", "windows", "process_creation")
    store.add_lesson({"id": 2, "artifact": "sigma_rule", "category": "other", "comment": "   ", "target": ""},
                     "T1053.005", "windows", "process_creation")
    assert len(store.list_lessons()) == 1, "a feedback without a comment carries no lesson"
    _, _, _, fake = _run(settings, report_file, monkeypatch)
    prompt = next(u for s, u in fake.calls if s == "generate" and "T1053.005" in u)
    assert "Exclude CCM parent" in prompt


def test_web_feedback_loop(settings, report_file, monkeypatch):
    from ti2dac.web.app import create_app

    record, out, store, _ = _run(settings, report_file, monkeypatch)
    client = TestClient(create_app(settings))
    pkg = record.packages[0]
    base = f"/runs/{record.run_id}/rules/{pkg.slug}/feedback"

    # a broken correction is refused, the feedback stays open and the page says why
    r = client.post(base, follow_redirects=False, data={"artifact": "sigma_rule", "category": "logic_error", "severity": "high",
                                                        "comment": "wrong field", "correction": "title: x\n"})
    assert r.status_code == 303 and "?fb=" in r.headers["location"]
    fid = int(r.headers["location"].split("fb=")[1].split("#")[0])
    assert store.get_feedback(fid)["status"] == "open"
    assert "Your corrected rule was not applied" in client.get(r.headers["location"].split("#")[0]).text

    # closing as fixed elsewhere can keep the comment as a lesson; closed feedback cannot be applied again
    client.post(f"/feedback/{fid}/resolve", data={"status": "applied", "note": "fixed in repo", "lesson": "1"})
    assert any(l["feedback_id"] == fid for l in store.list_lessons())
    assert client.post(f"/feedback/{fid}/apply", follow_redirects=False).status_code == 409

    # a valid correction becomes v2 (a draft) and is reported as applied
    corrected = yaml.safe_load(pkg.rule_yaml)
    corrected["detection"]["filter_x"] = {"ParentImage|endswith": "\\ccmexec.exe"}
    r = client.post(base, follow_redirects=False, data={"artifact": "sigma_rule", "category": "too_broad_fp", "severity": "medium",
                                                        "comment": "filter SCCM", "correction": yaml.safe_dump(corrected, sort_keys=False)})
    fid2 = int(r.headers["location"].split("fb=")[1].split("#")[0])
    page = client.get(r.headers["location"].split("#")[0]).text
    assert f"Feedback #{fid2} applied" in page and load_record(out).packages[0].version == 2 and load_record(out).packages[0].review_status == "draft"
