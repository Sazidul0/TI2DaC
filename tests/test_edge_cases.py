"""Edge cases found while hardening for production use (no API calls)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from ti2dac import pipeline, replay
from ti2dac import sigma_tools as st
from ti2dac.feedback import Store
from ti2dac.models import Clause, CorrelationDraft, FieldCondition, LogSource, Selection
from ti2dac.render import load_record, render

from .conftest import FakeLLM, ev, task_draft


def _run(settings, report_file, monkeypatch, actor="alice", **kw):
    fake = FakeLLM(settings, **kw)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a, **k: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, actor=actor)
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename)
    store.register_run(record, str(out))
    return record, out, store, fake


# --------------------------------------------------------------------------- simulation <-> rule self-test
def test_selftest_passes_and_failing_rule_is_repaired(settings, report_file, monkeypatch):
    record, out, _, fake = _run(settings, report_file, monkeypatch)
    task = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")
    # first draft used a bogus field: field errors + failing self-test -> exactly one repair -> passes
    assert task.repair_attempts == 1 and task.selftest == "pass", task.selftest_details
    assert json.loads((out / "tests" / f"{task.slug}.json").read_text())[0]["should_match"] is True
    assert "| pass |" in (out / "validation" / "validation-matrix.md").read_text()


def test_selftest_detects_rule_that_misses_its_simulation():
    d = task_draft()
    d.sigma.selections[1].clauses[0].conditions[0].values = ["/create", "/sc daily"]   # sim uses /sc onlogon
    y = st.render_rule(d.sigma, rule_id=st.stable_rule_id("a", "b"), author="t", references=[], tags=[])
    status, problems = replay.selftest(y, d.test_events)
    assert status == "fail" and "does NOT match" in problems[0]


def test_selftest_detects_false_positive_on_benign_lookalike():
    d = task_draft()
    d.test_events.append(ev("benign onlogon task by installer", False, Image="C:\\Windows\\System32\\schtasks.exe",
                            CommandLine="schtasks /create /tn Updater /sc onlogon /ru system",
                            ParentImage="C:\\Program Files\\Vendor\\setup.exe"))
    y = st.render_rule(d.sigma, rule_id=st.stable_rule_id("a", "c"), author="t", references=[], tags=[])
    status, problems = replay.selftest(y, d.test_events)
    assert status == "fail" and "false positive" in problems[0]


def test_replay_scopes_by_event_id_and_reads_siem_exports(tmp_path):
    y = st.render_rule(task_draft().sigma, rule_id=st.stable_rule_id("a", "d"), author="t", references=[], tags=[])
    lines = [
        {"winlog": {"event_id": 1, "event_data": {"Image": "C:\\Windows\\System32\\schtasks.exe",
                                                  "CommandLine": "schtasks /create /tn x /sc onlogon /ru system"}}},
        {"EventID": 13, "Image": "C:\\Windows\\System32\\schtasks.exe",
         "CommandLine": "schtasks /create /tn x /sc onlogon /ru system"},           # wrong event type
        {"EventID": 1, "Image": "C:\\Windows\\System32\\SCHTASKS.EXE",
         "CommandLine": "SCHTASKS /CREATE /TN X /SC ONLOGON /RU SYSTEM"},           # case-insensitive like Sigma
    ]
    f = tmp_path / "lab.jsonl"
    f.write_text("\n".join(json.dumps(x) for x in lines))
    assert replay.evaluate(y, replay.load_events(f)) == [0, 2]


# --------------------------------------------------------------------------- correlation rules
def test_threshold_rule_renders_validates_and_converts():
    d = task_draft().sigma
    d.title = "Password spraying from one source"
    d.logsource = LogSource(product="windows", category="", service="security")
    d.selections = [Selection(name="selection", clauses=[Clause(conditions=[
        FieldCondition(field="EventID", modifiers=[], values=["4625"]),
        FieldCondition(field="LogonType", modifiers=[], values=["3"])])])]
    d.condition = "selection"
    d.correlation = [CorrelationDraft(type="value_count", group_by=["IpAddress"], timespan="10m", gte=20,
                                      value_field="TargetUserName")]
    y = st.render_rule(d, rule_id=st.stable_rule_id("a", "spray"), author="t", references=[], tags=[])
    docs = st.load_docs(y)
    assert len(docs) == 2 and docs[1]["correlation"]["rules"] == [docs[0]["name"]]
    assert st.validate_rule(y)[0]
    q = {r.target: r for r in st.convert(y, ["splunk", "elastic_esql", "sentinel_asim"])}
    assert "dc(TargetUserName)" in q["splunk"].query and "count_distinct" in q["elastic_esql"].query
    assert q["sentinel_asim"].error   # -> filled by the AI gap translator in the pipeline
    assert st.set_status(y, "test").count("status: test") == 2


# --------------------------------------------------------------------------- environment fit
def test_telemetry_inventory_and_index_overrides(settings, report_file, monkeypatch):
    settings.telemetry = ["windows:security"]   # no Sysmon process creation collected
    settings.index_overrides = {"splunk": "index=wineventlog", "elastic_esql": "logs-endpoint.events.*"}
    record, *_ = _run(settings, report_file, monkeypatch)
    task = record.packages[0]
    assert any("not in your telemetry inventory" in w for w in task.quality_warnings)
    q = {x.target: x.query for x in task.queries if x.query}
    assert q["splunk"].startswith("index=wineventlog ") and q["elastic_esql"].startswith("from logs-endpoint.events.*")


def test_duplicate_of_existing_internal_rule_is_flagged(settings, report_file, monkeypatch, tmp_path):
    repo = tmp_path / "internal-rules"
    repo.mkdir()
    existing = task_draft().sigma
    existing.title = "Internal: schtasks onlogon system task"
    (repo / "schtasks.yml").write_text(st.render_rule(existing, rule_id="11111111-2222-3333-4444-555555555555",
                                                      author="soc", references=[], tags=["attack.t1053.005"]))
    settings.rule_repos = [str(repo)]
    record, *_ = _run(settings, report_file, monkeypatch)
    task = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")
    assert task.similar_rules and "Internal: schtasks onlogon" in task.similar_rules[0]


def test_non_english_report_is_flagged():
    assert pipeline.looks_english("The threat actor executed PowerShell on the host and created a task.")
    assert not pipeline.looks_english("攻击者在主机上执行了 PowerShell 并创建了计划任务。" * 20)
    assert not pipeline.looks_english("Der Angreifer führte PowerShell auf dem Host aus und erstellte eine Aufgabe. " * 10)


# --------------------------------------------------------------------------- governance
def test_four_eyes_and_roles_in_web(settings, report_file, monkeypatch):
    from ti2dac.users import Users
    from ti2dac.web.app import create_app

    record, out, *_ = _run(settings, report_file, monkeypatch, actor="alice")
    users = Users(settings.state_dir)
    users.add("alice", "correct horse battery", "approver")
    users.add("bob", "another long password", "approver")
    users.add("carol", "analyst password 123", "analyst")
    client = TestClient(create_app(settings))
    slug = record.packages[0].slug
    url = f"/runs/{record.run_id}/rules/{slug}/review"
    assert client.get("/").status_code == 401
    assert client.post(url, data={"status": "approved"}, auth=("carol", "analyst password 123")).status_code == 403
    assert client.post(url, data={"status": "approved"}, auth=("alice", "correct horse battery")).status_code == 409
    r = client.post(url, data={"status": "approved"}, auth=("bob", "another long password"), follow_redirects=False)
    assert r.status_code == 303 and load_record(out).packages[0].review_status == "approved"
    assert "status: test" in load_record(out).packages[0].rule_yaml


def test_user_store_hashes_passwords(settings):
    from ti2dac.users import Users

    u = Users(settings.state_dir)
    with pytest.raises(ValueError):
        u.add("x", "short", "analyst")
    u.add("dave", "a sufficiently long pw", "admin")
    raw = Path(settings.state_dir, "users.json").read_text()
    assert "a sufficiently long pw" not in raw and "pbkdf2_sha256$" in raw
    assert u.authenticate("dave", "a sufficiently long pw") == "admin"
    assert u.authenticate("dave", "wrong") is None and u.authenticate("nobody", "x") is None


def test_jobs_survive_restart(settings):
    store = Store(settings.db_path)
    store.job_create("j1", "report.html", "alice")
    store.job_log("j1", "stage 1")
    Store(settings.db_path).interrupt_running_jobs()   # what create_app does on start-up
    job = store.get_job("j1")
    assert job["status"] == "interrupted" and job["log"] == ["stage 1"]


# --------------------------------------------------------------------------- CLI: replay, export + CI tests
def test_cli_replay_export_and_rule_test(settings, report_file, monkeypatch, tmp_path):
    from ti2dac.cli import app

    record, out, store, _ = _run(settings, report_file, monkeypatch, actor="alice")
    monkeypatch.setenv("TI2DAC_STATE_DIR", settings.state_dir)
    monkeypatch.setenv("TI2DAC_OUTPUT_DIR", settings.output_dir)
    monkeypatch.setenv("TI2DAC_NO_AI", "1")
    runner = CliRunner()
    slug = next(p.slug for p in record.packages if p.behaviour.technique_id == "T1053.005")
    lab = tmp_path / "lab.json"
    lab.write_text(json.dumps([{"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe",
                                "CommandLine": "schtasks /create /tn ti2dac /sc onlogon /ru system /tr calc"}]))
    monkeypatch.setattr("ti2dac.cli.getpass.getuser", lambda: "bob")
    r = runner.invoke(app, ["replay", "--run", record.run_id, "--rule-slug", slug, "--events", str(lab),
                            "--expect", "match", "--record"])
    assert r.exit_code == 0, r.output
    assert "sigma_replay" in (out / "validation" / "validation-matrix.md").read_text()

    repo = tmp_path / "detections"
    r = runner.invoke(app, ["export", record.run_id, "--repo", str(repo)])
    assert "0 rule(s) exported" in r.output                     # nothing approved yet
    monkeypatch.setattr("ti2dac.cli.getpass.getuser", lambda: "alice")   # identity = OS user, not a flag
    r = runner.invoke(app, ["review", record.run_id, slug, "--status", "approved"])
    assert r.exit_code != 0 and "four-eyes" in r.output         # author cannot approve
    assert runner.invoke(app, ["review", record.run_id, slug, "--status", "approved", "--reviewer", "bob"]).exit_code != 0
    monkeypatch.setattr("ti2dac.cli.getpass.getuser", lambda: "bob")
    r = runner.invoke(app, ["review", record.run_id, slug, "--status", "approved"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(app, ["export", record.run_id, "--repo", str(repo)])
    assert "1 rule(s) exported" in r.output
    assert (repo / ".github" / "workflows" / "detections.yml").is_file()
    rule_files = list((repo / "rules").rglob("*.yml"))
    assert rule_files and "status: test" in rule_files[0].read_text()
    r = runner.invoke(app, ["rule-test", str(repo / "rules"), str(repo / "tests")])
    assert r.exit_code == 0 and "PASS" in r.output, r.output


def test_rerunning_a_report_never_overwrites_the_previous_package(settings, report_file, monkeypatch):
    first, out1, *_ = _run(settings, report_file, monkeypatch)
    second, out2, *_ = _run(settings, report_file, monkeypatch)
    assert first.run_id != second.run_id and second.run_id == first.run_id + "-2"
    assert (out1 / "run.json").is_file() and (out2 / "run.json").is_file()
    assert first.packages[0].rule_id == second.packages[0].rule_id      # rule identity is stable


def test_missing_anthropic_credentials_give_a_clear_error(settings, monkeypatch):
    from ti2dac.llm import LLM, LLMError
    from ti2dac.models import TranslationDraft

    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(settings.state_dir))   # no `ant auth login` profile either
    with pytest.raises(LLMError, match="No Anthropic credentials|authentication"):
        LLM(settings).structured("translate", "s", "u", TranslationDraft)



# --------------------------------------------------------------------------- independent-review findings
def test_replay_numeric_fields_and_field_name_case():
    rule = "title: t\nlogsource: {product: windows, service: security}\ndetection:\n  sel: {EventID: 4698}\n  condition: sel\n"
    assert replay.evaluate(rule, [{"EventID": "4698"}, {"EventID": 4698}, {"EventID": "4699"}]) == [0, 1]
    rule = ("title: t\nlogsource: {product: windows, category: network_connection}\ndetection:\n"
            "  sel: {DestinationPort|gte: 1024}\n  condition: sel\n")
    assert replay.evaluate(rule, [{"DestinationPort": "443"}, {"DestinationPort": "8443"}]) == [1]
    rule = "title: t\nlogsource: {product: windows, category: process_creation}\ndetection:\n  sel: {CommandLine|contains: whoami}\n  condition: sel\n"
    assert replay.evaluate(rule, [{"commandline": "whoami /all"}]) == [0]      # no duplicate-column crash


def test_ai_revision_starts_from_the_human_correction(settings, report_file, monkeypatch):
    record, out, store, fake = _run(settings, report_file, monkeypatch)
    pkg = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")
    docs = st.load_docs(pkg.rule_yaml)
    docs[0]["detection"]["filter_main_intune"] = {"ParentImage|endswith": "\\AgentExecutor.exe"}
    pipeline.apply_correction(record, pkg.slug, settings, corrected_yaml=st.dump_docs(docs), actor="bob")
    pipeline.apply_correction(record, pkg.slug, settings, feedback_text="also exclude SCCM", llm=fake, actor="bob")
    repair_prompt = [u for s_, u in fake.calls if s_ == "repair"][-1]
    assert "AgentExecutor" in repair_prompt, "the AI must revise the human-corrected rule, not the old draft"
    assert "author:" not in repair_prompt and "references:" not in repair_prompt


def test_feedback_paths_respect_tlp_and_redact_comments(settings, report_file, monkeypatch):
    record, out, store, fake = _run(settings, report_file, monkeypatch)
    pkg = record.packages[0]
    record.report.tlp_effective = "red"
    with pytest.raises(pipeline.PolicyError):
        pipeline.apply_correction(record, pkg.slug, settings, feedback_text="tighten", llm=fake, actor="bob")
    record.report.tlp_effective = "clear"
    settings.redaction.internal_domains = ["corp.local"]
    pipeline.apply_correction(record, pkg.slug, settings, llm=fake, actor="bob",
                              feedback_text="FP on ws-17.corp.local for CORP\\jdoe@corp.local 10.1.2.3")
    prompt = [u for s_, u in fake.calls if s_ == "repair"][-1]
    assert "ws-17" not in prompt and "jdoe" not in prompt and "10.1.2.3" not in prompt


def test_unknown_author_cannot_be_approved_and_download_never_ships_source(settings, report_file, monkeypatch):
    from ti2dac.web.app import create_app

    record, out, *_ = _run(settings, report_file, monkeypatch)
    pkg = record.packages[0]
    pkg.created_by = ""
    assert "no recorded author" in pipeline.review_problem(pkg, "approved", "bob")
    client = TestClient(create_app(settings))
    import io
    import zipfile
    names = zipfile.ZipFile(io.BytesIO(client.get(f"/runs/{record.run_id}/download").content)).namelist()
    assert names and not [n for n in names if n.startswith(("source/", "evidence/"))]
