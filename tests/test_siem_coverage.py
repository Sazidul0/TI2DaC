"""Wazuh output, deterministic thresholds and chains, client field normalization, grounded AI translation."""
from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ti2dac import chains, clients, pipeline
from ti2dac import sigma_tools as st
from ti2dac.feedback import Store
from ti2dac.models import (Behaviour, Clause, CorrelationDraft, DetectionPackage, FieldCondition, LogSource, SequenceDraft,
                           Selection, SigmaDraft)
from ti2dac.render import render

from .conftest import FakeLLM, analysis, task_draft


def _rule(sigma: SigmaDraft, rid: str = "11111111-1111-1111-1111-111111111111") -> str:
    return st.render_rule(sigma, rule_id=rid, author="t", references=[], tags=["attack.persistence", "attack.t1053.005"])


def _security(event_id: str, extra: dict | None = None, corr: CorrelationDraft | None = None) -> SigmaDraft:
    s = copy.deepcopy(task_draft().sigma)
    s.logsource = LogSource(product="windows", category="", service="security")
    conds = [FieldCondition(field="EventID", modifiers=[], values=[event_id])]
    conds += [FieldCondition(field=k, modifiers=[], values=v) for k, v in (extra or {}).items()]
    s.selections, s.condition = [Selection(name="selection", clauses=[Clause(conditions=conds)])], "selection"
    s.correlation = [corr] if corr else []
    return s


def _one(rule_yaml: str, target: str, client=None):
    (q,) = st.convert(rule_yaml, [target], None, client)
    return q


# --------------------------------------------------------------------------- Wazuh
def test_wazuh_rule_hangs_off_the_right_parent_and_matches():
    q = _one(_rule(task_draft().sigma), "wazuh_rule")
    assert q.method == "template" and q.query
    root = ET.fromstring(re.sub(r"<!--.*?-->", "", q.query, flags=re.S))
    rules = root.findall("rule")
    assert len(rules) == 2                                    # Image OR OriginalFileName -> two Wazuh rules
    assert {r.findtext("if_sid") for r in rules} == {"61603"}  # Sysmon event 1, not a parent Wazuh never reaches
    assert all(re.fullmatch(r"1[01]\d{4}", r.get("id")) for r in rules)
    fields = {f.get("name"): f for f in rules[0].findall("field")}
    assert fields["win.eventdata.parentImage"].get("negate") == "yes"
    cl = re.compile(fields["win.eventdata.commandLine"].text)
    assert cl.search("schtasks /create /tn x /sc onlogon /ru SYSTEM")
    assert not cl.search("schtasks /create /tn x /sc daily /ru SYSTEM")
    assert rules[0].find("mitre/id").text == "T1053.005"


def test_wazuh_threshold_uses_frequency_and_same_field():
    corr = CorrelationDraft(type="event_count", group_by=["IpAddress"], timespan="5m", gte=10, value_field="")
    q = _one(_rule(_security("4625", {"LogonType": ["3", "10"]}, corr)), "wazuh_rule")
    root = ET.fromstring(re.sub(r"<!--.*?-->", "", q.query, flags=re.S))
    base, thr = root.findall("rule")
    assert base.findtext("if_sid") == "60122" and base.get("level") == "0"
    assert thr.get("frequency") == "10" and thr.get("timeframe") == "300"
    assert thr.findtext("same_field") == "win.eventdata.ipAddress"
    assert thr.findtext("if_matched_group") in base.findtext("group")


def test_wazuh_indexer_query_uses_data_fields():
    q = _one(_rule(task_draft().sigma), "wazuh_indexer")
    assert "data.win.eventdata.commandLine" in q.query and "data.win.system.eventID:1" in q.query


def test_non_windows_rules_are_not_faked_for_wazuh():
    s = copy.deepcopy(task_draft().sigma)
    s.logsource = LogSource(product="linux", category="process_creation", service="")
    q = _one(_rule(s), "wazuh_rule")
    assert q.query is None and "does not support" in q.error


# --------------------------------------------------------------------------- thresholds: code, never AI
def test_thresholds_are_built_by_code_per_language():
    corr = CorrelationDraft(type="event_count", group_by=["IpAddress"], timespan="5m", gte=10, value_field="")
    y = _rule(_security("4625", corr=corr))
    kql = _one(y, "sentinel_securityevent")
    assert kql.method == "template" and "summarize EventCount = count()" in kql.query and "by IpAddress, bin(TimeGenerated, 5m)" in kql.query
    assert "where EventCount >= 10" in kql.query
    eql = _one(y, "elastic_eql")
    assert eql.query.startswith("sequence by source.ip with maxspan=5m") and "with runs=10" in eql.query
    lucene = _one(y, "elastic_lucene")
    assert "threshold is NOT in it" in lucene.notes and "count >= 10" in lucene.notes
    qradar = _one(y, "qradar_aql")
    assert qradar.query is None and "Not sent to the AI" in qradar.error


def test_single_rule_temporal_is_gone():
    assert "temporal" not in str(CorrelationDraft.model_json_schema())
    legacy = task_draft().sigma.model_dump()
    legacy["correlation"] = [{"type": "temporal", "group_by": ["x"], "timespan": "5m", "gte": 2, "value_field": ""}]
    assert SigmaDraft.model_validate(legacy).correlation == []


def test_correlated_rules_are_never_sent_to_the_ai(settings):
    settings.llm_targets = ["google_secops_yaral"]
    settings.ai_fill_gaps = ["qradar"]
    settings.targets = ["qradar_aql"]
    corr = CorrelationDraft(type="event_count", group_by=["IpAddress"], timespan="5m", gte=10, value_field="")
    pkg = _package("rule-001", _security("4625", corr=corr))
    pkg.queries = st.convert(pkg.rule_yaml, settings.targets)
    fake = FakeLLM(settings)
    pipeline._translate_llm(pkg, settings, fake)
    assert fake.calls == []
    assert any(q.target == "google_secops_yaral" and "built by code" in q.error for q in pkg.queries)


# --------------------------------------------------------------------------- client field normalization
@pytest.fixture
def acme(settings, tmp_path):
    d = tmp_path / "clients"
    d.mkdir()
    (d / "acme-splunk.yml").write_text(
        "name: acme extra\npriority: 2\ntransformations:\n"
        "  - id: acme_image\n    type: field_name_mapping\n    mapping:\n      Image: proc_path\n")
    (d / "acme.yaml").write_text(
        "name: acme\ntargets: [splunk, wazuh_rule]\n"
        "fields:\n  splunk: {DestinationIp: dest_ip, DestinationPort: dest_port}\n"
        "  wazuh_rule: {DestinationIp: data.dstip}\n"
        "pipelines:\n  splunk: [acme-splunk.yml]\n"
        "index_overrides: {splunk: index=acme_win}\n"
        "notes: {splunk: 'Network data in index=acme_fw'}\n")
    settings.clients_dir, settings.clients = str(d), ["acme"]
    return clients.active(settings)[0]


def _network_rule() -> str:
    s = copy.deepcopy(task_draft().sigma)
    s.logsource = LogSource(product="windows", category="network_connection", service="")
    s.selections = [Selection(name="selection", clauses=[Clause(conditions=[
        FieldCondition(field="Image", modifiers=["endswith"], values=["\\powershell.exe"]),
        FieldCondition(field="DestinationPort", modifiers=[], values=["4444"]),
        FieldCondition(field="DestinationIp", modifiers=["startswith"], values=["10."])])])]
    s.condition = "selection"
    return _rule(s)


def test_client_profile_renames_fields_for_its_siems(acme):
    y = _network_rule()
    (spl,) = st.convert(y, ["splunk"], acme.index_overrides, acme)
    assert spl.client == "acme" and "dest_ip" in spl.query and "dest_port" in spl.query and "proc_path" in spl.query
    assert spl.query.startswith("index=acme_win ") and "DestinationIp" not in spl.query
    wz = _one(y, "wazuh_rule", acme)
    assert 'name="data.dstip"' in wz.query and 'name="win.eventdata.destinationPort"' in wz.query   # client name kept
    fm = {f.sigma_field: f.targets for f in st.field_mappings(y, ["splunk"], acme)}
    assert fm["DestinationIp"]["splunk"] == "dest_ip"


def test_bad_profiles_fail_early(tmp_path, settings):
    d = tmp_path / "c"
    d.mkdir()
    (d / "x.yaml").write_text("name: x\nfields: {notasiem: {a: b}}\n")
    settings.clients_dir, settings.clients = str(d), ["x"]
    with pytest.raises(clients.ClientError, match="unknown target"):
        clients.active(settings)
    (d / "x.yaml").write_text("name: x\npipelines: {splunk: [../../etc/passwd]}\n")
    with pytest.raises(clients.ClientError, match="not found"):
        clients.active(settings)
    settings.clients = ["nobody"]
    (d / "x.yaml").write_text("name: x\n")
    with pytest.raises(clients.ClientError, match="no client profile nobody"):
        clients.active(settings)


def test_run_produces_client_queries_and_flags_unmapped_fields(settings, report_file, monkeypatch, acme):
    record, out, *_ = _run(settings, report_file, monkeypatch)
    p = record.packages[0]
    acme_q = [q for q in p.queries if q.client == "acme"]
    assert {q.target for q in acme_q} >= {"splunk", "wazuh_rule"}
    spl = next(q for q in acme_q if q.target == "splunk")
    assert "Not in client acme's field map" in spl.notes          # process fields the profile does not cover
    assert (out / "queries" / p.slug / "clients" / "acme" / "splunk.spl").is_file()
    assert "## Client queries" in (out / "report-summary.md").read_text()


# --------------------------------------------------------------------------- grounded AI translation
def test_ai_translation_gets_field_map_and_references_and_is_checked(settings, acme):
    settings.llm_targets, settings.ai_fill_gaps = [], []
    acme.llm_targets = ["google_secops_yaral"]
    acme.fields["google_secops_yaral"] = {"DestinationIp": "target.ip"}
    monkey = clients.active
    clients.active = lambda s: [acme]
    try:
        pkg = _package("rule-001", None, _network_rule())
        pkg.queries = st.convert(pkg.rule_yaml, settings.targets) + st.convert(pkg.rule_yaml, acme.targets, {}, acme)
        pkg.field_mappings = st.field_mappings(pkg.rule_yaml, settings.targets) + st.field_mappings(pkg.rule_yaml, acme.targets, acme)
        fake = FakeLLM(settings)
        pipeline._translate_llm(pkg, settings, fake)
    finally:
        clients.active = monkey
    (stage, prompt), = [c for c in fake.calls if c[0] == "translate"]
    assert '"DestinationIp":"target.ip"' in prompt and "<reference" in prompt and "index=acme_fw" not in prompt
    q = next(q for q in pkg.queries if q.client == "acme" and q.target == "google_secops_yaral")
    assert "CHECK:" in q.notes and "target.ip" in q.notes      # the fake answer ignored the map


def test_check_ai_query_catches_sigma_names_and_bad_xml():
    probs = pipeline.check_ai_query("SELECT * WHERE DestinationIp = '10.0.0.1'", {"DestinationIp": "dest_ip"}, "x")
    assert any("Sigma name DestinationIp" in p for p in probs)
    assert pipeline.check_ai_query("<rule id='1'><field>x</rule>", {}, "wazuh_ai")[0].startswith("not well-formed")
    assert "not a YARA-L" in pipeline.check_ai_query('graph $e.metadata.event_type = "PROCESS_LAUNCH"', {}, "google_secops_yaral")[0]
    assert not pipeline.check_ai_query("rule x {\n events:\n $e.metadata.event_type = \"PROCESS_LAUNCH\"\n condition:\n $e\n}",
                                       {}, "google_secops_yaral")
    kql = 'SecurityEvent | extend T = tostring(parse_xml(EventData).EventData.Data[@Name="TaskContent"])'
    assert "XPath" in pipeline.check_ai_query(kql, {}, "sentinel_ai")[0]


# --------------------------------------------------------------------------- multi-event chains
def _package(slug: str, sigma: SigmaDraft | None, rule_yaml: str | None = None, rid: str | None = None) -> DetectionPackage:
    d = task_draft()
    if sigma is not None:
        d.sigma = sigma
    rid = rid or f"{slug[-3:]:0>8}-1111-1111-1111-111111111111"
    b = Behaviour(**{**analysis().behaviours[0].model_dump(), "evidence_verified": [True]})
    return DetectionPackage(rule_id=rid, slug=slug, behaviour=b, draft=d, rule_yaml=rule_yaml or _rule(d.sigma, rid))


def test_chain_is_joined_by_code_for_each_language(settings):
    steps = [_package("rule-001", _security("4625")), _package("rule-002", _security("4624", {"LogonType": ["3"]})),
             _package("rule-003", _security("4698"))]
    c = chains.build(steps, slug="chain-001", name="Spray then task", ordered=True, within="10m", join_on="host",
                     source="analyst", evidence="", settings=settings)
    assert st.validate_rule(c.rule_yaml)[0]
    by = {q.target: q for q in c.queries}
    assert by["splunk"].query.startswith("| multisearch") and "first1<=last2" in by["splunk"].query
    assert by["elastic_eql"].query.startswith("sequence with maxspan=10m") and by["elastic_eql"].query.count("] by host.name") == 3
    assert "count_distinct(step)" in by["elastic_esql"].query
    assert all("not sent to the AI" in q.error for t, q in by.items() if t in ("qradar_aql", "opensearch"))
    assert all(q.method in ("template", "pysigma") for q in c.queries)
    assert "date_trunc(10 minutes, @timestamp)" in by["elastic_esql"].query


def test_chain_queries_keep_global_and_client_indexes(settings, acme):
    settings.index_overrides = {"splunk": "index=wineventlog", "elastic_esql": "logs-windows.*"}
    steps = [_package("rule-001", _security("4625")), _package("rule-002", _security("4698"))]
    c = chains.build(steps, slug="chain-001", name="x", ordered=True, within="10m", join_on="host",
                     source="analyst", evidence="", settings=settings, clients=[acme])
    by = {(q.client, q.target): q.query for q in c.queries}
    assert by[("", "splunk")].count("[search index=wineventlog ") == 2
    assert by[("acme", "splunk")].count("[search index=acme_win ") == 2
    assert by[("", "elastic_esql")].startswith("from logs-windows.* metadata")


def test_proposed_sequences_are_checked_and_built(settings, report_file, monkeypatch):
    def with_sequences():
        a = analysis()
        a.sequences = [
            SequenceDraft(name="Office macro then persistence", behaviour_ids=["B2", "B1"], ordered=True, within="1h",
                          join_on="host", evidence="The threat actor executed PowerShell with an encoded command"),
            SequenceDraft(name="Invented", behaviour_ids=["B1", "B2"], ordered=True, within="1h", join_on="host",
                          evidence="this quote is not in the report"),
            SequenceDraft(name="Unknown step", behaviour_ids=["B1", "B9"], ordered=True, within="1h", join_on="host",
                          evidence="The threat actor executed PowerShell with an encoded command")]
        return a
    monkeypatch.setattr("tests.conftest.analysis", with_sequences)
    record, out, *_ = _run(settings, report_file, monkeypatch)
    assert [s.name for s in record.analysis.sequences] == ["Office macro then persistence"]
    assert any("Invented' dropped" in w and "not in the report" in w for w in record.warnings)
    assert any("Unknown step' dropped" in w for w in record.warnings)
    (c,) = record.chains
    b2 = next(p.slug for p in record.packages if p.behaviour.id == "B2")
    assert c.steps[0] == b2 and c.source == "analysis"
    assert (out / "chains" / "chain-001" / "chain-001.yml").is_file()
    assert "Multi-event chains" in (out / "report-summary.md").read_text()
    from ti2dac.web.app import create_app

    page = TestClient(create_app(settings)).get(f"/runs/{record.run_id}").text
    assert 'id="chains"' in page and "ti2dac template" in page


def test_analyst_chain_and_rebuild_after_correction(settings, report_file, monkeypatch):
    record, out, *_ = _run(settings, report_file, monkeypatch)
    slugs = [p.slug for p in record.packages][:2]
    pipeline.add_chain(record, settings, slugs, name="Manual", within="30m", join_on="host", ordered=False)
    assert record.chains[0].source == "analyst" and "any order" not in record.chains[0].rule_yaml
    old = record.chains[0].rule_yaml
    fixed = st.render_rule(task_draft().sigma, rule_id=record.packages[0].rule_id, author="x", references=[], tags=[])
    pipeline.apply_correction(record, slugs[0], settings, corrected_yaml=fixed.replace("onlogon", "onstart"), llm=None)
    assert record.chains and record.chains[0].rule_yaml != old and "onstart" in record.chains[0].rule_yaml
    with pytest.raises(ValueError, match="2-4 existing rules"):
        pipeline.add_chain(record, settings, ["rule-999", slugs[0]], name="x", within="1h", join_on="host")


def test_chain_numbers_are_stable_when_new_chains_appear(settings, report_file, monkeypatch):
    record, *_ = _run(settings, report_file, monkeypatch)
    slugs = [p.slug for p in record.packages][:2]
    pipeline.add_chain(record, settings, slugs, name="Manual", within="30m", join_on="host")
    assert [(c.slug, c.name) for c in record.chains] == [("chain-001", "Manual")]
    behs = [p.behaviour.id for p in record.packages][:2]
    record.analysis.sequences.append(SequenceDraft(name="Proposed later", behaviour_ids=behs[::-1], ordered=True,
                                                   within="1h", join_on="host", evidence="x"))
    pipeline.rebuild_chains(record, settings)
    assert [(c.slug, c.name) for c in record.chains] == [("chain-001", "Manual"), ("chain-002", "Proposed later")]


def _run(settings, report_file, monkeypatch):
    from ti2dac.models import ReportAnalysis

    from . import conftest

    class Fake(FakeLLM):
        def structured(self, stage, system, user, schema):
            if schema is ReportAnalysis:   # looked up at call time: a test may patch conftest.analysis
                self.calls.append((stage, user))
                return conftest.analysis()
            return super().structured(stage, system, user, schema)

    fake = Fake(settings, bad_first=False)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a, **k: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(report_file), settings, store=store, actor="alice")
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename)
    store.register_run(record, str(out))
    return record, out, store, fake
