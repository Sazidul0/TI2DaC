"""Safety controls for generated simulation scripts.

The tool never executes scripts. Generated scripts are still treated as untrusted:
  * a linter blocks dangerous content (real credential theft, destructive commands,
    external downloads, security-tool tampering) and warns on risky-but-legitimate actions;
  * PowerShell -EncodedCommand payloads are decoded and linted too;
  * persistence created by `simulate` must be undone by `cleanup`;
  * every script gets a lab guard header that refuses to run unless TI2DAC_LAB=1.
A blocked script is replaced with a stub; the guide still documents the behaviour.
"""
from __future__ import annotations

import base64
import re

from .models import LintFinding

_LOCAL_URL = re.compile(r"https?://(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|example\.(?:com|org|net))(?:[:/]|\b)", re.I)

BLOCK_RULES: list[tuple[str, re.Pattern]] = [
    ("credential-dumping", re.compile(r"\b(sekurlsa|lsadump|mimikatz|Out-Minidump|Invoke-Mimikatz|pypykatz|nanodump|safetykatz)\b", re.I)),
    ("lsass-access", re.compile(r"lsass", re.I)),
    ("hive-export", re.compile(r"\breg(\.exe)?\s+save\s+\S*(sam|security|system)\b", re.I)),
    ("ntds-export", re.compile(r"ntdsutil.*\b(ifm|ac\s+i\s+ntds)\b|\bntds\.dit\b", re.I)),
    # Deleting shadows is allowed only against a ti2dac_ dummy volume or the nil shadow ID (both fail harmlessly
    # but still log the command line the rule needs).
    ("shadow-deletion", re.compile(r"vssadmin(\.exe)?\s+(delete\s+shadows?\b(?!.*?(?:/for=ti2dac|/shadow=\{0{8}-0{4}-0{4}-0{4}-0{12}\}))|resize\s+shadow)|shadowcopy\s+delete|wbadmin\s+delete|Win32_ShadowCopy.*Delete", re.I)),
    ("boot-config-tamper", re.compile(r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", re.I)),
    ("disk-destruction", re.compile(r"\bcipher(\.exe)?\s+/w|\bformat\s+[a-z]:|\bdiskpart\b|\bdd\s+if=.*\bof=/dev/(sd|nvme|hd)|\bmkfs\.|\bshred\b", re.I)),
    ("recursive-root-delete", re.compile(r"rm\s+-[a-z]*r[a-z]*f?\s+(/|/\*|~|\$HOME)(\s|$)|Remove-Item\s+.*-Recurse.*\b(C:\\(Windows|Users|Program Files)\\?)(\s|'|\"|$)|\bdel\s+/[sq].*\b[a-z]:\\\s*$", re.I)),
    ("log-clearing", re.compile(r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog|auditctl\s+-D\b|>\s*/var/log/", re.I)),
    ("file-encryption", re.compile(r"\b(AesManaged|AesCryptoServiceProvider|openssl\s+enc)\b.*(Get-ChildItem|find\s)", re.I)),
]
WARN_RULES: list[tuple[str, re.Pattern]] = [
    ("defender-tamper", re.compile(r"Set-MpPreference\s+.*-Disable|Add-MpPreference\s+.*-Exclusion|DisableAntiSpyware|DisableRealtimeMonitoring", re.I)),
    ("firewall-tamper", re.compile(r"netsh\s+(adv)?firewall\s+.*(off|disable)|ufw\s+disable|iptables\s+-F", re.I)),
    ("account-creation", re.compile(r"\bnet1?\s+user\s+\S+\s+\S*\s*/add|New-LocalUser|\buseradd\b|\badduser\b", re.I)),
    ("privilege-change", re.compile(r"\bnet1?\s+localgroup\s+administrators\b.*/add|Add-LocalGroupMember|usermod\s+-aG\s+(sudo|wheel)", re.I)),
    ("reboot", re.compile(r"\bshutdown(\.exe)?\s|Restart-Computer|\breboot\b", re.I)),
    # Reversible (reagentc /enable), so the simulation may do it for the rule's command line; review it anyway.
    ("recovery-tamper", re.compile(r"\breagentc(\.exe)?\s+[/-]disable\b", re.I)),
    ("process-kill", re.compile(r"taskkill\s+.*/im\s+(?!notepad|calc)|Stop-Process\s+-Name\s+(?!notepad|calc)|\bpkill\b|\bkillall\b", re.I)),
]
_DOWNLOAD = re.compile(
    r"(Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|DownloadString|DownloadFile|DownloadData|Start-BitsTransfer"
    r"|bitsadmin\s+/transfer|certutil(\.exe)?\s+.*-urlcache|\bcurl\b|\bwget\b|Net\.WebClient|mshta\s+https?:|regsvr32\s+.*/i:https?:)",
    re.I,
)
_URL = re.compile(r"https?://\S+", re.I)
_ENC = re.compile(r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)

# simulate pattern -> cleanup must contain one of these
PERSISTENCE_PAIRS = [
    (re.compile(r"schtasks(\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTask", re.I), re.compile(r"schtasks(\.exe)?\s+/delete|Unregister-ScheduledTask", re.I), "scheduled task"),
    (re.compile(r"\bsc(\.exe)?\s+create\b|New-Service", re.I), re.compile(r"\bsc(\.exe)?\s+delete\b|Remove-Service|Delete\(\)", re.I), "service"),
    # Removing a temp file is not removing the value: Remove-Item only counts on a registry path.
    (re.compile(r"\breg(\.exe)?\s+add\b|New-ItemProperty|Set-ItemProperty", re.I),
     re.compile(r"\breg(\.exe)?\s+delete\b|Remove-ItemProperty|Remove-Item\s+.*(HK(LM|CU|CR|U|EY_\w+):|Registry::)", re.I),
     "registry value"),
    (re.compile(r"\breagentc(\.exe)?\s+[/-]disable\b", re.I), re.compile(r"\breagentc(\.exe)?\s+[/-]enable\b", re.I),
     "disabled Windows Recovery Environment"),
    (re.compile(r"\bnet1?\s+user\s+\S+.*?/add|New-LocalUser|\buseradd\b", re.I), re.compile(r"\bnet1?\s+user\s+\S+\s+/del|Remove-LocalUser|\buserdel\b", re.I), "local account"),
    (re.compile(r"crontab\s+(-l.*\|\s*)?|/etc/cron", re.I), re.compile(r"crontab\s+-r|crontab\s+-l.*grep\s+-v|sed\s+-i.*cron|rm\s+.*cron", re.I), "cron entry"),
    (re.compile(r"systemctl\s+enable|/etc/systemd/system/", re.I), re.compile(r"systemctl\s+disable|rm\s+.*systemd", re.I), "systemd unit"),
    # Security and system state the warn rules allow (for the rule's command line) must be put back as well.
    (re.compile(r"Add-MpPreference\s+.*-Exclusion\w*", re.I), re.compile(r"Remove-MpPreference\s+.*-Exclusion\w*", re.I),
     "Defender exclusion"),
    (re.compile(r"Set-MpPreference\s+.*-Disable\w+\s+(\$true|1)\b", re.I),
     re.compile(r"Set-MpPreference\s+.*-Disable\w+\s+(\$false|0)\b", re.I), "disabled Defender setting"),
    (re.compile(r"netsh\s+(adv)?firewall\s+.*\b(state\s+off|opmode\s+disable)|Set-NetFirewallProfile\s+.*-Enabled\s+"
                r"(False|\$false|0)\b|\bufw\s+disable", re.I),
     re.compile(r"netsh\s+(adv)?firewall\s+.*\b(state\s+on|opmode\s+enable)|Set-NetFirewallProfile\s+.*-Enabled\s+"
                r"(True|\$true|1)\b|\bufw\s+enable", re.I), "disabled firewall"),
    (re.compile(r"netsh\s+advfirewall\s+firewall\s+add\s+rule|New-NetFirewallRule", re.I),
     re.compile(r"netsh\s+advfirewall\s+firewall\s+delete\s+rule|Remove-NetFirewallRule", re.I), "firewall rule"),
    (re.compile(r"\bnet1?\s+localgroup\s+\S+.*?/add|Add-LocalGroupMember|usermod\s+-a?G", re.I),
     re.compile(r"\bnet1?\s+localgroup\s+\S+.*?/del|Remove-LocalGroupMember|gpasswd\s+-d|\bdeluser\s+\S+\s+\S+", re.I),
     "group membership"),
    (re.compile(r"__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding", re.I),
     re.compile(r"Remove-WmiObject|Remove-CimInstance|\.Delete\(\)", re.I), "WMI event subscription"),
    (re.compile(r"\\Start Menu\\Programs\\Startup\b|shell:startup|\[Environment\]::GetFolderPath\(['\"]Startup", re.I),
     re.compile(r"(Remove-Item|\bdel\b|\berase\b).*(Startup|\$startup)", re.I), "Startup-folder file"),
    (re.compile(r"auditpol(\.exe)?\s+/set\s+.*:disable", re.I), re.compile(r"auditpol(\.exe)?\s+(/set\s+.*:enable|/restore)", re.I),
     "disabled audit policy"),
    (re.compile(r"\bsc(\.exe)?\s+config\s+\S+\s+start=\s*disabled|Set-Service\s+.*-StartupType\s+Disabled", re.I),
     re.compile(r"\bsc(\.exe)?\s+config\s+\S+\s+start=\s*(auto|demand|delayed-auto)|Set-Service\s+.*-StartupType\s+"
                r"(Automatic|Manual)", re.I), "disabled service"),
    (re.compile(r">>\s*\S*authorized_keys", re.I), re.compile(r"authorized_keys", re.I), "SSH authorized key"),
    (re.compile(r">>\s*\S*(\.bashrc|\.bash_profile|\.profile|\.zshrc)\b", re.I),
     re.compile(r"(sed\s+-i|grep\s+-v|cp\s+\S+\s+\S*|mv\s+\S+\s+\S*)\S*(\.bashrc|\.bash_profile|\.profile|\.zshrc)", re.I),
     "shell profile line"),
]


def _decode_encoded(script: str) -> list[str]:
    out = []
    for m in _ENC.finditer(script):
        try:
            out.append(base64.b64decode(m.group(1) + "==").decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    return out


_SPLIT_ARGS = re.compile(r"(?i)\bStart-Process\b|-(FilePath|ArgumentList|Wait|NoNewWindow|PassThru|WindowStyle\s+\w+)\b|[\"'`,()@]")


def flatten(script: str) -> str:
    """Re-join commands split across Start-Process/-ArgumentList, quotes or string arrays so that
    `Start-Process vssadmin.exe -ArgumentList "delete shadows"` is linted like `vssadmin.exe delete shadows`."""
    code = "\n".join(ln for ln in script.splitlines() if not ln.strip().startswith(("#", "//", "REM ", "::")))
    text = _SPLIT_ARGS.sub(" ", code)
    text = re.sub(r"\$env:\w+|%\w+%", "", text)
    text = re.sub(r"[A-Za-z]:\\(?:[^\s\\]+\\)*|\\(?:[^\s\\]+\\)+", "", text)   # drop directory prefixes
    return re.sub(r"\s+", " ", text)


def lint_script(script: str, cleanup: str = "") -> list[LintFinding]:
    """Regex linter: defense in depth, not a sandbox. A determined author can still evade it, which is
    why scripts are never executed by the tool and require human review before lab use."""
    findings: list[LintFinding] = []
    sources = [(script, 0)] + [(d, -1) for d in _decode_encoded(script)] + [(flatten(script), -2)]
    for text, base in sources:
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//", "REM ", "::")):
                continue
            lineno = i if base == 0 else 0
            label = (stripped[:160] if base == 0 else f"[decoded -EncodedCommand] {stripped[:140]}" if base == -1
                     else f"[flattened] {stripped[:140]}")
            for name, pat in BLOCK_RULES:
                if pat.search(stripped) and not (base == -2 and any(f.rule == name for f in findings)):
                    findings.append(LintFinding(severity="block", rule=name, line=lineno, text=label))
            if base == -2:
                continue   # flattened text is only for block rules
            for name, pat in WARN_RULES:
                if pat.search(stripped):
                    findings.append(LintFinding(severity="warn", rule=name, line=lineno, text=label))
            if _DOWNLOAD.search(stripped):
                urls = _URL.findall(stripped)
                if not urls or any(not _LOCAL_URL.match(u) for u in urls):
                    findings.append(LintFinding(severity="block", rule="external-network", line=lineno, text=label))
    for created, removed, what in PERSISTENCE_PAIRS:
        if created.search(script) and not removed.search(cleanup):
            findings.append(LintFinding(severity="warn", rule="missing-cleanup", line=0,
                                        text=f"cleanup does not undo the {what} that simulate creates or changes"))
    findings += _unconditional_restore(script, cleanup)
    return findings


_STATE_TOGGLES = [   # (simulate turns it off, cleanup turns it on, what)
    (re.compile(r"\breagentc(\.exe)?\s+[/-]disable\b", re.I), re.compile(r"\breagentc(\.exe)?\s+[/-]enable\b", re.I),
     "Windows Recovery Environment"),
    (re.compile(r"Set-MpPreference\s+.*-Disable\w+\s+(\$true|1)\b", re.I),
     re.compile(r"Set-MpPreference\s+.*-Disable\w+\s+(\$false|0)\b", re.I), "Defender setting"),
    (re.compile(r"netsh\s+(adv)?firewall\s+.*\bstate\s+off|Set-NetFirewallProfile\s+.*-Enabled\s+(False|\$false|0)\b", re.I),
     re.compile(r"netsh\s+(adv)?firewall\s+.*\bstate\s+on|Set-NetFirewallProfile\s+.*-Enabled\s+(True|\$true|1)\b", re.I),
     "firewall"),
    (re.compile(r"auditpol(\.exe)?\s+/set\s+.*:disable", re.I), re.compile(r"auditpol(\.exe)?\s+/set\s+.*:enable", re.I),
     "audit policy"),
]


def _unconditional_restore(script: str, cleanup: str) -> list[LintFinding]:
    """Cleanup that re-enables a setting must check the state saved before the test: a lab VM where it was already
    off would otherwise be left changed. A restore line with no `if` on it or just above it is unconditional."""
    out = []
    lines = cleanup.splitlines()
    for off, on, what in _STATE_TOGGLES:
        if not off.search(script):
            continue
        for i, ln in enumerate(lines):
            if on.search(ln) and not any(re.search(r"\bif\b", x, re.I) for x in lines[max(0, i - 2):i + 1]):
                out.append(LintFinding(severity="warn", rule="unconditional-restore", line=i + 1,
                                       text=f"cleanup restores the {what} without checking its state before the test; "
                                            "if it was already off, cleanup changes the VM. Save the prior state in "
                                            "simulate and restore only that."))
    return out


def lab_guard(language: str) -> str:
    if language == "powershell":
        return (
            "# --- ti2dac lab guard: refuses to run outside an isolated lab ---\n"
            "if ($env:TI2DAC_LAB -ne '1') {\n"
            "    Write-Error 'Lab-only simulation. Set $env:TI2DAC_LAB=1 in an ISOLATED lab VM to run.'; exit 1\n"
            "}\n"
            "$ErrorActionPreference = 'Stop'\n"
        )
    if language == "bash":
        return (
            "# --- ti2dac lab guard: refuses to run outside an isolated lab ---\n"
            "if [ \"${TI2DAC_LAB:-}\" != \"1\" ]; then\n"
            "  echo 'Lab-only simulation. export TI2DAC_LAB=1 in an ISOLATED lab VM to run.' >&2; exit 1\n"
            "fi\n"
            "set -euo pipefail\n"
        )
    return (
        "# --- ti2dac lab guard ---\n"
        "import os, sys\n"
        "if os.environ.get('TI2DAC_LAB') != '1':\n"
        "    sys.exit('Lab-only simulation. Set TI2DAC_LAB=1 in an ISOLATED lab VM to run.')\n"
    )


def blocked_stub(language: str, findings: list[LintFinding]) -> str:
    reasons = "; ".join(sorted({f.rule for f in findings if f.severity == "block"}))
    msg = f"Generated simulation was BLOCKED by the safety linter ({reasons}). Use the Atomic Red Team test referenced in README.md or write a reviewed script."
    if language == "powershell":
        return f"Write-Error '{msg}'\nexit 1\n"
    if language == "bash":
        return f"echo '{msg}' >&2\nexit 1\n"
    return f"import sys\nsys.exit({msg!r})\n"
