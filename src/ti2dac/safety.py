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
    (re.compile(r"\breg(\.exe)?\s+add\b|New-ItemProperty|Set-ItemProperty", re.I), re.compile(r"\breg(\.exe)?\s+delete\b|Remove-ItemProperty|Remove-Item", re.I), "registry value"),
    (re.compile(r"\bnet1?\s+user\s+\S+.*?/add|New-LocalUser|\buseradd\b", re.I), re.compile(r"\bnet1?\s+user\s+\S+\s+/del|Remove-LocalUser|\buserdel\b", re.I), "local account"),
    (re.compile(r"crontab\s+(-l.*\|\s*)?|/etc/cron", re.I), re.compile(r"crontab\s+-r|crontab\s+-l.*grep\s+-v|sed\s+-i.*cron|rm\s+.*cron", re.I), "cron entry"),
    (re.compile(r"systemctl\s+enable|/etc/systemd/system/", re.I), re.compile(r"systemctl\s+disable|rm\s+.*systemd", re.I), "systemd unit"),
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
                                        text=f"simulate creates a {what} but cleanup does not remove it"))
    return findings


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
