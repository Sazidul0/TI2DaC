"""Deterministic detection-quality checks on generated rules and model self-assessments."""
from __future__ import annotations

import re

import yaml

# System binaries (LOLBins) and widely-known tools that SigmaHQ legitimately detects by name.
KNOWN_BINARIES = set("""
powershell.exe pwsh.exe cmd.exe rundll32.exe regsvr32.exe mshta.exe wscript.exe cscript.exe certutil.exe
bitsadmin.exe schtasks.exe at.exe wmic.exe wmiprvse.exe net.exe net1.exe nltest.exe whoami.exe systeminfo.exe
ipconfig.exe tasklist.exe taskkill.exe reg.exe regedit.exe sc.exe vssadmin.exe wevtutil.exe bcdedit.exe
wbadmin.exe msiexec.exe installutil.exe msbuild.exe regasm.exe regsvcs.exe cmstp.exe odbcconf.exe forfiles.exe
mstsc.exe explorer.exe svchost.exe lsass.exe services.exe winlogon.exe userinit.exe taskhostw.exe dllhost.exe
conhost.exe rdpclip.exe notepad.exe wordpad.exe calc.exe winword.exe excel.exe powerpnt.exe outlook.exe
onenote.exe msedge.exe chrome.exe firefox.exe iexplore.exe curl.exe tar.exe expand.exe extrac32.exe
makecab.exe esentutl.exe ntdsutil.exe dsquery.exe csvde.exe ldifde.exe quser.exe qwinsta.exe query.exe
nslookup.exe ping.exe route.exe netsh.exe arp.exe hostname.exe findstr.exe find.exe attrib.exe icacls.exe
takeown.exe cipher.exe fsutil.exe diskshadow.exe robocopy.exe xcopy.exe sdbinst.exe mavinject.exe
psexec.exe psexesvc.exe paexec.exe procdump.exe procdump64.exe sysmon.exe sysmon64.exe 7z.exe 7za.exe
winrar.exe rar.exe rclone.exe anydesk.exe teamviewer.exe screenconnect.clientservice.exe atera.exe
ngrok.exe plink.exe putty.exe winscp.exe mimikatz.exe rubeus.exe sharphound.exe adfind.exe bloodhound.exe
nanodump.exe lazagne.exe advanced_ip_scanner.exe netscan.exe megasync.exe filezilla.exe
applicationframehost.exe runtimebroker.exe sihost.exe werfault.exe searchprotocolhost.exe searchindexer.exe
smss.exe csrss.exe wininit.exe lsm.exe spoolsv.exe ctfmon.exe fontdrvhost.exe dwm.exe audiodg.exe wermgr.exe
backgroundtaskhost.exe smartscreen.exe securityhealthservice.exe msmpeng.exe reagentc.exe consent.exe
comsvcs.dll ntdll.dll kernel32.dll dbghelp.dll dbgcore.dll samlib.dll vaultcli.dll wininet.dll
""".split())

_FILE = re.compile(r"[\w.-]{1,64}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr|sys|sh|py|elf|so|lnk|jar)\b", re.I)


# PE version-info fields survive a rename (changing them means editing the binary's resources), so naming a
# file there is the robust way to catch renamed tools and masquerading copies, not an IOC.
_PE_FIELDS = {"originalfilename", "product", "description", "company", "internalname"}


def _values(node, out: list[str]) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if str(k).split("|")[0].lower() not in _PE_FIELDS:
                _values(v, out)
    elif isinstance(node, list):
        for v in node:
            _values(v, out)
    elif isinstance(node, str):
        out.append(node)


def brittle_artifacts(rule_yaml: str, report_file_names: list[str]) -> list[str]:
    """File names in positive selections that come from this report and are not system/known tools.

    Attackers rename such artifacts for free, so a rule that depends on them is an IOC in disguise.
    """
    try:
        from .sigma_tools import first_doc

        det = first_doc(rule_yaml)["detection"]
    except Exception:
        return []
    report = {f.lower() for f in report_file_names}
    values: list[str] = []
    for name, sel in det.items():
        if name != "condition" and not name.startswith("filter"):
            _values(sel, values)
    hits = {m.group(0).lower() for v in values for m in _FILE.finditer(v)}
    return sorted(h for h in hits if h in report and h not in KNOWN_BINARIES)


# Techniques whose real behaviour cannot be reproduced safely; the model tends to rate them 5/5.
UNSAFE_TO_SIMULATE = ("T1003", "T1555", "T1552.002", "T1485", "T1486", "T1561", "T1529", "T1495")


def calibrate_scores(technique_id: str, scores) -> str:
    """Cap self-reported reproducibility for techniques that need real credential/destructive actions."""
    if technique_id.upper().startswith(UNSAFE_TO_SIMULATE) and scores.reproducibility > 2:
        scores.reproducibility = 2
        return f"{technique_id}: reproducibility capped at 2 (cannot be simulated safely; needs an approved Atomic test)"
    return ""
