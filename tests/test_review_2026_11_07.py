"""Fixes from the 2026-11-07 review of the Salat (WebRAT) run output."""
from __future__ import annotations

import re

import pytest

from ti2dac import attack, iocs, redact, regexes, safety
from ti2dac import sigma_tools as st
from ti2dac.pipeline import _passthrough

_RUN_KEY = r"""title: Run key to random AppData exe
id: d9586855-30fb-56ad-890f-b744f3cc3e0f
status: experimental
logsource: {product: windows, category: registry_set}
detection:
  selection_key:
    TargetObject|contains: '\Microsoft\Windows\CurrentVersion\Run'
  selection_value:
    Details|re|i: '\\AppData\\Roaming\\[a-z0-9]{14}\\[a-z0-9]{5}\.exe'
  filter_installer:
    Image|endswith: '\msiexec.exe'
  condition: selection_key and selection_value and not 1 of filter_*
level: high
"""

_REAGENTC = r"""title: WinRE disabled
id: 723ff70c-6703-5ee5-8219-64aabe455c79
status: experimental
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    - Image|endswith: '\reagentc.exe'
    - OriginalFileName: reagentc.exe
  selection_cli:
    CommandLine|windash|contains: ' /disable'
  filter_main_mgmt:
    ParentImage|endswith: ['\ccmexec.exe', '\TiWorker.exe']
  condition: selection_img and selection_cli and not 1 of filter_*
level: high
"""

_VALUE = r"C:\Users\v\AppData\Roaming\bpr10xf4s4k72i\w5soi.exe"


# --------------------------------------------------------------------------- regex semantics
@pytest.mark.parametrize("pattern,flags", [
    (r"\\AppData\\Roaming\\[a-z0-9]{14}\\[a-z0-9]{5}\.exe", re.I),
    (r"^C:\\Users\\", 0), (r"w5soi\.exe$", 0), (r"^nope|bpr10", 0), (r"(?:roaming|local)\\bpr", re.I),
])
def test_whole_value_pattern_keeps_sigma_search_meaning(pattern, flags):
    whole = regexes.anchor(pattern)
    if flags & re.I:
        whole = regexes.fold_case(whole)
    for s in (_VALUE, _VALUE.upper(), "unrelated"):
        assert bool(re.fullmatch(whole, s, re.S)) == bool(re.search(pattern, s, flags)), (pattern, s)


def test_lucene_syntax_and_unsupported_constructs():
    assert regexes.to_lucene(r"(?:a|b)\d+@x") == r"(a|b)[0-9]+\@x"
    assert regexes.fold_case("[^a-z-]") == "[^a-zA-Z-]"
    assert "lookaround" in regexes.lucene_problems(r"foo(?=bar)")
    assert regexes.lucene_problems(r"\\AppData\\[a-z]{3}\.exe") == []


def test_anchored_engines_get_whole_value_regexes():
    by = {q.target: q for q in st.convert(_RUN_KEY, ["elastic_lucene", "opensearch", "wazuh_indexer", "elastic_esql",
                                                     "elastic_eql", "loki", "splunk", "defender_xdr"])}
    for t in ("elastic_lucene", "opensearch", "wazuh_indexer"):
        q = by[t].query
        assert "/.*\\\\[aA][pP][pP][dD][aA][tT][aA]" in q and ".[eE][xX][eE].*/" in q and "(?i)" not in q, t
    assert 'rlike ".*\\\\\\\\[aA][pP]' in by["elastic_esql"].query and "(?i)" not in by["elastic_esql"].query
    # EQL: the regex sits in an EQL string, so a literal backslash is \\\\ there; regex~ is the case-insensitive form
    assert 'regex~ ".*\\\\\\\\AppData\\\\\\\\Roaming\\\\\\\\[a-z0-9]{14}' in by["elastic_eql"].query
    assert "Details=~`(?i).*\\\\AppData" in by["loki"].query and "exe.*`" in by["loki"].query
    # unanchored engines keep the Sigma pattern as it was
    assert '"(?i)\\\\\\\\AppData' in by["splunk"].query and "matches regex \"(?i)\\\\\\\\AppData" in by["defender_xdr"].query


def test_eql_case_sensitive_regex_uses_plain_regex_operator():
    rule = _RUN_KEY.replace("Details|re|i:", "Details|re:")
    (q,) = st.convert(rule, ["elastic_eql"])
    assert " regex \".*" in q.query and "regex~" not in q.query


def test_loki_groups_expanded_values_inside_and():
    (q,) = st.convert(_REAGENTC, ["loki"])
    head, _, rest = q.query.partition(") and (CommandLine=~")
    group, _, tail = rest.partition(") and ParentImage!~")
    assert head and tail and group.count(" or CommandLine=~") == 4, q.query


# --------------------------------------------------------------------------- redaction / AI translation
def test_windows_path_segments_are_not_unc_hosts():
    sent = r"Details|re|i: \\AppData\\Roaming\\[a-z0-9]{14}\\x.exe"
    assert redact.redact(sent).text == sent
    assert "[HOST_1]" in redact.redact(r"copy \\FILESRV01\share\a.exe").text


def test_pass_through_fields_are_not_given_to_the_ai():
    assert _passthrough("crowdstrike_cql", "TargetObject", "TargetObject")
    assert not _passthrough("crowdstrike_cql", "CommandLine", "CommandLine")     # native Falcon name
    assert not _passthrough("crowdstrike_cql", "Image", "ImageFileName")
    assert not _passthrough("splunk", "Image", "Image")                          # not a renaming target


# --------------------------------------------------------------------------- IOCs
_REPORT = """SHA-256 c3026c37c027041f92fd716d4720c0b9da2b0e714546cda16f2bc0f486375572
MD5 6ec1fc5a577ec6b6948f33f8fc414036
Imphash 1aae8bf580c846f39c71c05898e57e88 (the generic Go-runtime imphash)
One is the RC4 key in hex,
29c8d34a14ac9527dc0e459668595d56 . The key is AES-GCM-encrypted in the binary under chain(md5("biba")) =
93851482190d261c1302a29caa569522 .
In the lab the ID was bb977c07233235349b32b7e2eac54bcc and the check-in sent {"2":"bb977c07233235349b32b7e2eac54bcc"}
The 198.18.0.0/15 addresses are the lab's fake DNS answers. DoH to 1.1.1.1 and dns.google; code from golang.org/x/crypto.
URL https://gitlab.com/webrat1/importantfiles/-/raw/mai
n/{7z.dll, 7z.exe, MSTSCLib.dll, AxMSTSCLib.dll, ff
mpeg.exe}
ffdesktop drives the downloaded ffmpeg.exe for video. The loader
w5soi.exe runs from AppData.
6 https://tonapi.io/v2/dns/remoteadministratortool.
ton/resolve
https://tonapi.io/v2/dns/webratpanel.ton/resolve
TON name remoteadministratortool.ton, webratpanel.ton
Salat holds the mutex Global\\WEBR_V4CTHH83SX7G . Store installs under Local\\Packages .
Detect Global\\WEBR_V4* in memory. It finds lsass.exe and reads key4.db without nss3.dll; payload 203.0.113.9 and 45.9.20.1
T1036.005 /
.001
Masquerading
T1027.002 / .007 / .013 Obfuscation
"""


def test_ioc_extraction_drops_keys_lab_addresses_and_legit_names():
    i = iocs.extract_iocs(_REPORT)
    assert i.md5 == ["6ec1fc5a577ec6b6948f33f8fc414036"]
    for v in ("1aae8bf580c846f39c71c05898e57e88", "29c8d34a14ac9527dc0e459668595d56",
              "93851482190d261c1302a29caa569522", "bb977c07233235349b32b7e2eac54bcc"):
        assert v in i.excluded
    assert i.ipv4 == ["45.9.20.1"] and {"198.18.0.0", "1.1.1.1", "203.0.113.9"} <= set(i.excluded)
    assert "golang.org" not in i.domains and "golang.org" in i.excluded
    assert {"remoteadministratortool.ton", "webratpanel.ton"} <= set(i.domains)
    assert "lsass.exe" not in i.file_names and "nss3.dll" in i.excluded
    assert "ffmpeg.exe" in i.file_names and "mpeg.exe" not in i.file_names
    assert "w5soi.exe" in i.file_names   # at a line start after a whole word: not a fragment
    assert i.mutexes == ["Global\\WEBR_V4CTHH83SX7G"]


def test_urls_cut_by_line_wraps_are_joined():
    urls = iocs.extract_iocs(_REPORT).urls
    assert "https://gitlab.com/webrat1/importantfiles/-/raw/main/" in urls
    assert "https://tonapi.io/v2/dns/remoteadministratortool.ton/resolve" in urls
    assert "https://tonapi.io/v2/dns/webratpanel.ton/resolve" in urls
    assert not any(u.count("https://") > 1 for u in urls)


def test_attack_shorthand_sub_techniques_are_expanded():
    ids = iocs.extract_iocs(_REPORT).attack_ids
    assert {"T1036.005", "T1036.001", "T1027.002", "T1027.007", "T1027.013"} <= set(ids)


# --------------------------------------------------------------------------- ATT&CK / lint
def test_revoked_technique_moves_to_its_successor():
    new, note = attack.resolve_revoked("T1562.001")
    if attack.lookup("T1562.001") is None or not attack.lookup("T1562.001").get("revoked"):
        pytest.skip("bundled ATT&CK index predates v20")
    assert new == "T1685" and "revoked" in note
    assert attack.resolve_revoked("T1490") == ("T1490", "")


def test_unconditional_winre_restore_is_flagged():
    rules = {f.rule for f in safety.lint_script("reagentc /disable", "reagentc /enable")}
    assert "unconditional-restore" in rules
    ok = safety.lint_script("reagentc /disable", "if ($before -match 'Enabled') {\n  reagentc /enable\n}")
    assert "unconditional-restore" not in {f.rule for f in ok}


# --------------------------------------------------------------------------- same classes, found across SigmaHQ
@pytest.mark.parametrize("text", [
    r"TargetFilename|endswith: \\WindowsPowerShell\\Modules\\x.psm1",     # escaped path, not \\host\share
    r"PipeName|re: \\mojo\.5688\.8052",                                    # regex, not a UNC host
    r"C:\Windows\System32\logonUI.exe.local",                              # DLL redirection folder, not a .local host
    "echo x >> /etc/rc.local", "cfgpath: user.local", "-Dcatalina.home=/opt/tomcat",
    r"\Users\Contacts\ and \Users\Searches\ and /home/httpd/html", "os.dup2(s.fileno(),0); cmd=c.gets",
    "w.nessus.org/nessus", "sa-id-gen@1.0.4", r"(e.g. \\attacker.com\share)",
])
def test_redaction_leaves_rule_syntax_alone(text):
    assert redact.redact(text).mapping == {}, redact.redact(text).text


@pytest.mark.parametrize("text,secret", [
    (r"copy \\FILESRV01\share\a.exe", "FILESRV01"), (r"net use \\FS01\data", "FS01"),
    (r'{"Path": "\\\\SRV-APP01\\share"}', "SRV-APP01"), ("contact j.smith.", "j.smith"),
    ("runas /user:svc-sql.", "svc-sql"), ("dc01.acme.local", "dc01"), (r"C:\Users\jdoe\x", "jdoe"),
    ("the beacon went to 10.0.0.5.", "10.0.0.5"),
])
def test_redaction_still_hides_identities(text, secret):
    assert secret not in redact.redact(text).text


def test_ioc_ranges_script_names_reference_links_and_glued_commands():
    t = ("Block 20.140.0.0/14 and 224.0.0.0. Payload 45.9.20.1. Run 00.sh then wmiexec.py; WshShell.Run and "
         "process.name fields. Fetched http://temp.sh/x/a.exe and http://107.178.101.245:5488/l64;chmod and "
         "http://h.example.ru/p;jsessionid=1. Follow https://twitter.com/x and https://www.crowdstrike.com/blog/x. "
         "Dropped msbuild.exe, werfault.exe and evil32.exe.")
    i = iocs.extract_iocs(t)
    assert i.ipv4 == ["45.9.20.1", "107.178.101.245"] and "20.140.0.0" in i.excluded and "224.0.0.0" in i.excluded
    assert "temp.sh" in i.domains and not {"00.sh", "wmiexec.py", "wshshell.run", "process.name"} & set(i.domains)
    assert "http://107.178.101.245:5488/l64" in i.urls and "http://h.example.ru/p;jsessionid=1" in i.urls
    assert not any("twitter" in u or "crowdstrike" in u for u in i.urls)
    assert {"evil32.exe", "00.sh", "wmiexec.py"} <= set(i.file_names)   # attacker scripts are file IOCs, not domains
    assert not {"msbuild.exe", "werfault.exe"} & set(i.file_names)


def test_coverage_gaps_are_not_reported_as_failures():
    for err in ["SigmaTransformationError: Unable to determine table name from rule.",
                "SigmaTransformationError: Crowdstrike Query Language does not support the ParentCommandLine field",
                "SigmaTransformationError: Only file name of parent image is available in CrowdStrike Query Language events.",
                "SigmaFeatureNotSupportedByBackendError: ORing CIDR matching is not yet supported by LogScale backend",
                "InvalidHashAlgorithmError: No valid hash algo found in Hashes field.",
                "NotImplementedError: SigmaCIDRExpression values (e.g. cidr) have no Wazuh rule equivalent here"]:
        assert st.conversion_problem(err) == "not-available", err
    assert st.conversion_problem("AttributeError: 'X' object has no attribute 'y'") == "failed"


_CIDR = r"""title: cidr
id: 5f8e8a31-1d41-4c1e-9b4e-6f3f0b0b0b0b
status: experimental
logsource: {product: windows, category: network_connection}
detection:
  selection:
    Image|endswith: '\cmstp.exe'
  filter:
    DestinationIp|cidr: ['10.0.0.0/8', '192.168.0.0/16']
  condition: selection and not filter
level: high
"""


def test_qradar_converts_cidr_with_incidr():
    (q,) = st.convert(_CIDR, ["qradar_aql"])
    assert q.error is None and "INCIDR('10.0.0.0/8', destinationip)" in q.query


def test_crowdstrike_drops_an_unsupported_or_alternative():
    rule = _REAGENTC.replace("    - OriginalFileName: reagentc.exe\n", "    - Description: reagentc\n")
    (q,) = st.convert(rule, ["crowdstrike_cql"])
    assert q.query and "Description" not in q.query and "reagentc" in q.query and "Converted without" in q.notes


def test_more_state_changes_need_cleanup():
    cases = [("Add-MpPreference -ExclusionPath C:\\ti2dac", "Remove-MpPreference -ExclusionPath C:\\ti2dac"),
             ("netsh advfirewall firewall add rule name=ti2dac dir=in action=allow", "netsh advfirewall firewall delete rule name=ti2dac"),
             ("net localgroup administrators ti2dac /add", "net localgroup administrators ti2dac /delete"),
             ("sc config Spooler start= disabled", "sc config Spooler start= demand"),
             ("echo k >> ~/.ssh/authorized_keys", "sed -i '/k/d' ~/.ssh/authorized_keys")]
    for sim, clean in cases:
        assert "missing-cleanup" in {f.rule for f in safety.lint_script(sim, "Write-Host x")}, sim
        assert "missing-cleanup" not in {f.rule for f in safety.lint_script(sim, clean)}, sim
    fw = safety.lint_script("netsh advfirewall set allprofiles state off", "netsh advfirewall set allprofiles state on")
    assert "unconditional-restore" in {f.rule for f in fw}


def test_revoked_attack_tag_in_a_rule_is_reported():
    if not (attack.lookup("T1562.001") or {}).get("revoked"):
        pytest.skip("bundled ATT&CK index predates v20")
    ok, issues = st.validate_rule(_REAGENTC.replace("level: high", "tags: [attack.t1562.001]\nlevel: high"))
    assert ok and any("RevokedATTACKTag" in i and "attack.t1685" in i for i in issues)
    assert attack.predecessors("T1685") == ["T1562.001"]


def test_lessons_under_a_revoked_id_reach_its_successor(tmp_path):
    if not (attack.lookup("T1562.001") or {}).get("revoked"):
        pytest.skip("bundled ATT&CK index predates v20")
    from ti2dac.feedback import Store

    store = Store(tmp_path / "t.db")
    store.add_lesson({"id": 1, "artifact": "rule", "comment": "exclude the SCCM client", "category": "false_positive"},
                     "T1562.001", "windows", "process_creation", tlp="clear")
    assert store.relevant_lessons("T1685", "windows", "registry_set", 5, ["clear"])


def test_leftover_sigma_names_ignores_native_and_query_defined_columns():
    from ti2dac.pipeline import leftover_sigma_names

    rule = ("title: t\nlogsource: {product: windows, service: security}\ndetection:\n  sel:\n    EventID: 4698\n"
            "    TaskContent|contains: powershell\n  condition: sel\n")
    kql = ('SecurityEvent | where EventID == 4698 | extend TaskContent = tostring(parse_xml(EventData))'
           ' | where TaskContent has "powershell"')
    assert leftover_sigma_names(rule, kql, {}, ["sentinel_asim", "sentinel_securityevent"]) == []
    assert leftover_sigma_names(rule, "EventID=4698 TaskContent=/powershell/i", {}, ["crowdstrike_cql"]) == \
        ["EventID", "TaskContent"]
