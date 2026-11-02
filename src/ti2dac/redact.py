"""Pseudonymize sensitive data before any text leaves the machine, and enforce TLP policy.

Internal incident reports carry usernames, hostnames, internal IPs, staff and customer names,
account SIDs and sometimes credentials. Detection logic needs none of these, so they are replaced
with stable placeholders ([USER_1], [HOST_2], ...) before condensing and before any AI call. The
mapping is kept locally (source/redaction-map.json, never sent, never shared with the package).

Deterministic regex redaction is a safety net, not a DLP product: configure `redaction.terms` with
customer/organisation names and `redaction.internal_domains` with your AD/DNS suffixes.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

PLACEHOLDER = re.compile(r"\[(?:HOST|USER|IP|EMAIL|SID|ORG|SECRET)(?:_\d+)?\]")

_TLP = re.compile(r"\bTLP\s*[:\-]?\s*(RED|AMBER\s*\+\s*STRICT|AMBER|GREEN|CLEAR|WHITE)\b", re.I)
TLP_ORDER = ["clear", "green", "amber", "amber+strict", "red"]

_SECRET_KV = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|pass|passphrase|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b"
    r"\s*[:=]\s*)(\"[^\"\n]{3,}\"|'[^'\n]{3,}'|[^\s,;\"'|]{3,})")
_SECRET_VAR = re.compile(r"(?i)(\$\w*(?:pass|pwd|secret|token|key)\w*\s*=\s*)(\"[^\"\n]+\"|'[^'\n]+')")
_SECRET_FLAG = re.compile(r"(?i)((?:^|\s)-p)(?!ass|ath|ort|rofile|roc|olicy|\s)([^\s\"'|]{4,})")   # 7z -pSecret, mysql -pX
_SECRET_TOKENS = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b"
    r"|\bxox[abpr]-[A-Za-z0-9-]{10,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SID = re.compile(r"\bS-1-5-21-\d{6,10}-\d{6,10}-\d{6,10}(?:-\d{3,})?\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PROFILE = re.compile(r"(?i)((?:[a-z]:)?\\{1,2}Users\\{1,2}|/home/|/Users/)([^\\/\s\"'<>|:*?]+)")
_DOMAIN_USER = re.compile(r"\b([A-Z][A-Z0-9-]{1,14})\\{1,2}([A-Za-z][\w.$-]{1,30})\b")
_INTERNAL_TLD = r"(?:local|lan|internal|intranet|intra|corp|lcl|ad|home|localdomain)"
_FQDN = re.compile(r"\b((?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+)\b")
_HOSTLIKE = re.compile(r"\b[A-Z]{2,6}-[A-Z]{1,6}\d{0,3}-\d{1,5}\b")   # FIN-WS-0231, NYC-DC-01 (two-segment schemes)
_UNC = re.compile(r"(?:(?<=^)|(?<=[\s\"'(=,>|]))(\\\\(?:\\\\)?)([A-Za-z0-9][\w-]{0,62}(?:\.[\w-]+)*)(?=\\)", re.M)   # \\server\ only
_PERSON = re.compile(r"(?<![\w.@\[\\/%-])([a-z])\.([a-z]{4,20})(?![\w@\]\\/-])")
_FILE_EXT = set("""enc inc bak conf data dump crypt lock locked""".split() + """dll exe png jpg gif zip rar ps1 bat cmd vbs hta lnk msi scr sys txt log xml htm bin dat tmp cab iso img
vhd pdf doc xls ppt csv ini cfg jar py sh js docm xlsm docx xlsx pptx json yaml html aspx php com net org""".split())
_SERVICE_ACCOUNT = re.compile(r"\b(?:svc|srv|sa|adm)[_-][A-Za-z0-9._$-]{2,30}\b", re.I)
_HOSTLIKE2 = re.compile(r"\b(?:DC|SRV|WS|PC|LT|FS|SQL|EXCH|APP|WEB|VM)\d{1,4}\b")

KEEP_USERS = {"public", "default", "all users", "all", "default user", "administrator", "admin", "system", "localservice",
              "networkservice", "<user>", "user", "username", "%username%", "$env:username", "*", "ti2dac", "redacted",
              "victim", "guest", "test", "sample", "analyst"}
_GENERIC_UNC = {"localhost", "tsclient", "registry", "device", "global??", "microsoft", "wsl$", "wsl.localhost",
                "live.sysinternals.com", "pipe", "mailslot", "systemroot", "?", ".", "127.0.0.1", "server", "share",
                "host", "hostname", "computer", "target", "remote", "dc", "fileserver", "domain"}
_NOT_HOST_SEGMENTS = {"AES", "GCM", "CBC", "SHA", "HMAC", "RSA", "UTF", "ALERT", "CAN", "ZDI", "ICS", "CVE", "CWE", "MAR",
                      "AA", "TLP", "ISO", "IEC", "NIST", "SP", "RFC", "APT", "UNC", "DEV", "STORM", "TA", "KB", "MS", "TAG"}
_NAMEISH = re.compile(r"[A-Za-z][\w.-]{1,30}")

# Structured log fields that name hosts / accounts (learned, then replaced everywhere in the text)
_HOST_FIELDS = re.compile(r"\"(?:Computer|ComputerName|Hostname|HostName|host\.name|DeviceName|Workstation|WorkstationName|"
                          r"SourceHostname|DestinationHostname|MachineName)\"\s*:\s*\"([^\"]{2,80})\"")
_USER_FIELDS = re.compile(r"\"(?:User|UserName|user\.name|TargetUserName|SubjectUserName|AccountName|AccountUpn|"
                          r"InitiatingProcessAccountName|ParentUser|SourceUser)\"\s*:\s*\"([^\"]{2,120})\"")
KEEP_DOMAINS = {"NT AUTHORITY", "BUILTIN", "HKLM", "HKCU", "HKCR", "HKU", "HKCC", "WORKGROUP", "NT SERVICE",
                "FONT DRIVER HOST", "WINDOW MANAGER", "IIS APPPOOL"}


@dataclass
class Redaction:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)      # placeholder -> original (stays local)
    counts: dict[str, int] = field(default_factory=dict)


class _Pseudonymizer:
    def __init__(self) -> None:
        self.forward: dict[tuple[str, str], str] = {}
        self.mapping: dict[str, str] = {}
        self.counts: dict[str, int] = {}

    def __call__(self, kind: str, value: str) -> str:
        if kind == "SECRET":   # never keep a reversible map of secrets
            self.counts["SECRET"] = self.counts.get("SECRET", 0) + 1
            return "[SECRET]"
        key = (kind, value.lower())
        if key not in self.forward:
            n = sum(1 for k in self.forward if k[0] == kind) + 1
            ph = f"[{kind}_{n}]"
            self.forward[key] = ph
            self.mapping[ph] = value
            self.counts[kind] = self.counts.get(kind, 0) + 1
        return self.forward[key]


def _is_internal_ip(s: str, networks: list) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_unspecified or s.endswith((".0", ".255")) or s.startswith("0."):
        return False   # 127.0.0.1 / ranges are technique details (e.g. `ping 127.0.0.1` delays), not identities
    return ip.is_private or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10") or any(ip in n for n in networks)


def redact(text: str, *, internal_domains: list[str] | None = None, internal_networks: list[str] | None = None,
           terms: list[str] | None = None, hostname_patterns: list[str] | None = None,
           netbios_domains: list[str] | None = None) -> Redaction:
    p = _Pseudonymizer()
    nets = [ipaddress.ip_network(n, strict=False) for n in (internal_networks or [])]
    domains = [d.lower().lstrip(".") for d in (internal_domains or [])]

    # 1. secrets (irreversible)
    text = _SECRET_TOKENS.sub(lambda m: p("SECRET", m.group(0)), text)
    text = _SECRET_KV.sub(lambda m: m.group(1) + p("SECRET", m.group(2)), text)
    text = _SECRET_VAR.sub(lambda m: m.group(1) + '"' + p("SECRET", m.group(2)) + '"', text)
    text = _SECRET_FLAG.sub(lambda m: m.group(1) + p("SECRET", m.group(2)), text)

    # 2. configured organisation / customer names
    for term in sorted(terms or [], key=len, reverse=True):
        if term.strip():
            text = re.sub(rf"(?i)\b{re.escape(term)}\b", lambda m: p("ORG", term), text)

    # 3. identities
    users: set[str] = set()
    text = _SID.sub(lambda m: p("SID", m.group(0)), text)

    def email(m: re.Match) -> str:
        users.add(m.group(0).split("@")[0])
        return p("EMAIL", m.group(0))

    text = _EMAIL.sub(email, text)

    def profile(m: re.Match) -> str:
        name = m.group(2)
        if (name.lower() in KEEP_USERS or not _NAMEISH.fullmatch(name) or len(name) < 3 or name.endswith(".")
                or name.rsplit(".", 1)[-1].lower() in _FILE_EXT):
            return m.group(0)
        users.add(name)
        return m.group(1) + p("USER", name)

    learned_hosts: set[str] = set()
    for m in _HOST_FIELDS.finditer(text):
        v = m.group(1)
        if not PLACEHOLDER.search(v) and v.lower() not in ("localhost", "-", "n/a"):
            learned_hosts.add(v.split(".")[0])
    for m in _USER_FIELDS.finditer(text):
        v = m.group(1).replace("\\\\", "\\")
        if "\\" in v:
            dom, _, u = v.partition("\\")
            if dom.upper() not in KEEP_DOMAINS:
                netbios_domains = list(netbios_domains or []) + [dom]
            v = u
        v = v.split("@")[0]
        if _NAMEISH.fullmatch(v) and v.lower() not in KEEP_USERS and v.upper() not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            users.add(v)
    text = _PROFILE.sub(profile, text)

    # UNC paths: \\server\share -> host is infrastructure (must run before DOMAIN\user matching)
    def unc(m: re.Match) -> str:
        host = m.group(2)
        if (PLACEHOLDER.fullmatch(host) or host.lower() in _GENERIC_UNC or _IPV4.fullmatch(host)
                or len(host) < 3 or re.fullmatch(r"x[0-9a-f]{2}", host, re.I)):
            return m.group(0)   # generic names, kernel paths, shellcode escapes; IPs go to the IP pass
        return m.group(1) + p("HOST", host.split(".")[0])

    text = _UNC.sub(unc, text)
    text = _SERVICE_ACCOUNT.sub(lambda m: p("USER", m.group(0)), text)

    netbios = {d.split(".")[0].upper() for d in domains} | {n.upper() for n in (netbios_domains or [])}

    def domuser(m: re.Match) -> str:
        dom, user = m.group(1), m.group(2)
        if dom.upper() not in netbios or user.lower() in KEEP_USERS:
            return m.group(0)
        users.add(user)
        sep = "\\\\" if "\\\\" in m.group(0) else "\\"
        return p("ORG", dom) + sep + p("USER", user)

    text = re.sub(r"(?<!\\)" + _DOMAIN_USER.pattern, domuser, text)
    # initial.lastname style staff names (but not file names such as a.dll)
    text = _PERSON.sub(lambda m: m.group(0) if m.group(2) in _FILE_EXT else p("USER", m.group(0)), text)
    for u in sorted(users, key=len, reverse=True):     # same person mentioned elsewhere by bare name
        if len(u) >= 4 and u.lower() not in KEEP_USERS:
            text = re.sub(rf"(?<![\w\[]){re.escape(u)}(?![\w\]])", lambda m: p("USER", u), text)

    # 4. infrastructure: internal FQDNs (and their short names), host-like names, internal IPs
    shorts: set[str] = set()

    def fqdn(m: re.Match) -> str:
        name = m.group(1)
        low = name.lower()
        internal = any(low == d or low.endswith("." + d) for d in domains) or re.search(rf"\.{_INTERNAL_TLD}$", low)
        if not internal:
            return name
        if any(low == d for d in domains) or re.fullmatch(rf"[a-z0-9-]+\.{_INTERNAL_TLD}", low) and low.split(".")[0] in [d.split(".")[0] for d in domains]:
            return p("ORG", name)
        shorts.add(name.split(".")[0])
        return p("HOST", name.split(".")[0])

    text = _FQDN.sub(fqdn, text)
    patterns = [_HOSTLIKE, _HOSTLIKE2] + [re.compile(x) for x in (hostname_patterns or [])]
    def host(m: re.Match) -> str:
        if set(m.group(0).upper().split("-")) & _NOT_HOST_SEGMENTS:
            return m.group(0)   # AES-GCM-256, ICS-ALERT-14, ZDI-CAN-24433 ... are not hosts
        return p("HOST", m.group(0))

    for pat in patterns:
        text = pat.sub(host, text)
    shorts |= learned_hosts
    for s in sorted(shorts, key=len, reverse=True):
        text = re.sub(rf"(?<![\w\[-]){re.escape(s)}(?![\w\]-])", lambda m: p("HOST", s), text, flags=re.I)
    text = _IPV4.sub(lambda m: p("IP", m.group(0)) if _is_internal_ip(m.group(0), nets) else m.group(0), text)
    return Redaction(text=text, mapping=p.mapping, counts=p.counts)


# --------------------------------------------------------------------------- TLP
def detect_tlp(text: str) -> str:
    """Most restrictive TLP marking in the document ('' if unmarked). TLP:WHITE == TLP:CLEAR."""
    found = {re.sub(r"\s+", "", m.group(1).lower()).replace("white", "clear") for m in _TLP.finditer(text[:200_000])}
    return max(found, key=TLP_ORDER.index) if found else ""


def tlp_allowed(tlp: str, allowed: list[str]) -> bool:
    return tlp in allowed
