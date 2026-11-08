"""Deterministic IOC / artifact extraction (no AI, no tokens).

IOCs are kept out of the LLM prompt: they are optional enrichment, not behaviour, and long
hashes are very token-expensive. They are reported separately in the package.
"""
from __future__ import annotations

import ipaddress
import re

from .models import IOCSet

_REFANG = [
    # Undo markdown escaping first: svchorst\[.\]com -> svchorst[.]com
    (re.compile(r"\\([\[\].])"), r"\1"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
]

# Curated TLD list: avoids treating file names (rundll32.exe, payload.ps1) as domains.
_TLDS = set("""
com net org info biz io co us uk de fr ru cn jp kr in br au ca nl se no fi dk pl cz ua by kz ir
il tr sa ae qa pk bd vn th my sg id ph hk tw eu me tv cc ws su xyz top online site club shop app
dev cloud live pro link space tech store website fun icu vip work page digital network email
group news world today life ltd services solutions systems support host one zone run ai gov edu
mil int asia mobi name tk ml ga cf gq pw to ly st sh ch at be es it pt gr ro hu bg rs hr si sk lt
lv ee md am ge az uz kg tj tm mn np lk mm kh la nz za ng ke eg ma tn dz gh mx ar cl pe ve uy py bo
ec cu do gt hn sv ni cr pa jm tt ton onion bit
""".split())

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")   # a sentence-ending '.' is not part of it
_DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])", re.I)
_URL = re.compile(r"\bhttps?://[^\s<>\"'`)\]{}|^]+", re.I)
_MD5 = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I)
_SHA1 = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
_SHA256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_ATTACK = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
_ATTACK_SHORTHAND = re.compile(r"\b(T1\d{3})\.\d{3}((?:\s*/\s*\.\d{3})+)")   # "T1036.005 / .001"
_MUTEX = re.compile(r"(?<![\w\\])(?:Global|Local|Session\\\d+)\\[A-Za-z0-9_.{}-]{3,}(?![\w*{}-])")
_WINPATH = re.compile(r"(?:[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\[\w.$-]+\\)[^\s\"'<>|*?,;]+")
_REGKEY = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s\"'<>|,;]+", re.I)
_FILENAME = re.compile(r"(?<![\w.-])[\w.-]{1,64}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr|sys|sh|py|elf|so|lnk|jar)\b", re.I)
_HASH_ANY = re.compile(r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", re.I)


def refang(text: str) -> str:
    for pat, rep in _REFANG:
        text = pat.sub(rep, text)
    return text


def _uniq(items) -> list[str]:
    seen: dict[str, None] = {}
    for i in items:
        seen.setdefault(i, None)
    return list(seen)


# Context words before a 32/40/64-hex value. The nearest one decides: a file-hash label keeps it, anything
# else (crypto keys, bot/evidence IDs, imphash) is not a file hash. `md5(` is a function call, not a label.
_HASH_LABEL = re.compile(r"\b(?:md5|sha-?1|sha-?256|hash(?:es)?|sample)\b(?!\()", re.I)
_NOT_FILE_HASH = re.compile(r"\b(?:key|keys|rc4|aes|xor|des|iv|nonce|salt|seed|imphash|pehash|ssdeep|bot|id|guid|uuid|"
                            r"evidence|token|serial|thumbprint|mutex|session|machineguid|password|secret)\b", re.I)

# Resolvers and services every network uses: the report names them as infrastructure the malware abuses. Blocking
# the domain breaks the business; block the specific URLs (kept) instead.
_LEGIT_IPS = {"1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
              "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS"}
_LEGIT_DOMAINS = {   # services malware abuses: the domain is excluded, URLs with a path on it are kept
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "golang.org", "go.dev", "python.org",
    "pypi.org", "npmjs.com", "microsoft.com", "microsoft.net", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "outlook.com", "bing.com", "xbox.com", "azure.com", "azureedge.net", "google.com",
    "googleapis.com", "gstatic.com", "dns.google", "cloudflare.com", "cloudflare-dns.com", "amazonaws.com", "apple.com",
    "mozilla.org", "dropbox.com", "discord.com", "telegram.org", "steampowered.com", "w3.org", "sysinternals.com",
    "socket.io", "example.com", "example.org", "example.net"}
# Reference links in a report (publishers, social media, ATT&CK, sandboxes): neither the domain nor its URLs are IOCs.
_REFERENCE_DOMAINS = {
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com", "medium.com", "mitre.org", "virustotal.com",
    "any.run", "hybrid-analysis.com", "bleepingcomputer.com", "elastic.co", "crowdstrike.com", "mandiant.com",
    "thedfirreport.com", "paloaltonetworks.com", "sophos.com", "trendmicro.com", "redcanary.com", "secureworks.com",
    "recordedfuture.com", "talosintelligence.com", "cisco.com", "cisa.gov", "us-cert.gov", "nist.gov", "first.org",
    "microsoft.com", "welivesecurity.com", "kaspersky.com", "securelist.com", "proofpoint.com", "sentinelone.com",
    "checkpoint.com", "fortinet.com", "zscaler.com", "huntress.com", "volexity.com", "google.com", "cloud.google.com"}
# Real TLDs that are also script/file extensions or field names (00.sh, wmiexec.py, WshShell.Run, process.name,
# README.md): such a name counts as a domain only if it is the host of a URL in the report.
_AMBIGUOUS_TLDS = {"sh", "py", "run", "name", "md", "zip", "mov"}
# Windows and common application binaries the report mentions as targets, tools or masquerade names.
_LEGIT_FILES = set("""
kernel32.dll kernelbase.dll ntdll.dll user32.dll advapi32.dll gdi32.dll shell32.dll ole32.dll ws2_32.dll wininet.dll
winhttp.dll crypt32.dll bcrypt.dll dbghelp.dll amsi.dll mscoree.dll comsvcs.dll nss3.dll
lsass.exe csrss.exe smss.exe services.exe wininit.exe winlogon.exe svchost.exe explorer.exe taskhost.exe taskhostw.exe
spoolsv.exe dwm.exe audiodg.exe conhost.exe sihost.exe ctfmon.exe applicationframehost.exe runtimebroker.exe
searchindexer.exe cmd.exe powershell.exe pwsh.exe rundll32.exe regsvr32.exe mshta.exe wscript.exe cscript.exe reg.exe
regedit.exe sc.exe schtasks.exe at.exe taskkill.exe tasklist.exe net.exe net1.exe whoami.exe wmic.exe msiexec.exe
certutil.exe bitsadmin.exe reagentc.exe vssadmin.exe wbadmin.exe bcdedit.exe wevtutil.exe netsh.exe nltest.exe
ipconfig.exe systeminfo.exe hostname.exe notepad.exe calc.exe mstsc.exe chrome.exe msedge.exe firefox.exe iexplore.exe
werfault.exe wermgr.exe esentutl.exe mobsync.exe msbuild.exe gpscript.exe runas.exe wmiprvse.exe dllhost.exe
taskmgr.exe userinit.exe consent.exe logonui.exe wuauclt.exe fodhelper.exe eventvwr.exe sdclt.exe computerdefaults.exe
msdt.exe hh.exe installutil.exe regasm.exe regsvcs.exe cmstp.exe forfiles.exe odbcconf.exe mavinject.exe ntdsutil.exe
diskshadow.exe expand.exe extrac32.exe makecab.exe curl.exe tar.exe ftp.exe finger.exe cmdkey.exe quser.exe query.exe
arp.exe route.exe ping.exe nslookup.exe netstat.exe tracert.exe attrib.exe icacls.exe takeown.exe cipher.exe
wsmprovhost.exe winrm.cmd msvcr100.dll msvcp140.dll vcruntime140.dll dbgcore.dll version.dll
next.js node.js vue.js react.js three.js jquery.js
wdfilter.sys wdboot.sys wdnisdrv.sys mpksldrv.sys mpsdrv.sys ntoskrnl.exe hal.dll ci.dll
""".split())


def join_wrapped(text: str) -> str:
    """Undo line wraps inside URLs (PDF tables cut `.../raw/mai` + `n/...`): a URL that ends a line is joined with the
    next line's first token when that token continues a path (contains a '/')."""
    pat = re.compile(r"(https?://[^\s<>\"'`)\]{}|^]+)\n(?!https?://)([^\s<>\"'`)\]{}|^]*/[^\s<>\"'`)\]{}|^]*)", re.I)
    prev = None
    while prev != text:
        prev, text = text, pat.sub(r"\1\2", text)
    return text


def _hash_contexts(t: str, value: str) -> list[bool | None]:
    """Per occurrence: True = labelled as a file hash, False = labelled as something else, None = no label."""
    out = []
    for m in re.finditer(rf"(?<![0-9a-f]){value}(?![0-9a-f])", t, re.I):
        window = t[max(0, m.start() - 100):m.start()]
        hits = [(x.end(), True) for x in _HASH_LABEL.finditer(window)] + \
               [(x.end(), False) for x in _NOT_FILE_HASH.finditer(window)]
        out.append(max(hits)[1] if hits else None)
    return out


def _split_hashes(t: str, found: list[str], excluded: dict[str, str]) -> list[str]:
    keep = []
    for h in found:
        ctx = _hash_contexts(t, h)
        if True not in ctx and False in ctx:
            excluded[h] = "hex value labelled as a key, ID or imphash, not a file hash"
        else:
            keep.append(h)
    return keep


def _under(d: str, roots: set[str]) -> bool:
    return any(d == x or d.endswith("." + x) for x in roots)


def _legit_domain(d: str) -> bool:
    return _under(d, _LEGIT_DOMAINS) or _under(d, _REFERENCE_DOMAINS)


def _url_host(u: str) -> str:
    return re.sub(r"^https?://(?:[^@/]*@)?", "", u, flags=re.I).split("/")[0].split(":")[0].lower()


def _clean_url(u: str) -> str:
    u = u.rstrip(".,;:")
    return re.sub(r";(?![^/;]*=)[^/]*$", "", u)   # `.../l64;chmod` (a shell command glued on), not `;jsessionid=x`


def _wrapped_fragments(t: str, names: list[str]) -> set[str]:
    """File names that only occur as the tail of a word cut by a line break (`ff` + newline + `mpeg.exe`), judged by
    the joined name (`ffmpeg.exe`) also occurring in the text. Without that evidence the name is kept."""
    known = {n.lower() for n in names}
    frags = set()
    for n in known:
        occ = list(re.finditer(rf"(?<![\w.-]){re.escape(n)}\b", t, re.I))
        cut = []
        for m in occ:
            pm = re.search(r"([\w-]+)$", t[:m.start() - 1]) if m.start() > 0 and t[m.start() - 1] == "\n" else None
            if pm and (pm.group(1) + n).lower() in known:
                cut.append(m)
        if occ and len(cut) == len(occ):
            frags.add(n)
    return frags


def _mutexes(t: str) -> list[str]:
    r"""Named kernel objects. `Local\Packages` is a path fragment, so a name needs a digit, `_` or `{`, or the word
    'mutex' just before it."""
    out = []
    for m in _MUTEX.finditer(t):
        name = m.group(0).rstrip(".")
        if re.search(r"[\d_{]", name.split("\\")[-1]) or re.search(r"mutex|mutant", t[max(0, m.start() - 40):m.start()], re.I):
            out.append(name)
    return _uniq(out)


_SYSTEM_ROOTS = {"c:\\windows\\", "c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\program files\\",
                 "c:\\programdata\\", "c:\\users\\"}


def _file_paths(t: str, excluded: dict[str, str]) -> list[str]:
    out = []
    for p in _uniq(p.rstrip(".)") for p in _WINPATH.findall(t)):
        low = p.lower()
        if low in _SYSTEM_ROOTS:
            excluded[p] = "system folder (not an indicator)"
        elif low.startswith(("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")) and low.rsplit("\\", 1)[-1] in _LEGIT_FILES:
            excluded[p] = "legitimate location of a Windows file (the malware imitates it)"
        else:
            out.append(p)
    return out


def extract_iocs(text: str) -> IOCSet:
    t = refang(text)
    joined = join_wrapped(t)
    excluded: dict[str, str] = {}
    ips = []
    for mm in _IPV4.finditer(t):
        m = mm.group(0)
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if ip.is_unspecified:
            continue
        if not ip.is_global or ip.is_multicast:
            excluded[m] = "private, reserved, multicast or lab address (not routable on the internet)"
        elif re.match(r"/\d{1,2}\b", t[mm.end():mm.end() + 3]):
            excluded[m] = "network range (CIDR), not a host address"
        elif m in _LEGIT_IPS:
            excluded[m] = f"public resolver ({_LEGIT_IPS[m]})"
        else:
            ips.append(m)
    urls = []
    for u in _uniq(_clean_url(u) for u in _URL.findall(joined)):
        host = _url_host(u)
        if _under(host, _REFERENCE_DOMAINS) or (_under(host, _LEGIT_DOMAINS) and not re.search(r"//[^/]+/[^/\s]", u)):
            excluded[u] = "reference link or bare legitimate site, not an indicator"
        else:
            urls.append(u)
    url_hosts = {_url_host(u) for u in urls}
    domains = []
    for full, tld in _DOMAIN.findall(t):
        if tld.lower() in _TLDS and not _IPV4.fullmatch(full):
            d = full.lower().rstrip(".")
            if _under(d, _REFERENCE_DOMAINS):
                excluded[d] = "reference site (publisher, social media, ATT&CK, sandbox), not an indicator"
            elif _under(d, _LEGIT_DOMAINS):
                excluded[d] = "legitimate service the malware uses: block the specific URLs, not the domain"
            elif tld.lower() in _AMBIGUOUS_TLDS and d not in url_hosts:
                excluded[d] = "script, file or field name with a TLD-like extension (not seen as a URL host)"
            else:
                domains.append(d)
    sha256 = _split_hashes(t, _uniq(h.lower() for h in _SHA256.findall(t)), excluded)
    sha1 = _split_hashes(t, _uniq(h.lower() for h in _SHA1.findall(t)), excluded)
    md5 = _split_hashes(t, _uniq(h.lower() for h in _MD5.findall(t)), excluded)
    attack = list(_ATTACK.findall(t))
    for m in _ATTACK_SHORTHAND.finditer(t):
        attack += [f"{m.group(1)}{sub}" for sub in re.findall(r"\.\d{3}", m.group(2))]
    names = _uniq(f.lower() for f in _FILENAME.findall(t))
    frags = _wrapped_fragments(t, names)
    file_names = []
    for n in names:
        if n in frags:
            continue
        if n in _LEGIT_FILES:
            excluded[n] = "Windows or common application file (mentioned, not an indicator)"
        else:
            file_names.append(n)
    return IOCSet(
        ipv4=_uniq(ips),
        domains=_uniq(domains),
        urls=urls,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        cves=_uniq(c.upper() for c in _CVE.findall(t)),
        attack_ids=_uniq(attack),
        file_paths=_file_paths(t, excluded)[:200],
        registry_keys=_uniq(k.rstrip(".)") for k in _REGKEY.findall(t))[:200],
        file_names=file_names[:500],
        mutexes=_mutexes(t),
        excluded=excluded,
    )


def ioc_density(text: str) -> float:
    """Share of whitespace tokens that are IOCs (hashes/IPs/domains/urls)."""
    tokens = text.split()
    if not tokens:
        return 0.0
    t = refang(text)
    hits = len(_HASH_ANY.findall(t)) + len(_IPV4.findall(t)) + len(_URL.findall(t))
    hits += sum(1 for _, tld in _DOMAIN.findall(t) if tld.lower() in _TLDS)
    return min(1.0, hits / len(tokens))


def mask_hashes(text: str) -> str:
    """Replace hashes with a short placeholder (a SHA-256 costs ~30+ tokens)."""
    return _HASH_ANY.sub("<hash>", text)
