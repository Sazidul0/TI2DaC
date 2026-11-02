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
ec cu do gt hn sv ni cr pa jm tt
""".split())

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])", re.I)
_URL = re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.I)
_MD5 = re.compile(r"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", re.I)
_SHA1 = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
_SHA256 = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_ATTACK = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
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


def extract_iocs(text: str) -> IOCSet:
    t = refang(text)
    ips = []
    for m in _IPV4.findall(t):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if not ip.is_unspecified:
            ips.append(m)
    urls = _uniq(u.rstrip(".,") for u in _URL.findall(t))
    domains = []
    for full, tld in _DOMAIN.findall(t):
        if tld.lower() in _TLDS and not _IPV4.fullmatch(full):
            domains.append(full.lower().rstrip("."))
    sha256 = _uniq(h.lower() for h in _SHA256.findall(t))
    sha1 = _uniq(h.lower() for h in _SHA1.findall(t))
    md5 = _uniq(h.lower() for h in _MD5.findall(t))
    return IOCSet(
        ipv4=_uniq(ips),
        domains=_uniq(domains),
        urls=urls,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        cves=_uniq(c.upper() for c in _CVE.findall(t)),
        attack_ids=_uniq(_ATTACK.findall(t)),
        file_paths=_uniq(p.rstrip(".)") for p in _WINPATH.findall(t))[:200],
        registry_keys=_uniq(k.rstrip(".)") for k in _REGKEY.findall(t))[:200],
        file_names=_uniq(f.lower() for f in _FILENAME.findall(t))[:500],
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
