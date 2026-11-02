"""Token optimizer: shrink a report to the parts that describe attacker *behaviour*.

Deterministic, no API calls. Steps:
  1. split into blocks under their headings
  2. drop boilerplate/IOC sections and IOC-dense blocks (IOCs are extracted separately)
  3. strip hex/base64 dumps and mask hashes
  4. score blocks for behavioural signal (ATT&CK IDs, command lines, tool names, TTP verbs)
  5. if over budget, keep the densest blocks and restore original order

Typical effect on vendor blogs: 40-70% fewer tokens with the TTP content intact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .iocs import ioc_density, mask_hashes

CHARS_PER_TOKEN = 4.0   # conservative estimate for English + code


def est_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN) + 1


_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*$")
_DROP_SECTION = re.compile(
    r"\b(indicators?( of compromise)?|iocs?|hashes|file hashes|network indicators|yara|snort|suricata"
    r"|(our|report|professional|managed|dfir report) services|contact( us)?|subscribe|newsletter|about (the )?(author|us)"
    r"|related (posts|articles|reading)"
    r"|share this|acknowledg|disclaimer|legal|cookie|table of contents|appendix [b-z]|further reading)\b",
    re.I,
)
_KEEP_SECTION = re.compile(r"\b(att&ck|mitre|ttps?|techniques?|timeline|summary|analysis|execution|persistence"
                           r"|discovery|lateral|credential|exfil|impact|evasion|command and control)\b", re.I)
_BOILER = re.compile(
    r"\b(subscribe|newsletter|cookie|contact us|pricing|request a demo|book a demo|podcast|sign up|follow us"
    r"|all rights reserved|privacy policy|terms of (use|service)|spotify|apple podcasts|share on|read more)\b",
    re.I,
)
_ATTACK = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
_CMD = re.compile(
    r"(\b[\w-]+\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|jse|hta|lnk|msi|scr|sh|py|elf|so)\b"
    r"|\s/[a-z]{1,12}\b|\s-{1,2}[a-z][\w-]{1,20}\b|\\\\|HK(?:LM|CU|EY_)\b|%\w+%|\$env:"
    r"|\b(?:powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|schtasks|at|wmic"
    r"|net1?|nltest|whoami|systeminfo|ipconfig|tasklist|reg|sc|vssadmin|wevtutil|bcdedit|psexec|procdump"
    r"|mimikatz|rubeus|sharphound|adfind|bloodhound|cobalt ?strike|sliver|anydesk|screenconnect|atera|rclone"
    r"|7z|winrar|curl|wget|bash|chmod|crontab|systemctl|ssh|nohup|base64|python|msiexec|installutil|msbuild"
    r"|ntdsutil|comsvcs|minidump|lsass|samaccountname|kerberoast|dcsync|wmiprvse|rdp|smb|winrm)\b)",
    re.I,
)
_VERB = re.compile(
    r"\b(execut\w*|ran|launch\w*|creat\w*|persist\w*|scheduled task|service|registry|lateral\w*|dump\w*"
    r"|credential\w*|exfiltrat\w*|discover\w*|enumerat\w*|inject\w*|download\w*|stag\w*|archiv\w*"
    r"|encrypt\w*|delet\w*|disabl\w*|tamper\w*|privilege\w*|escalat\w*|beacon\w*|c2|command and control"
    r"|spawn\w*|abus\w*|leverag\w*|obfuscat\w*|encod\w*|deploy\w*|modif\w*|install\w*)\b",
    re.I,
)
_HEXLINE = re.compile(r"^(?:\s*(?:0x)?[0-9a-f]{2,}[\s:,]*){8,}$|^[A-Za-z0-9+/=]{80,}$", re.I)
_LONGTOKEN = re.compile(r"\S{121,}")


@dataclass
class Block:
    idx: int
    heading: str
    text: str
    score: float
    tokens: int


@dataclass
class Condensed:
    text: str
    original_tokens: int
    condensed_tokens: int
    kept_blocks: int
    total_blocks: int
    dropped_sections: list[str]


def procedure_signals(text: str) -> int:
    """Distinct command-line / tool / registry tokens: a proxy for how 'procedural' a report is."""
    return len({m.group(0).strip().lower() for m in _CMD.finditer(text)})


def _clean_block(text: str) -> str:
    lines = [ln for ln in text.splitlines() if not _HEXLINE.match(ln.strip())]
    text = "\n".join(lines)
    text = mask_hashes(text)
    return _LONGTOKEN.sub(lambda m: m.group(0)[:60] + "…", text)


def _score(text: str, heading: str) -> float:
    s = 4.0 * min(len(_ATTACK.findall(text)), 6)
    s += 2.0 * min(len(_CMD.findall(text)), 8)
    s += 1.0 * min(len(_VERB.findall(text)), 8)
    if _KEEP_SECTION.search(heading):
        s += 2.0
    if _BOILER.search(text):
        s -= 10.0
    return s


def split_blocks(text: str) -> tuple[list[Block], list[str]]:
    blocks: list[Block] = []
    dropped: list[str] = []
    heading, skipping = "", False
    for raw in re.split(r"\n\s*\n", text):
        raw = raw.strip()
        if not raw:
            continue
        m = _HEADING.match(raw.splitlines()[0])
        if m:
            heading = m.group(1).strip()
            skipping = bool(_DROP_SECTION.search(heading)) and not _KEEP_SECTION.search(heading)
            if skipping:
                dropped.append(heading)
            rest = "\n".join(raw.splitlines()[1:]).strip()
            if not rest:
                continue
            raw = rest
        if skipping:
            continue
        if len(raw) > 80 and ioc_density(raw) > 0.35:
            continue
        cleaned = _clean_block(raw)
        if not cleaned.strip():
            continue
        blocks.append(Block(len(blocks), heading, cleaned, _score(cleaned, heading), est_tokens(cleaned)))
    return blocks, dropped


def condense(text: str, budget_tokens: int) -> Condensed:
    original = est_tokens(text)
    blocks, dropped = split_blocks(text)

    # Near-duplicate removal (captions repeated around screenshots, etc.)
    seen: set[str] = set()
    uniq = []
    for b in blocks:
        key = re.sub(r"\W+", "", b.text.lower())[:160]
        if key in seen:
            continue
        seen.add(key)
        uniq.append(b)
    blocks = uniq

    total = sum(b.tokens for b in blocks)
    if total <= budget_tokens:
        chosen = [b for b in blocks if b.score > -5]
    else:
        # Greedy by signal density; zero-signal prose is the first thing to go.
        ranked = sorted((b for b in blocks if b.score > 0), key=lambda b: (b.score / b.tokens ** 0.5), reverse=True)
        chosen, used = [], 0
        for b in ranked:
            if used + b.tokens > budget_tokens:
                continue
            chosen.append(b)
            used += b.tokens
        chosen.sort(key=lambda b: b.idx)

    out: list[str] = []
    last_heading, last_idx = None, -2
    for b in chosen:
        if b.heading and b.heading != last_heading:
            out.append(f"## {b.heading}")
            last_heading = b.heading
        elif b.idx != last_idx + 1:
            out.append("[…]")
        out.append(b.text)
        last_idx = b.idx
    result = "\n\n".join(out)
    return Condensed(result, original, est_tokens(result), len(chosen), len(blocks), dropped)
