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
# A name starts only at the beginning of a [\w-] run (after at most two dashes, as \b allowed): starting at every
# \b inside a long run rescans the run each time, quadratic on whole-report text.
_CMD = re.compile(
    r"((?:(?<![\w-])|(?<=(?<![\w-])-)|(?<=(?<![\w-])--))(?=\w)[\w-]+\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|jse|hta|lnk|msi|scr|sh|py|elf|so)\b"
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
# Groups need a separator between them: with optional separators a long hex run followed by a non-hex
# character backtracks exponentially, and `re` holds the GIL, which froze the whole web server.
_HEXLINE = re.compile(r"^(?:0x)?[0-9a-f]{2,}(?:[\s:,]+(?:0x)?[0-9a-f]{2,}){7,}[\s:,]*$|^(?:0x)?[0-9a-f]{16,}$"
                      r"|^[A-Za-z0-9+/=]{80,}$", re.I)
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


def _overhead(b: Block) -> int:
    """Tokens of the '## heading' (or '[…]') line and separators a kept block may add to the output."""
    return est_tokens(f"## {b.heading}\n\n\n\n") if b.heading else est_tokens("[…]\n\n\n\n")


def _pieces(text: str, limit: int) -> list[str]:
    """Split text into chunks of at most `limit` chars: on lines, then sentences, then hard cuts."""
    units: list[str] = []
    for line in text.splitlines():
        if len(line) <= limit:
            units.append(line)
            continue
        for sent in re.split(r"(?<=[.!?])\s+", line):
            units += [sent[i:i + limit] for i in range(0, len(sent), limit)] if len(sent) > limit else [sent]
    out, cur = [], ""
    for u in units:
        if cur and len(cur) + 1 + len(u) > limit:
            out.append(cur)
            cur = u
        else:
            cur = f"{cur}\n{u}" if cur else u
    if cur.strip():
        out.append(cur)
    return [x for x in out if x.strip()]


def _split_oversized(blocks: list[Block], budget_tokens: int) -> list[Block]:
    """A block bigger than the whole budget (e.g. a report with single newlines only) could never be kept."""
    out: list[Block] = []
    for b in blocks:
        if b.tokens + _overhead(b) <= budget_tokens:
            out.append(b)
            continue
        # quarter-budget chunks, so the densest parts of the block can be picked
        limit = max(40, int((budget_tokens // 4 - _overhead(b) - 1) * CHARS_PER_TOKEN))
        out += [Block(0, b.heading, t, _score(t, b.heading), est_tokens(t)) for t in _pieces(b.text, limit)]
    for i, b in enumerate(out):
        b.idx = i
    return out


def condense(text: str, budget_tokens: int) -> Condensed:
    original = est_tokens(text)
    blocks, dropped = split_blocks(text)

    # Duplicate removal (captions repeated around screenshots, etc.): the whole normalized text, so distinct
    # blocks that only share a long prefix are both kept.
    seen: set[str] = set()
    uniq = []
    for b in blocks:
        key = re.sub(r"\W+", "", b.text.lower())
        if key in seen:
            continue
        seen.add(key)
        uniq.append(b)
    blocks = uniq

    total = sum(b.tokens + _overhead(b) for b in blocks)
    if total <= budget_tokens:
        chosen = [b for b in blocks if b.score > -5]
    else:
        blocks = _split_oversized(blocks, budget_tokens)
        # Greedy by signal density; zero-signal prose is the first thing to go (unless nothing else is left).
        pool = [b for b in blocks if b.score > 0] or [b for b in blocks if b.score > -5] or blocks
        ranked = sorted(pool, key=lambda b: (b.score / b.tokens ** 0.5), reverse=True)
        chosen, used = [], 0
        for b in ranked:
            cost = b.tokens + _overhead(b)
            if used + cost > budget_tokens:
                continue
            chosen.append(b)
            used += cost
        if not chosen and ranked:   # tiny budget: the best block, cut to fit, beats an empty report
            b = ranked[0]
            keep = max(1, int((budget_tokens - _overhead(b)) * CHARS_PER_TOKEN))
            chosen = [Block(b.idx, b.heading, b.text[:keep], b.score, est_tokens(b.text[:keep]))]
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
