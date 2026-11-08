"""Rewrite Sigma regular expressions for SIEM regex engines that do not share Sigma's semantics.

A Sigma `|re` value matches anywhere in the field (like Python's re.search). Several engines only accept a
match of the whole value: Lucene/OpenSearch query_string `/re/`, ES|QL RLIKE, EQL `regex`, and Loki label
filters (`=~`). pySigma 0.11 backends emit the Sigma pattern bare, so `\\AppData\\...\\.exe` silently never
matched there. Lucene syntax (used by Elastic, ES|QL, EQL, OpenSearch, Wazuh indexer) also has no anchors,
no inline flags such as (?i), no (?:...) groups and reserves `<>@&~#"` as operators.

Pure string functions; the pySigma glue lives in targets.py.
"""
from __future__ import annotations

import re

_LUCENE_RESERVED = set('<>@&~#"')
_CLASS_ESCAPES = {"d": "0-9", "w": "a-zA-Z0-9_", "s": " \t\n\r\f"}
_GROUP_HEAD = re.compile(r"\(\?(?:P<\w+>|<[=!]|[:=!]|[imsx]+\)|[imsx-]+:)")
_LEADING_FLAGS = re.compile(r"\(\?([imsx]+)\)")


def _class_end(p: str, i: int) -> int:
    """Index of the `]` closing the character class that opens at p[i] (len(p) if unterminated)."""
    j = i + 1
    if j < len(p) and p[j] == "^":
        j += 1
    if j < len(p) and p[j] == "]":   # a leading ] is a literal
        j += 1
    while j < len(p):
        if p[j] == "\\":
            j += 2
            continue
        if p[j] == "]":
            return j
        j += 1
    return len(p)


def _escaped(p: str, i: int) -> bool:
    n = 0
    while i - 1 - n >= 0 and p[i - 1 - n] == "\\":
        n += 1
    return n % 2 == 1


def split_alternation(p: str) -> list[str]:
    """Top-level `|` branches (not inside groups, classes or escapes)."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(p):
        c = p[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _class_end(p, i) + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == "|" and depth == 0:
            out.append(p[start:i])
            start = i + 1
        i += 1
    out.append(p[start:])
    return out


def leading_flags(p: str) -> tuple[str, str]:
    """('(?i)x' -> ('i', 'x')): flags of a leading inline group, and the rest of the pattern."""
    m = _LEADING_FLAGS.match(p)
    return (m.group(1), p[m.end():]) if m else ("", p)


def anchor(p: str) -> str:
    """The Sigma (search) meaning as a whole-value pattern: `x` -> `.*x.*`, `^x$` -> `x`, `^a|b` -> `(a.*|.*b.*)`."""
    branches = []
    for b in split_alternation(p):
        if b.startswith("^"):
            b = b[1:]
        elif not b.startswith(".*"):
            b = ".*" + b
        if b.endswith("$") and not _escaped(b, len(b) - 1):
            b = b[:-1]
        elif not (b.endswith(".*") and not _escaped(b, len(b) - 2)):
            b = b + ".*"
        branches.append(b)
    return branches[0] if len(branches) == 1 else "(" + "|".join(branches) + ")"


def _fold_class(body: str) -> str:
    """Character-class body with the other case of every letter and letter range added."""
    adds: list[str] = []
    i = 1 if body.startswith("^") else 0
    while i < len(body):
        if body[i] == "\\":
            i += 2
            continue
        c = body[i]
        if i + 2 < len(body) and body[i + 1] == "-" and body[i + 2] != "\\":
            lo, hi = c, body[i + 2]
            if lo.isalpha() and hi.isalpha() and lo.islower() == hi.islower():
                adds.append(f"{lo.swapcase()}-{hi.swapcase()}")
            i += 3
            continue
        if c.isalpha() and c.swapcase() != c:
            adds.append(c.swapcase())
        i += 1
    if not adds:
        return body
    extra = "".join(a for a in dict.fromkeys(adds) if a not in body)
    if body.endswith("-") and not _escaped(body, len(body) - 1):   # keep a trailing literal '-' last
        return body[:-1] + extra + "-"
    return body + extra


def fold_case(p: str) -> str:
    """Case-insensitive pattern without a flag: `ab[a-z]` -> `[aA][bB][a-zA-Z]`."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\":
            out.append(p[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = _class_end(p, i)
            out.append("[" + _fold_class(p[i + 1:j]) + p[j:j + 1])
            i = j + 1
            continue
        if c == "(" and p.startswith("(?", i):
            m = _GROUP_HEAD.match(p, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
        if c == "{":
            m = re.compile(r"\{\d*,?\d*\}").match(p, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
        out.append(f"[{c.lower()}{c.upper()}]" if c.isalpha() and c.swapcase() != c else c)
        i += 1
    return "".join(out)


def to_lucene(p: str) -> str:
    """Python-style regex -> Lucene RegExp syntax: (?:x) -> (x), \\d/\\w/\\s -> classes, reserved chars escaped."""
    out, i = [], 0
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            e = p[i + 1]
            if e in _CLASS_ESCAPES:
                out.append(f"[{_CLASS_ESCAPES[e]}]")
            elif e.lower() in _CLASS_ESCAPES:                       # \D \W \S
                out.append(f"[^{_CLASS_ESCAPES[e.lower()]}]")
            else:
                out.append(p[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = _class_end(p, i)
            body = p[i + 1:j]
            body = re.sub(r"\\([dws])", lambda m: _CLASS_ESCAPES[m.group(1)], body)
            body = "".join("\\" + ch if ch in _LUCENE_RESERVED and not _escaped(body, k) else ch
                           for k, ch in enumerate(body))
            out.append("[" + body + p[j:j + 1])
            i = j + 1
            continue
        if p.startswith("(?:", i):
            out.append("(")
            i += 3
            continue
        out.append("\\" + c if c in _LUCENE_RESERVED else c)
        i += 1
    return "".join(out)


_UNSUPPORTED_LUCENE = [
    (re.compile(r"\(\?<?[=!]"), "lookaround"),
    (re.compile(r"(?<!\\)(?:\\\\)*\\[1-9]"), "back-reference"),
    (re.compile(r"(?<!\\)(?:\\\\)*\\[bBAZz]"), "\\b / \\A / \\Z anchor"),
    (re.compile(r"(?<!\\)(?:\\\\)*\\[tnrfv]"), "\\t / \\n escape (Lucene reads it as the letter)"),
    (re.compile(r"[*+?}]\?"), "lazy quantifier"),
    (re.compile(r"(?<!\\)(?:\\\\)*\\[DWS](?=[^\[]*\])"), "negated class escape inside [...]"),
    (re.compile(r"\(\?P?<\w+>"), "named group"),
]


def lucene_problems(p: str) -> list[str]:
    """Constructs in a (Python-style) pattern that Lucene RegExp cannot express."""
    return [name for rx, name in _UNSUPPORTED_LUCENE if rx.search(p)]
