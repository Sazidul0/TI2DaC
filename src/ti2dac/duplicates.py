"""Find existing rules that already cover a generated rule (SigmaHQ + internal repositories).

Similarity = same logsource, then how much of the new rule's detection values an existing rule
already covers (containment, so broad SigmaHQ rules that list many tools still match), damped for
catch-all rules with hundreds of values, plus a bonus for a shared ATT&CK technique tag. Field names are ignored: almost every
process rule uses Image/CommandLine, so they say nothing about intent. Cheap and deterministic; it flags candidates for a
human to compare, it does not decide.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from functools import lru_cache
from pathlib import Path

import httpx
import yaml

SIGMAHQ_ZIP = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip"
_TOKEN = re.compile(r"[a-z0-9_]{3,}")
_STOP = {"exe", "dll", "windows", "system32", "program", "files", "users", "the", "and"}


def _tokens(doc: dict) -> set[str]:
    out: set[str] = set()

    def visit(node):
        if isinstance(node, dict):
            for v in node.values():
                visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)
        elif node is not None:
            out.update(t for t in _TOKEN.findall(str(node).lower()) if t not in _STOP)

    det = {k: v for k, v in (doc.get("detection") or {}).items() if k != "condition" and not str(k).startswith("filter")}
    visit(det)
    return out


def _logsource_key(doc: dict) -> str:
    ls = doc.get("logsource") or {}
    return f"{ls.get('product', '')}:{ls.get('category') or ls.get('service', '')}"


def _techniques(doc: dict) -> set[str]:
    return {t.lower() for t in doc.get("tags") or [] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(t).lower())}


def _entry(doc: dict, path: str) -> dict | None:
    if not isinstance(doc, dict) or "detection" not in doc:
        return None
    return {"id": str(doc.get("id", "")), "title": str(doc.get("title", "")), "path": path,
            "ls": _logsource_key(doc), "tech": sorted(_techniques(doc)), "tok": sorted(_tokens(doc))}


def sync_sigmahq(state_dir: str | Path, url: str = SIGMAHQ_ZIP) -> tuple[Path, int]:
    """Download the SigmaHQ rule pack and store a compact index (rules are read in memory, never extracted)."""
    r = httpx.get(url, timeout=120, follow_redirects=True)
    r.raise_for_status()
    entries = []
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for name in zf.namelist():
            if not name.endswith((".yml", ".yaml")) or zf.getinfo(name).file_size > 1_000_000:
                continue
            try:
                for doc in yaml.safe_load_all(zf.read(name)):
                    e = _entry(doc, "sigmahq:" + name)
                    if e:
                        entries.append(e)
            except yaml.YAMLError:
                continue
    out = Path(state_dir) / "sigmahq_index.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(entries, separators=(",", ":")))
    _load.cache_clear()
    return out, len(entries)


@lru_cache(maxsize=4)
def _load(index_path: str, repos: tuple[str, ...]) -> list[dict]:
    entries: list[dict] = []
    p = Path(index_path)
    if p.is_file():
        entries.extend(json.loads(p.read_text()))
    for repo in repos:
        for f in Path(repo).rglob("*.y*ml"):
            try:
                for doc in yaml.safe_load_all(f.read_text(errors="replace")):
                    e = _entry(doc, str(f))
                    if e:
                        entries.append(e)
            except (yaml.YAMLError, OSError):
                continue
    return entries


def find_similar(rule_yaml: str, settings, threshold: float = 0.45, limit: int = 3) -> list[str]:
    try:
        doc = next(iter(yaml.safe_load_all(rule_yaml)), None) or {}
    except yaml.YAMLError:
        return []
    corpus = _load(str(Path(settings.state_dir) / "sigmahq_index.json"), tuple(settings.rule_repos))
    if not corpus:
        return []
    mine, ls, tech, rid = _tokens(doc), _logsource_key(doc), _techniques(doc), str(doc.get("id", ""))
    scored = []
    for e in corpus:
        if e["ls"] != ls or e["id"] == rid or not mine:
            continue
        other = {x for x in e["tok"] if not x.startswith("f:")}   # tolerate indexes built with field tokens
        shared = mine & other
        if len(shared) < min(2, len(mine)):
            continue
        # coverage of the new rule, damped for catch-all rules that list hundreds of values
        score = 0.6 * len(shared) / len(mine) + 0.4 * (len(shared) / len(other)) ** 0.5
        if tech & set(e["tech"]):
            score += 0.15
        if score >= threshold:
            scored.append((round(min(score, 1.0), 2), e))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [f"{e['title']} ({e['id']}) {e['path']} similarity={s}" for s, e in scored[:limit]]
