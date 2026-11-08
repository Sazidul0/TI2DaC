"""MITRE ATT&CK lookups, mapping validation and Navigator layer export.

The full STIX bundle is ~55 MB; we ship a compact index (id -> name/tactics/flags) built
from it. Refresh with ``ti2dac attack-update`` (writes to the state dir, which overrides
the bundled copy).
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import httpx

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
_BUNDLED = Path(__file__).parent / "data" / "attack_index.json"
_OVERRIDE: Path | None = None


def set_override_dir(state_dir: str | Path) -> None:
    global _OVERRIDE
    _OVERRIDE = Path(state_dir) / "attack_index.json"
    load_index.cache_clear()
    _successor_map.cache_clear()


def build_index(stix: dict) -> dict:
    techniques: dict[str, dict] = {}
    version = ""
    stix_ids: dict[str, str] = {}      # STIX id -> ATT&CK id, for revoked-by relationships
    revoked_by: dict[str, str] = {}    # STIX id -> STIX id
    for obj in stix.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[obj.get("source_ref", "")] = obj.get("target_ref", "")
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
        if obj.get("type") != "attack-pattern":
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        stix_ids[obj.get("id", "")] = ext["external_id"]
        techniques[ext["external_id"]] = {
            "name": obj.get("name", ""),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "platforms": obj.get("x_mitre_platforms", []),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "revoked": bool(obj.get("revoked")),
        }
    for src, dst in revoked_by.items():
        if src in stix_ids and dst in stix_ids:
            techniques[stix_ids[src]]["revoked_by"] = stix_ids[dst]
    return {"attack_version": version, "techniques": techniques}


def update_index(dest_dir: str | Path, source: str | None = None) -> Path:
    if source and Path(source).is_file():
        stix = json.loads(Path(source).read_text())
    else:
        r = httpx.get(source or STIX_URL, timeout=120, follow_redirects=True)
        r.raise_for_status()
        stix = r.json()
    dest = Path(dest_dir) / "attack_index.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_index(stix), separators=(",", ":"), sort_keys=True))
    load_index.cache_clear()
    _successor_map.cache_clear()
    return dest


@lru_cache(maxsize=1)
def load_index() -> dict:
    for p in (_OVERRIDE, _BUNDLED):
        if p and p.is_file():
            return json.loads(p.read_text())
    return {"attack_version": "", "techniques": {}}


def lookup(tid: str) -> dict | None:
    return load_index()["techniques"].get(tid.upper())


def resolve_revoked(tid: str) -> tuple[str, str]:
    """(current id, note) for a revoked technique: its revoked-by successor, or else the one live technique with the
    same name (ATT&CK v20 moved e.g. T1562.001 "Disable or Modify Tools" to T1685 under defense-impairment).
    Unchanged id and '' when the technique is live, unknown, or has no clear successor."""
    idx = load_index()["techniques"]
    t = idx.get(tid.upper())
    if not t or not t.get("revoked"):
        return tid, ""
    new = t.get("revoked_by")
    if not (new and new in idx and not idx[new]["revoked"] and not idx[new]["deprecated"]):
        same = [k for k, v in idx.items() if k != tid.upper() and not v["revoked"] and not v["deprecated"]
                and v["name"].lower() == t["name"].lower()]
        new = same[0] if len(same) == 1 else None
    if not new:
        return tid, ""
    return new, f"{tid} is revoked in ATT&CK; replaced by {new} ({idx[new]['name']})"


def predecessors(tid: str) -> list[str]:
    """Revoked techniques whose successor is `tid` (T1685 -> ['T1562.001']): lessons and history recorded under
    the old id still apply to the new one."""
    return _successor_map().get(tid.upper(), [])


@lru_cache(maxsize=1)
def _successor_map() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, v in load_index()["techniques"].items():
        if v.get("revoked"):
            new, _ = resolve_revoked(k)
            if new != k:
                out.setdefault(new, []).append(k)
    return out


def validate_mapping(tid: str, name: str, tactic: str) -> tuple[bool, str, str, str]:
    """Returns (valid, note, corrected_name, corrected_tactic)."""
    idx = load_index()["techniques"]
    if not idx:
        return True, "ATT&CK index unavailable; mapping not verified", name, tactic
    t = idx.get(tid.upper())
    if t is None:
        parent = idx.get(tid.split(".")[0].upper())
        if parent:
            return False, f"{tid} does not exist; parent {tid.split('.')[0]} ({parent['name']}) does", name, tactic
        return False, f"{tid} is not an ATT&CK Enterprise technique", name, tactic
    notes = []
    if t["revoked"] or t["deprecated"]:
        notes.append(f"{tid} is {'revoked' if t['revoked'] else 'deprecated'} in ATT&CK")
    if tactic not in t["tactics"] and t["tactics"]:
        notes.append(f"tactic '{tactic}' not listed for {tid}; using '{t['tactics'][0]}'")
        tactic = t["tactics"][0]
    if t["name"].lower() not in name.lower():
        name = t["name"]
    return not (t["revoked"] or t["deprecated"]), "; ".join(notes), name, tactic


def navigator_layer(name: str, description: str, techniques: list[dict]) -> dict:
    """techniques: [{id, tactic, comment, score}]"""
    return {
        "name": name[:120],
        "versions": {"attack": load_index().get("attack_version") or "17", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description[:500],
        "sorting": 3,
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": t["id"],
                "tactic": t["tactic"],
                "score": t.get("score", 1),
                "color": "",
                "comment": t.get("comment", ""),
                "enabled": True,
                "showSubtechniques": True,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0, "maxValue": 3},
        "legendItems": [
            {"label": "Detection generated (draft)", "color": "#ffe766"},
            {"label": "Detection validated in lab", "color": "#ff6666"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectSubtechniquesWithParent": False,
    }
