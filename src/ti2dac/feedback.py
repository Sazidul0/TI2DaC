"""Feedback, review, test-evidence and lessons store (SQLite).

Follows common detection-engineering practice:
  * structured reviewer feedback with an error taxonomy per artifact (not free text only)
  * corrections are versioned: the corrected rule becomes v{n+1}; v{n} is archived
  * alert dispositions / lab test results (TP / benign TP / FP) feed the validation matrix
  * accepted feedback is distilled into short "lessons" that are injected into future
    generation prompts for the same technique / log source (closed learning loop)
  * everything is in an append-only audit log; export to JSONL for evaluation datasets
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import obs

ARTIFACTS = ["behaviour", "attack_mapping", "sigma_rule", "query", "telemetry", "simulation", "ads", "other"]
CATEGORIES = {
    "hallucinated_evidence": "Evidence/behaviour not in the report",
    "not_a_behaviour": "Extracted item is an IOC/narrative, not a TTP",
    "missed_behaviour": "Important behaviour in the report was missed",
    "incorrect_attack_mapping": "Wrong ATT&CK technique or tactic",
    "wrong_logsource": "Wrong Sigma logsource / telemetry",
    "wrong_field_name": "Field does not exist for the logsource or SIEM",
    "logic_error": "Rule would not match the described behaviour",
    "too_broad_fp": "Too many false positives",
    "too_narrow_fn": "Easily bypassed / misses variants (false negatives)",
    "syntax_error": "Rule or query does not parse / run",
    "translation_error": "SIEM query is wrong for that platform",
    "unsafe_simulation": "Simulation is unsafe or not lab-contained",
    "simulation_no_trigger": "Simulation does not trigger the rule",
    "incomplete_cleanup": "Cleanup leaves artefacts behind",
    "documentation_error": "ADS / guide content is wrong or unclear",
    "other": "Other",
}
SEVERITIES = ["critical", "high", "medium", "low"]
TEST_RESULTS = {
    "fired": "Positive test: rule fired on the simulation",
    "not_fired": "Positive test: rule did NOT fire on the simulation",
    "quiet": "Negative test: no matches on normal activity",
    "false_positive": "Negative test / production: matched benign activity",
    "true_positive": "Production alert: confirmed malicious",
    "benign_true_positive": "Production alert: real behaviour, authorised/benign",
}
REVIEW_STATES = ["draft", "reviewed", "approved", "rejected"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, created_at TEXT, title TEXT, sha256 TEXT, source TEXT, path TEXT);
CREATE TABLE IF NOT EXISTS packages (
  run_id TEXT, slug TEXT, rule_id TEXT, version INTEGER, technique_id TEXT, tactic TEXT,
  product TEXT, category TEXT, title TEXT, review_status TEXT, sigma_status TEXT,
  PRIMARY KEY (run_id, slug));
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, reviewer TEXT, run_id TEXT, slug TEXT,
  rule_id TEXT, rule_version INTEGER, artifact TEXT, target TEXT, category TEXT, severity TEXT,
  comment TEXT, correction TEXT, status TEXT DEFAULT 'open', resolution TEXT, resolved_at TEXT,
  resolved_by TEXT);
CREATE TABLE IF NOT EXISTS test_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, tester TEXT, run_id TEXT, slug TEXT,
  rule_version INTEGER, target TEXT, result TEXT, fp_count INTEGER, evidence TEXT, environment TEXT);
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, feedback_id INTEGER, technique_id TEXT,
  product TEXT, category TEXT, artifact TEXT, text TEXT, active INTEGER DEFAULT 1, tlp TEXT);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, action TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, created_at TEXT, actor TEXT, label TEXT, status TEXT, run_id TEXT, error TEXT,
  log TEXT DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_fb_run ON feedback(run_id, slug);
CREATE INDEX IF NOT EXISTS ix_tr_run ON test_results(run_id, slug);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)
            if "tlp" not in {r["name"] for r in c.execute("PRAGMA table_info(lessons)")}:
                c.execute("ALTER TABLE lessons ADD COLUMN tlp TEXT")   # databases from before lessons carried TLP

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def audit(self, actor: str, action: str, details: dict, level: int = logging.INFO) -> None:
        """Audit trail in the database, mirrored as an `audit` event to the log stream (and from there a SIEM)."""
        with self._conn() as c:
            c.execute("INSERT INTO audit_log(ts, actor, action, details) VALUES (?,?,?,?)",
                      (_now(), actor, action, json.dumps(details, ensure_ascii=False)))
        obs.event("audit", level, action=action, actor=actor,
                  details={k: (v[:300] if isinstance(v, str) else v) for k, v in details.items()})

    def health(self) -> tuple[bool, str]:
        try:
            with self._conn() as c:
                result = c.execute("PRAGMA quick_check").fetchone()[0]
                c.execute("SELECT count(*) FROM audit_log").fetchone()
        except sqlite3.Error as e:
            return False, f"{type(e).__name__}: {e}"
        return result == "ok", "ok" if result == "ok" else f"quick_check: {result}"

    def stuck_jobs(self, minutes: int) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, created_at, label FROM jobs WHERE status='running' AND created_at < ?",
                                               (cutoff,))]

    # ------------------------------------------------------------------ runs / packages
    def register_run(self, record, path: str) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?)",
                      (record.run_id, record.created_at, record.report.title, record.report.sha256,
                       record.report.source, path))
            for p in record.packages:
                b, ls = p.behaviour, p.draft.sigma.logsource
                c.execute(
                    "INSERT INTO packages VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id, slug) DO UPDATE SET "
                    "rule_id=excluded.rule_id, version=excluded.version, technique_id=excluded.technique_id, "
                    "tactic=excluded.tactic, product=excluded.product, category=excluded.category, "
                    "title=excluded.title, sigma_status=excluded.sigma_status, review_status=excluded.review_status",
                    (record.run_id, p.slug, p.rule_id, p.version, b.technique_id, b.tactic, ls.product,
                     ls.category or ls.service, p.draft.sigma.title, p.review_status, p.sigma_status))

    def list_runs(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY created_at DESC")]

    def run_path(self, run_id: str) -> str | None:
        with self._conn() as c:
            r = c.execute("SELECT path FROM runs WHERE run_id=?", (run_id,)).fetchone()
            return r["path"] if r else None

    # ------------------------------------------------------------------ feedback
    def add_feedback(self, *, reviewer: str, run_id: str, slug: str, rule_id: str, rule_version: int,
                     artifact: str, category: str, severity: str, comment: str, correction: str = "",
                     target: str = "") -> int:
        if artifact not in ARTIFACTS:
            raise ValueError(f"artifact must be one of {ARTIFACTS}")
        if category not in CATEGORIES:
            raise ValueError(f"category must be one of {list(CATEGORIES)}")
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if not comment.strip() and not correction.strip():
            raise ValueError("a comment or a correction is required")
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO feedback(created_at, reviewer, run_id, slug, rule_id, rule_version, artifact, target,"
                " category, severity, comment, correction) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (_now(), reviewer, run_id, slug, rule_id, rule_version, artifact, target, category, severity,
                 comment.strip(), correction))
            fid = cur.lastrowid
        self.audit(reviewer, "feedback.add", {"id": fid, "run_id": run_id, "slug": slug, "category": category})
        return int(fid)

    def get_feedback(self, fid: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM feedback WHERE id=?", (fid,)).fetchone()
            return dict(r) if r else None

    def list_feedback(self, run_id: str | None = None, slug: str | None = None, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM feedback WHERE 1=1", []
        for col, val in (("run_id", run_id), ("slug", slug), ("status", status)):
            if val:
                q += f" AND {col}=?"
                args.append(val)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY id DESC", args)]

    def resolve_feedback(self, fid: int, status: str, resolution: str, actor: str) -> None:
        if status not in ("applied", "rejected", "wontfix", "open"):
            raise ValueError("bad status")
        with self._conn() as c:
            c.execute("UPDATE feedback SET status=?, resolution=?, resolved_at=?, resolved_by=? WHERE id=?",
                      (status, resolution, _now(), actor, fid))
        self.audit(actor, "feedback.resolve", {"id": fid, "status": status, "resolution": resolution})

    # ------------------------------------------------------------------ lessons
    def add_lesson(self, feedback: dict, technique_id: str, product: str, category: str, *, tlp: str) -> None:
        """`tlp`: the effective TLP of the feedback's run; the comment may quote that report."""
        if not (feedback.get("comment") or "").strip():
            return   # a bare corrected rule carries no reusable advice; the new version is the record
        text = f"[{feedback['artifact']}/{feedback['category']}] {feedback['comment']}".strip()
        if feedback.get("target"):
            text = f"({feedback['target']}) " + text
        with self._conn() as c:
            c.execute("INSERT INTO lessons(created_at, feedback_id, technique_id, product, category, artifact, text, tlp)"
                      " VALUES (?,?,?,?,?,?,?,?)",
                      (_now(), feedback["id"], technique_id, product, category, feedback["artifact"], text[:280],
                       tlp.lower()))

    def relevant_lessons(self, technique_id: str, product: str, category: str | list[str], limit: int,
                         tlps: list[str]) -> list[str]:
        """Most specific first: same technique > same parent technique > same logsource.

        `category` may be a list: before generation the logsource is not chosen yet, so the caller
        passes the categories the behaviour's observables point to. Only lessons marked with one of
        `tlps` are returned (lessons without a marking predate it and are never sent)."""
        if not tlps:
            return []
        parent = technique_id.split(".")[0]
        cats = [x for x in ([category] if isinstance(category, str) else category) if x] or ["\x00"]
        ph = ",".join("?" * len(cats))
        tph = ",".join("?" * len(tlps))
        with self._conn() as c:
            rows = c.execute(
                "SELECT text, CASE WHEN technique_id=? THEN 3 WHEN technique_id LIKE ? THEN 2 "
                f"WHEN product=? AND category IN ({ph}) THEN 1 ELSE 0 END AS score FROM lessons "
                f"WHERE active=1 AND tlp IN ({tph}) "
                f"AND (technique_id=? OR technique_id LIKE ? OR (product=? AND category IN ({ph}))) "
                "ORDER BY score DESC, id DESC LIMIT ?",
                (technique_id, parent + "%", product, *cats, *tlps, technique_id, parent + "%", product, *cats, limit),
            ).fetchall()
        return list(dict.fromkeys(r["text"] for r in rows))

    def list_lessons(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM lessons ORDER BY id DESC")]

    def set_lesson_active(self, lesson_id: int, active: bool, actor: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE lessons SET active=? WHERE id=?", (1 if active else 0, lesson_id))
        self.audit(actor, "lesson.toggle", {"id": lesson_id, "active": active})

    # ------------------------------------------------------------------ tests / review
    def add_test_result(self, *, tester: str, run_id: str, slug: str, rule_version: int, target: str,
                        result: str, fp_count: int = 0, evidence: str = "", environment: str = "") -> int:
        if result not in TEST_RESULTS:
            raise ValueError(f"result must be one of {list(TEST_RESULTS)}")
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO test_results(created_at, tester, run_id, slug, rule_version, target, result, fp_count,"
                " evidence, environment) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (_now(), tester, run_id, slug, rule_version, target, result, fp_count, evidence, environment))
            tid = cur.lastrowid
        self.audit(tester, "test.record", {"id": tid, "run_id": run_id, "slug": slug, "target": target, "result": result})
        return int(tid)

    def test_results(self, run_id: str, slug: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM test_results WHERE run_id=?", [run_id]
        if slug:
            q += " AND slug=?"
            args.append(slug)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY id", args)]

    def set_review(self, run_id: str, slug: str, status: str, reviewer: str, note: str = "") -> None:
        if status not in REVIEW_STATES:
            raise ValueError(f"status must be one of {REVIEW_STATES}")
        with self._conn() as c:
            c.execute("UPDATE packages SET review_status=? WHERE run_id=? AND slug=?", (status, run_id, slug))
        self.audit(reviewer, "review.set", {"run_id": run_id, "slug": slug, "status": status, "note": note})

    def audit_entries(self, limit: int = 200) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # ------------------------------------------------------------------ background jobs (web)
    def job_create(self, jid: str, label: str, actor: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO jobs(id, created_at, actor, label, status) VALUES (?,?,?,?, 'running')",
                      (jid, _now(), actor, label[:300]))

    def job_log(self, jid: str, line: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE jobs SET log = substr(log || ? || char(10), -20000) WHERE id=?", (line, jid))

    def job_finish(self, jid: str, status: str, run_id: str | None = None, error: str | None = None) -> None:
        with self._conn() as c:
            c.execute("UPDATE jobs SET status=?, run_id=?, error=? WHERE id=?", (status, run_id, error, jid))

    def get_job(self, jid: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not r:
            return None
        job = dict(r)
        job["log"] = [ln for ln in (job["log"] or "").splitlines() if ln]
        return job

    def list_jobs(self, limit: int = 10) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT id, created_at, actor, label, status, run_id FROM jobs "
                                               "ORDER BY created_at DESC LIMIT ?", (limit,))]

    def interrupt_running_jobs(self) -> None:
        with self._conn() as c:
            c.execute("UPDATE jobs SET status='interrupted', error='process restarted while running' "
                      "WHERE status='running'")

    # ------------------------------------------------------------------ export
    def export_jsonl(self, out: Path, runs_root: Path | None = None) -> int:
        """One line per feedback item, with the artifact under review when available (eval datasets)."""
        n = 0
        with out.open("w") as fh:
            for fb in reversed(self.list_feedback()):
                row = dict(fb)
                path = self.run_path(fb["run_id"])
                if path:
                    rule = next(Path(path, "rules").glob(f"{fb['slug']}-*.yml"), None) if Path(path, "rules").is_dir() else None
                    if rule:
                        row["artifact_current"] = rule.read_text()
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                n += 1
        return n


def target_status(results: list[dict], target: str, rule_version: int) -> tuple[str, int, list[str]]:
    """Fold test results for one target into the plan's validation-status vocabulary."""
    rs = [r for r in results if r["target"] in (target, "all") and r["rule_version"] == rule_version]
    pos = any(r["result"] == "fired" for r in rs)
    pos_fail = any(r["result"] == "not_fired" for r in rs)
    neg = any(r["result"] == "quiet" for r in rs)
    fps = [r for r in rs if r["result"] == "false_positive"]
    fp_count = sum(r["fp_count"] or 1 for r in fps)
    causes = [r["evidence"] for r in fps if r["evidence"]]
    if pos_fail and not pos:
        return "failed", fp_count, causes
    if pos and (neg or fps):
        return "tested-positive-and-negative", fp_count, causes
    if pos:
        return "tested-positive", fp_count, causes
    if neg or fps:
        return "tested-negative", fp_count, causes
    return "", fp_count, causes
