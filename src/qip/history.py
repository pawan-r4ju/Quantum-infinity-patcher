"""SQLite-based scan history and audit log."""

from __future__ import annotations

import datetime
import json
import sqlite3
from pathlib import Path
from typing import Optional

from qip.config import USER_CONFIG_DIR
from qip.models import Finding, Patch, RunStatus, ScanRun, ScanSummary

DEFAULT_DB_PATH = USER_CONFIG_DIR / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    repo_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    total_findings INTEGER DEFAULT 0,
    total_patches INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    rejected INTEGER DEFAULT 0,
    deployed INTEGER DEFAULT 0,
    timing_json TEXT DEFAULT '{}',
    config_snapshot TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    cve_id TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL DEFAULT 0.0,
    component TEXT,
    ecosystem TEXT,
    reachable INTEGER,
    fix_available INTEGER DEFAULT 0,
    patch_id TEXT
);

CREATE TABLE IF NOT EXISTS patches (
    patch_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    cve_id TEXT NOT NULL,
    file_path TEXT,
    fix_type TEXT,
    confidence TEXT,
    test_result TEXT DEFAULT 'skip',
    review_status TEXT DEFAULT 'pending',
    reviewed_at TEXT,
    deployed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_patches_run ON patches(run_id);
"""


class HistoryDB:
    """SQLite-backed scan history database."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _ensure_schema(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def record_run_start(self, run: ScanRun) -> None:
        """Record the start of a scan run."""
        self.conn.execute(
            """INSERT INTO runs (run_id, repo_path, started_at, status, config_snapshot)
               VALUES (?, ?, ?, ?, ?)""",
            (
                run.run_id,
                run.repo_path,
                run.started_at.isoformat(),
                run.status.value,
                json.dumps(run.config_snapshot),
            ),
        )
        self.conn.commit()

    def record_run_end(
        self,
        run_id: str,
        status: RunStatus,
        findings: list[Finding],
        patches: list[Patch],
        timing: dict[str, float],
    ) -> None:
        """Record the completion of a scan run."""
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            """UPDATE runs SET
                finished_at = ?, status = ?,
                total_findings = ?, total_patches = ?,
                timing_json = ?
               WHERE run_id = ?""",
            (now, status.value, len(findings), len(patches), json.dumps(timing), run_id),
        )

        # Insert findings
        for f in findings:
            self.conn.execute(
                """INSERT INTO findings (run_id, cve_id, severity, cvss_score, component, ecosystem, reachable, fix_available)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id, f.cve_id, f.severity.value, f.cvss_score,
                    f.component, f.ecosystem,
                    1 if f.reachable else 0,
                    1 if f.fixed_version else 0,
                ),
            )

        # Insert patches
        for p in patches:
            self.conn.execute(
                """INSERT INTO patches (patch_id, run_id, cve_id, file_path, fix_type, confidence, test_result, review_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    p.patch_id, run_id, p.cve_id, p.patch_file,
                    p.fix_type.value, p.confidence.value,
                    p.test_result.value, p.review_status.value,
                ),
            )

        self.conn.commit()

    def update_patch_review(self, patch_id: str, status: str) -> None:
        """Update patch review status."""
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "UPDATE patches SET review_status = ?, reviewed_at = ? WHERE patch_id = ?",
            (status, now, patch_id),
        )
        self.conn.commit()

    def list_runs(self, limit: int = 20) -> list[ScanSummary]:
        """List recent scan runs."""
        rows = self.conn.execute(
            """SELECT run_id, repo_path, status, total_findings, total_patches,
                      approved, rejected, started_at, finished_at, timing_json
               FROM runs ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()

        summaries = []
        for row in rows:
            timing = json.loads(row["timing_json"]) if row["timing_json"] else {}
            duration = sum(timing.values()) if timing else 0.0
            summaries.append(
                ScanSummary(
                    run_id=row["run_id"],
                    repo_path=row["repo_path"],
                    status=RunStatus(row["status"]),
                    total_findings=row["total_findings"] or 0,
                    total_patches=row["total_patches"] or 0,
                    approved=row["approved"] or 0,
                    rejected=row["rejected"] or 0,
                    duration_seconds=duration,
                    date=row["started_at"][:10],
                )
            )
        return summaries

    def get_run(self, run_id: str) -> Optional[dict]:
        """Get full details of a specific run."""
        row = self.conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            return None
        return dict(row)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
