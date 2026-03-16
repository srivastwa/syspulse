"""
SQLite-backed report store.
Reports are stored as raw JSON blobs with a few indexed metadata columns.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

DB_PATH = Path(__file__).parent / "eciso.db"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = _conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname     TEXT    NOT NULL,
                os_name      TEXT,
                assessed_at  TEXT    NOT NULL,
                submitted_at TEXT    NOT NULL,
                overall_score REAL   NOT NULL,
                tier         TEXT    NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count     INTEGER DEFAULT 0,
                medium_count   INTEGER DEFAULT 0,
                low_count      INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                raw_json     TEXT    NOT NULL
            )
        """)


def insert_report(raw_json: str) -> int:
    data: dict[str, Any] = json.loads(raw_json)
    system = data.get("system", {})
    score  = data.get("score", {})
    counts = score.get("counts", {})

    total = sum(
        counts.get(k, 0)
        for k in ("critical", "high", "medium", "low", "info")
    )

    with get_db() as db:
        cur = db.execute("""
            INSERT INTO reports
              (hostname, os_name, assessed_at, submitted_at,
               overall_score, tier,
               critical_count, high_count, medium_count, low_count, total_findings,
               raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            system.get("hostname", "unknown"),
            system.get("os_name", ""),
            system.get("assessed_at", datetime.now(timezone.utc).isoformat()),
            datetime.now(timezone.utc).isoformat(),
            score.get("overall", 0.0),
            score.get("tier", "UNKNOWN"),
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            total,
            raw_json,
        ))
        return cur.lastrowid  # type: ignore[return-value]


def list_reports() -> list[sqlite3.Row]:
    with get_db() as db:
        return db.execute("""
            SELECT id, hostname, os_name, assessed_at, submitted_at,
                   overall_score, tier,
                   critical_count, high_count, medium_count, low_count, total_findings
            FROM reports
            ORDER BY submitted_at DESC
        """).fetchall()


def get_report(report_id: int) -> sqlite3.Row | None:
    with get_db() as db:
        return db.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()


def delete_report(report_id: int) -> bool:
    with get_db() as db:
        cur = db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        return cur.rowcount > 0


def get_stats() -> dict[str, Any]:
    with get_db() as db:
        row = db.execute("""
            SELECT
                COUNT(*)                        AS total_reports,
                AVG(overall_score)              AS avg_score,
                SUM(critical_count)             AS total_critical,
                SUM(high_count)                 AS total_high,
                COUNT(CASE WHEN tier='CRITICAL' THEN 1 END) AS critical_hosts,
                COUNT(CASE WHEN tier='HIGH'     THEN 1 END) AS high_hosts,
                COUNT(CASE WHEN tier='MEDIUM'   THEN 1 END) AS medium_hosts,
                COUNT(CASE WHEN tier='LOW'      THEN 1 END) AS low_hosts
            FROM reports
        """).fetchone()
        return dict(row) if row else {}
