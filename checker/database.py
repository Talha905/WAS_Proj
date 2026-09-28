"""
checker/database.py
SQLite persistence layer for scan metadata and results.
"""
import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "instance" / "checker.db"


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id               TEXT PRIMARY KEY,
                target_url       TEXT NOT NULL,
                spec_source      TEXT NOT NULL,
                config_json      TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                started_at       TEXT,
                completed_at     TEXT,
                total_checks     INTEGER DEFAULT 0,
                completed_checks INTEGER DEFAULT 0,
                scan_depth       TEXT DEFAULT 'standard',
                acm_json         TEXT,
                policy_score     INTEGER,
                lifecycle_log    TEXT
            );

            CREATE TABLE IF NOT EXISTS results (
                id                   TEXT PRIMARY KEY,
                scan_id              TEXT NOT NULL,
                endpoint             TEXT NOT NULL,
                method               TEXT NOT NULL,
                module_name          TEXT NOT NULL,
                payload_json         TEXT,
                expected_status      INTEGER,
                actual_status        INTEGER,
                response_snippet     TEXT,
                response_headers_json TEXT,
                verdict              TEXT NOT NULL,
                severity             TEXT NOT NULL,
                evidence_diff        TEXT,
                remediation          TEXT,
                created_at           TEXT,
                similarity_score     REAL,
                baseline_snippet     TEXT,
                sensitive_fields     TEXT,
                poe_curl             TEXT,
                poe_python           TEXT,
                is_canary            INTEGER DEFAULT 0,
                mutation_verified    INTEGER
            );
        """)

        # Run graceful migrations for existing SQLite databases
        scan_cols = [
            ("scan_depth", "TEXT DEFAULT 'standard'"),
            ("acm_json", "TEXT"),
            ("policy_score", "INTEGER"),
            ("lifecycle_log", "TEXT"),
        ]
        for col_name, col_type in scan_cols:
            try:
                conn.execute(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass

        result_cols = [
            ("similarity_score", "REAL"),
            ("baseline_snippet", "TEXT"),
            ("sensitive_fields", "TEXT"),
            ("poe_curl", "TEXT"),
            ("poe_python", "TEXT"),
            ("is_canary", "INTEGER DEFAULT 0"),
            ("mutation_verified", "INTEGER"),
        ]
        for col_name, col_type in result_cols:
            try:
                conn.execute(f"ALTER TABLE results ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass


def _row_to_dict(row) -> dict:
    return dict(row) if row else None


def create_scan(target_url: str, spec_source: str, config: dict) -> str:
    scan_id = str(uuid.uuid4())
    scan_depth = config.get("scan_depth", "standard")
    with get_db() as conn:
        conn.execute(
            """INSERT INTO scans (id, target_url, spec_source, config_json, status, started_at, scan_depth)
               VALUES (?, ?, ?, ?, 'running', ?, ?)""",
            (scan_id, target_url, spec_source, json.dumps(config),
             datetime.now(timezone.utc).isoformat(), scan_depth),
        )
    return scan_id


def update_scan(scan_id: str, **kwargs) -> None:
    allowed = {
        "status",
        "completed_at",
        "total_checks",
        "completed_checks",
        "scan_depth",
        "acm_json",
        "policy_score",
        "lifecycle_log",
    }
    cols = {k: v for k, v in kwargs.items() if k in allowed}
    if not cols:
        return
    set_clause = ", ".join(f"{k} = ?" for k in cols)
    values = list(cols.values()) + [scan_id]
    with get_db() as conn:
        conn.execute(f"UPDATE scans SET {set_clause} WHERE id = ?", values)


def add_result(scan_id: str, result: dict) -> str:
    result_id = str(uuid.uuid4())
    sens_fields = result.get("sensitive_fields")
    sens_str = json.dumps(sens_fields) if isinstance(sens_fields, list) else (sens_fields or "")

    with get_db() as conn:
        conn.execute(
            """INSERT INTO results
               (id, scan_id, endpoint, method, module_name, payload_json,
                expected_status, actual_status, response_snippet,
                response_headers_json, verdict, severity, evidence_diff,
                remediation, created_at, similarity_score, baseline_snippet,
                sensitive_fields, poe_curl, poe_python, is_canary, mutation_verified)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result_id,
                scan_id,
                result.get("endpoint", ""),
                result.get("method", ""),
                result.get("module_name", ""),
                json.dumps(result.get("payload", {})),
                result.get("expected_status"),
                result.get("actual_status"),
                result.get("response_snippet", "")[:4000],
                json.dumps(result.get("response_headers", {})),
                result.get("verdict", "INCONCLUSIVE"),
                result.get("severity", "INFO"),
                result.get("evidence_diff", ""),
                result.get("remediation", ""),
                datetime.now(timezone.utc).isoformat(),
                result.get("similarity_score"),
                result.get("baseline_snippet", "")[:2000],
                sens_str,
                result.get("poe_curl", ""),
                result.get("poe_python", ""),
                1 if result.get("is_canary") else 0,
                result.get("mutation_verified"),
            ),
        )
    return result_id


def get_scan(scan_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _row_to_dict(row)


def get_results(scan_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM results WHERE scan_id = ? ORDER BY created_at", (scan_id,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_result(result_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM results WHERE id = ?", (result_id,)).fetchone()
        return _row_to_dict(row)


def delete_scan(scan_id: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM results WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def list_scans() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC"
        ).fetchall()
        results = []
        for row in rows:
            d = _row_to_dict(row)
            # attach summary counts
            counts = conn.execute(
                """SELECT verdict, COUNT(*) as cnt FROM results
                   WHERE scan_id = ? GROUP BY verdict""",
                (d["id"],),
            ).fetchall()
            vc = {r["verdict"]: r["cnt"] for r in counts}
            total = sum(vc.values())
            summary = {
                "total": total,
                "needs_fix": vc.get("NEEDS_FIX", 0),
                "passes": vc.get("PASSES", 0),
                "inconclusive": vc.get("INCONCLUSIVE", 0),
            }
            d["verdict_counts"] = vc
            d["summary"] = summary
            results.append(d)
        return results
