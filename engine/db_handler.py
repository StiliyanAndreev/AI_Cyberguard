import logging
import os
from contextlib import contextmanager
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

_MAX_TEXT_LEN = 100_000


def _truncate(value: str | None, max_len: int = _MAX_TEXT_LEN) -> str:
    if not value:
        return ""
    return str(value)[:max_len]


def _get_dsn() -> str:
    return (
        f"host={os.getenv('POSTGRES_HOST', 'localhost')} "
        f"port={os.getenv('POSTGRES_PORT', '5432')} "
        f"dbname={os.getenv('POSTGRES_DB', 'cyberguard')} "
        f"user={os.getenv('POSTGRES_USER', 'cyberguard')} "
        f"password={os.getenv('POSTGRES_PASSWORD', 'cyberguard')}"
    )


@contextmanager
def _conn():
    conn = psycopg2.connect(_get_dsn())
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           SERIAL PRIMARY KEY,
                    repo_name    TEXT,
                    author       TEXT,
                    commit_hash  TEXT,
                    risk_score   INTEGER,
                    report_text  TEXT,
                    diff_text    TEXT,
                    timestamp    TIMESTAMP
                )
            """)
            # Add unique index if not present (handles existing tables without constraint)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS scans_repo_commit_idx
                ON scans (repo_name, commit_hash)
            """)


def save_scan(
    repo_name: str,
    author: str,
    commit_hash: str,
    risk_score: int | None,
    report_text: str,
    diff_text: str = "",
) -> None:
    score = min(100, max(0, int(risk_score or 0)))
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans
                    (repo_name, author, commit_hash, risk_score, report_text, diff_text, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (repo_name, commit_hash) DO NOTHING
                """,
                (
                    _truncate(repo_name, 500),
                    _truncate(author, 500),
                    _truncate(commit_hash, 40),
                    score,
                    _truncate(report_text),
                    _truncate(diff_text),
                    datetime.now(),
                ),
            )


def get_all_scans() -> list[tuple]:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM scans ORDER BY timestamp DESC")
            return cur.fetchall()


def delete_scan(scan_id: int) -> None:
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
