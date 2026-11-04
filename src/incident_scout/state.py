from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    value REAL,
    url TEXT,
    opened_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    resolved_at TEXT,
    missed_runs INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_incident
    ON incidents (fingerprint) WHERE resolved_at IS NULL;
CREATE TABLE IF NOT EXISTS pending (
    fingerprint TEXT PRIMARY KEY,
    rule TEXT NOT NULL,
    streak INTEGER NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_health (
    rule TEXT PRIMARY KEY,
    failed_runs INTEGER NOT NULL,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS health (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    failed_runs INTEGER NOT NULL DEFAULT 0,
    blind_since TEXT,
    last_ok TEXT,
    last_run TEXT,
    last_error TEXT
);
INSERT OR IGNORE INTO health (id) VALUES (1);
"""


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def open_incident(self, fingerprint: str) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.db.execute(
            "SELECT * FROM incidents WHERE fingerprint = ? AND resolved_at IS NULL", (fingerprint,)
        ).fetchone()
        return row

    def open_incidents(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM incidents WHERE resolved_at IS NULL ORDER BY opened_at"
        ).fetchall()

    def recent_incidents(self, limit: int = 10) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM incidents WHERE resolved_at IS NOT NULL "
            "ORDER BY resolved_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def open(self, finding: Finding, now: datetime, first_seen: str | None = None) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO incidents (fingerprint, rule, severity, summary, value, url, "
                "opened_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.fingerprint,
                    finding.rule,
                    finding.severity,
                    finding.summary,
                    finding.value,
                    finding.url,
                    first_seen or iso(now),
                    iso(now),
                ),
            )
            self.db.execute("DELETE FROM pending WHERE fingerprint = ?", (finding.fingerprint,))

    def touch(self, incident_id: int, finding: Finding, now: datetime) -> None:
        with self.db:
            self.db.execute(
                "UPDATE incidents SET last_seen = ?, value = ?, summary = ?, missed_runs = 0 "
                "WHERE id = ?",
                (iso(now), finding.value, finding.summary, incident_id),
            )

    def miss(self, incident_id: int) -> int:
        with self.db:
            row = self.db.execute(
                "UPDATE incidents SET missed_runs = missed_runs + 1 WHERE id = ? "
                "RETURNING missed_runs",
                (incident_id,),
            ).fetchone()
        return int(row[0])

    def resolve(self, incident_id: int, now: datetime) -> None:
        with self.db:
            self.db.execute(
                "UPDATE incidents SET resolved_at = ? WHERE id = ?", (iso(now), incident_id)
            )

    def bump_pending(self, finding: Finding, now: datetime) -> tuple[int, str]:
        with self.db:
            row = self.db.execute(
                "INSERT INTO pending (fingerprint, rule, streak, first_seen) VALUES (?, ?, 1, ?) "
                "ON CONFLICT (fingerprint) DO UPDATE SET streak = streak + 1 "
                "RETURNING streak, first_seen",
                (finding.fingerprint, finding.rule, iso(now)),
            ).fetchone()
        return int(row[0]), str(row[1])

    def drop_pending(self, seen: Iterable[str], evaluated_rules: Iterable[str]) -> None:
        seen, rules = set(seen), set(evaluated_rules)
        stale = [
            row["fingerprint"]
            for row in self.db.execute("SELECT fingerprint, rule FROM pending")
            if row["rule"] in rules and row["fingerprint"] not in seen
        ]
        with self.db:
            self.db.executemany(
                "DELETE FROM pending WHERE fingerprint = ?", [(fp,) for fp in stale]
            )

    def pending(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM pending ORDER BY first_seen").fetchall()

    def health(self) -> sqlite3.Row:
        row: sqlite3.Row = self.db.execute("SELECT * FROM health WHERE id = 1").fetchone()
        return row

    def run_failed(self, now: datetime, error: str) -> int:
        with self.db:
            row = self.db.execute(
                "UPDATE health SET failed_runs = failed_runs + 1, last_run = ?, last_error = ? "
                "WHERE id = 1 RETURNING failed_runs",
                (iso(now), error[:500]),
            ).fetchone()
        return int(row[0])

    def mark_blind(self, since: datetime) -> None:
        with self.db:
            self.db.execute("UPDATE health SET blind_since = ? WHERE id = 1", (iso(since),))

    def run_succeeded(self, now: datetime) -> str | None:
        """Record a successful run and return when the monitor went blind, if it was."""
        blind_since = self.health()["blind_since"]
        with self.db:
            self.db.execute(
                "UPDATE health SET failed_runs = 0, blind_since = NULL, last_ok = ?, last_run = ?, "
                "last_error = NULL WHERE id = 1",
                (iso(now), iso(now)),
            )
        return str(blind_since) if blind_since else None

    def rule_failed(self, rule: str, error: str) -> int:
        with self.db:
            row = self.db.execute(
                "INSERT INTO rule_health (rule, failed_runs, last_error) VALUES (?, 1, ?) "
                "ON CONFLICT (rule) DO UPDATE SET failed_runs = failed_runs + 1, "
                "last_error = excluded.last_error RETURNING failed_runs",
                (rule, error[:500]),
            ).fetchone()
        return int(row[0])

    def rule_succeeded(self, rule: str) -> int:
        """Reset a rule's failure streak and return how long it was."""
        row = self.db.execute(
            "SELECT failed_runs FROM rule_health WHERE rule = ?", (rule,)
        ).fetchone()
        if row is None:
            return 0
        with self.db:
            self.db.execute("DELETE FROM rule_health WHERE rule = ?", (rule,))
        return int(row[0])

    def failing_rules(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM rule_health ORDER BY rule").fetchall()
