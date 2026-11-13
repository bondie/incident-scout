from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from .models import Event, Finding

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
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    incident_id INTEGER REFERENCES incidents (id),
    grp TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_incident ON events (incident_id);
CREATE INDEX IF NOT EXISTS events_by_time ON events (at);
"""
# Columns added after the first release; existing databases get them on open.
INCIDENT_COLUMNS = (
    "diagnosis",
    "diagnosed_at",
    "evidence",
    "review",
    "reviewed_at",
    "proposal",
    "proposed_at",
    "proposal_token",
    "decision",
    "decided_at",
    "decision_reason",
    "decision_ticket",
    "labels",
    "members",
)
ID_PREFIX = "SCOUT-"


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


def short_id(incident_id: int) -> str:
    """The id a person copies from a card or notification, e.g. SCOUT-47."""
    return f"{ID_PREFIX}{incident_id}"


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.executescript(SCHEMA)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(incidents)")}
        with self.db:
            for column in INCIDENT_COLUMNS:
                if column not in columns:
                    self.db.execute(f"ALTER TABLE incidents ADD COLUMN {column} TEXT")

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

    def incident(self, incident_id: int) -> sqlite3.Row | None:
        row: sqlite3.Row | None = self.db.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return row

    def incidents_since(self, moment: datetime, rule: str | None = None) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM incidents WHERE (resolved_at IS NULL OR resolved_at >= ?) "
            "AND (? IS NULL OR rule = ?) ORDER BY opened_at DESC",
            (iso(moment), rule, rule),
        ).fetchall()

    def save_diagnosis(self, incident_id: int, diagnosis: str, now: datetime) -> None:
        with self.db:
            self.db.execute(
                "UPDATE incidents SET diagnosis = ?, diagnosed_at = ? WHERE id = ?",
                (diagnosis, iso(now), incident_id),
            )

    def save_evidence(self, incident_id: int, pack: str) -> None:
        with self.db:
            self.db.execute("UPDATE incidents SET evidence = ? WHERE id = ?", (pack, incident_id))

    def save_review(self, incident_id: int, review: str, now: datetime) -> None:
        with self.db:
            self.db.execute(
                "UPDATE incidents SET review = ?, reviewed_at = ? WHERE id = ?",
                (review, iso(now), incident_id),
            )

    def save_proposal(self, incident_id: int, proposal: str, token: str, now: datetime) -> None:
        with self.db:
            self.db.execute(
                "UPDATE incidents SET proposal = ?, proposal_token = ?, proposed_at = ?, "
                "decision = NULL, decided_at = NULL, decision_reason = NULL, "
                "decision_ticket = NULL WHERE id = ?",
                (proposal, token, iso(now), incident_id),
            )

    def decide(
        self,
        incident_id: int,
        decision: str,
        now: datetime,
        reason: str | None = None,
        ticket: str | None = None,
    ) -> None:
        """A decision without a reason or ticket keeps the ones recorded before."""
        with self.db:
            self.db.execute(
                "UPDATE incidents SET decision = ?, decided_at = ?, "
                "decision_reason = COALESCE(?, decision_reason), "
                "decision_ticket = COALESCE(?, decision_ticket) WHERE id = ?",
                (decision, iso(now), reason, ticket, incident_id),
            )

    def proposals_since(self, moment: datetime) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM incidents WHERE proposed_at >= ?", (iso(moment),)
        ).fetchone()
        return int(row[0])

    def same_problem(self, fingerprint: str, since: datetime) -> list[sqlite3.Row]:
        """Incidents of one rule and key opened since a moment, newest first."""
        return self.db.execute(
            "SELECT * FROM incidents WHERE fingerprint = ? AND opened_at >= ? "
            "ORDER BY opened_at DESC",
            (fingerprint, iso(since)),
        ).fetchall()

    def record(self, events: Iterable[Event], now: datetime) -> None:
        with self.db:
            self.db.executemany(
                "INSERT INTO events (at, kind, severity, incident_id, grp, title, message) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (iso(now), e.kind, e.severity, e.incident_id, e.group, e.title, e.message)
                    for e in events
                ],
            )

    def has_event(self, incident_id: int, kind: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM events WHERE incident_id = ? AND kind = ? LIMIT 1", (incident_id, kind)
        ).fetchone()
        return row is not None

    def timeline(self, incident: sqlite3.Row) -> list[sqlite3.Row]:
        """The incident's own events plus monitoring health changes while it was open."""
        return self.db.execute(
            "SELECT * FROM events WHERE incident_id = ? OR (incident_id IS NULL "
            "AND grp = 'health' AND at >= ? AND (? IS NULL OR at <= ?)) ORDER BY at, id",
            (incident["id"], incident["opened_at"], *[incident["resolved_at"]] * 2),
        ).fetchall()

    def diagnoses_since(self, moment: datetime) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM incidents WHERE diagnosed_at >= ?", (iso(moment),)
        ).fetchone()
        return int(row[0])

    def open(self, finding: Finding, now: datetime, first_seen: str | None = None) -> int:
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO incidents (fingerprint, rule, severity, summary, value, url, "
                "opened_at, last_seen, labels, members) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.fingerprint,
                    finding.rule,
                    finding.severity,
                    finding.summary,
                    finding.value,
                    finding.url,
                    first_seen or iso(now),
                    iso(now),
                    json.dumps(finding.labels, ensure_ascii=False),
                    _members({}, finding, first_seen or iso(now)),
                ),
            )
            self.db.execute("DELETE FROM pending WHERE fingerprint = ?", (finding.fingerprint,))
        return int(cursor.lastrowid or 0)

    def touch(self, incident_id: int, finding: Finding, now: datetime) -> None:
        row = self.db.execute(
            "SELECT members FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        known = json.loads(row["members"]) if row and row["members"] else {}
        with self.db:
            self.db.execute(
                "UPDATE incidents SET last_seen = ?, value = ?, summary = ?, missed_runs = 0, "
                "members = ? WHERE id = ?",
                (
                    iso(now),
                    finding.value,
                    finding.summary,
                    _members(known, finding, iso(now)),
                    incident_id,
                ),
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


def _members(known: dict[str, str], finding: Finding, seen_at: str) -> str:
    """Every record the problem has hit, with when it was first seen."""
    seen = dict.fromkeys((m for m in finding.members if m not in known), seen_at)
    return json.dumps({**known, **seen}, ensure_ascii=False)
