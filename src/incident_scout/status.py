"""The state a desktop viewer shows, as `status.json` next to the database.

Written after every check and decision, so a viewer reads one small file instead of opening
the database, which `Store` would write to. It holds proposal tokens, so only its owner can
read it.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from . import server
from .proposal import Proposal
from .state import Store, iso, short_id

VERSION = 1
RECENT = 5
DIAGNOSIS_FIELDS = ("summary", "likely_cause", "category", "scope", "confidence")
DIAGNOSIS_LISTS = ("next_steps", "key_evidence")


def status_path(state_path: Path) -> Path:
    return state_path.with_name("status.json")


def snapshot(store: Store, now: datetime, port: int | None) -> dict[str, Any]:
    base = f"http://127.0.0.1:{port}" if port else None
    health = store.health()
    undecided = store.db.execute(
        "SELECT * FROM incidents WHERE proposal IS NOT NULL AND decision IS NULL "
        "ORDER BY proposed_at DESC"
    ).fetchall()
    return {
        "version": VERSION,
        "generated_at": iso(now),
        "health": {
            "last_run": health["last_run"],
            "last_ok": health["last_ok"],
            "blind_since": health["blind_since"],
            "failed_runs": health["failed_runs"],
            "last_error": health["last_error"],
        },
        "failing_rules": [
            {"rule": row["rule"], "failed_runs": row["failed_runs"], "error": row["last_error"]}
            for row in store.failing_rules()
        ],
        "open": [incident(row, base) for row in store.open_incidents()],
        "pending": [
            {
                "rule": row["rule"],
                "project": project(row["rule"]),
                "streak": row["streak"],
                "first_seen": row["first_seen"],
            }
            for row in store.pending()
        ],
        "proposals": [incident(row, base) for row in undecided],
        "recent": [incident(row, base) for row in store.recent_incidents(RECENT)],
    }


def project(rule: str) -> str | None:
    """Rules fanned out over sources are named `rule@source`; the source is the project."""
    _, _, source = rule.partition("@")
    return source or None


def incident(row: sqlite3.Row, base: str | None) -> dict[str, Any]:
    data = {
        "id": short_id(row["id"]),
        "rule": row["rule"],
        "project": project(row["rule"]),
        "severity": row["severity"],
        "summary": row["summary"],
        "opened_at": row["opened_at"],
        "last_seen": row["last_seen"],
        "resolved_at": row["resolved_at"],
        "url": row["url"],
        "value": row["value"],
        "diagnosis": diagnosis(row["diagnosis"]),
        "proposal": None,
    }
    if not row["proposal"]:
        return data
    proposal = Proposal.from_json(row["proposal"])
    token = row["proposal_token"]
    data["proposal"] = {
        "title": proposal.title,
        "priority": proposal.priority,
        "recommendation": proposal.recommendation,
        "existing_ticket": proposal.existing_ticket or None,
        "reason": proposal.reason or None,
        "description": proposal.description or None,
        "proposed_at": row["proposed_at"],
        "decision": row["decision"],
        "ticket": row["decision_ticket"],
        "page": server.links(base, row["id"], token)["detail"] if base and token else None,
    }
    return data


def diagnosis(text: str | None) -> dict[str, Any] | None:
    """The investigator's verdict without the model bookkeeping; None when there is none."""
    try:
        data = json.loads(text or "")
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    found: dict[str, Any] = {key: data.get(key) for key in DIAGNOSIS_FIELDS}
    for key in DIAGNOSIS_LISTS:
        value = data.get(key)
        found[key] = [str(item) for item in value] if isinstance(value, list) else []
    return found


def write(store: Store, now: datetime, port: int | None) -> None:
    """Replace the file in one step, so a viewer never reads half of it."""
    path = status_path(store.path)
    text = json.dumps(snapshot(store, now, port), ensure_ascii=False, indent=1)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".status-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        Path(temporary).replace(path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
