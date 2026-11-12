"""Decide whether an incident deserves a ticket and draft it for the project manager.

The model only proposes; a person approves or rejects every proposal before it reaches anyone.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .evidence import EvidencePack
from .investigator import Diagnosis, OllamaInvestigator, choice, json_object

RECOMMENDATIONS = ("create_ticket", "no_ticket", "existing_ticket")
PRIORITIES = ("low", "medium", "high", "critical")

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "recommendation": {"type": "string", "enum": list(RECOMMENDATIONS)},
        "existing_ticket": {"type": "string"},
        "reason": {"type": "string"},
        "title": {"type": "string"},
        "priority": {"type": "string", "enum": list(PRIORITIES)},
        "description": {"type": "string"},
    },
    "required": ["recommendation", "existing_ticket", "reason", "title", "priority", "description"],
}

SYSTEM_PROMPT = """\
You help an on-call developer decide whether a production incident needs a ticket for the
project manager (PM). You get the incident, how often the same problem happened recently, the
diagnosis and the evidence it was made from. When a person reviewed the incident, the review
overrides the diagnosis: build the recommendation, reason and description on the reviewed cause.

Recommend one of:
- create_ticket: the problem needs a developer's work. It lasts, keeps coming back, affects
  customers, orders or data, or its cause is a bug or misconfiguration that will not fix itself.
- no_ticket: a one-off spike that is already gone, scanner or bot traffic that did no harm, or a
  deployment or restart whose errors stopped when it finished.
- existing_ticket: one of the similar past tickets is about the same shop and the same problem
  and is not resolved. Put its key in existing_ticket; otherwise leave existing_ticket empty.
  Similar tickets of other shops are only hints about the cause, never an existing ticket.

Then draft the ticket for the PM, who is not a developer:
- title: at most 80 characters, name the shop and the symptom.
- priority: low, medium, high or critical, by the impact on customers.
- description in JIRA wiki markup, never Markdown: h3. headings, *bold*, bullet lists with
  "* ", double curly braces around paths and identifiers such as {{/api/v2/orders}}, and
  never a bare {code} or other {macro}.
  Say what happens and since when, how often, the impact on customers, the evidence with its
  numbers, and what a developer should check first.
- reason: one or two sentences on why you recommend this.
Use only facts from the input. Write reason, title and description in {language}.
Respond with JSON only."""


@dataclass(frozen=True)
class Proposal:
    recommendation: str
    existing_ticket: str
    reason: str
    title: str
    priority: str
    description: str
    model: str = ""
    seconds: float = 0.0

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Proposal:
        return cls(**json.loads(text))


def parse_proposal(content: str, model: str = "", seconds: float = 0.0) -> Proposal:
    data = json_object(content, model, SCHEMA["required"])
    return Proposal(
        recommendation=choice(data["recommendation"], RECOMMENDATIONS),
        existing_ticket=str(data["existing_ticket"] or "").strip(),
        reason=str(data["reason"]),
        title=str(data["title"])[:120],
        priority=choice(data["priority"], PRIORITIES),
        description=str(data["description"]),
        model=model,
        seconds=round(seconds, 1),
    )


def draft(
    investigator: OllamaInvestigator,
    incident: sqlite3.Row,
    history: Sequence[sqlite3.Row],
    now: datetime,
) -> Proposal:
    system = SYSTEM_PROMPT.replace("{language}", investigator.language)
    content, seconds = investigator.complete(system, brief(incident, history, now), SCHEMA)
    return parse_proposal(content, investigator.model, seconds)


def brief(incident: sqlite3.Row, history: Sequence[sqlite3.Row], now: datetime) -> str:
    """Everything the model may use, as plain text."""
    opened = datetime.fromisoformat(incident["opened_at"])
    resolved = incident["resolved_at"]
    status = f"open for {_minutes(now - opened)}"
    if resolved:
        status = f"resolved after {_minutes(datetime.fromisoformat(resolved) - opened)}"
    lines = [
        "## Incident",
        f"rule: {incident['rule']} ({incident['severity']})",
        f"alert: {incident['summary']}",
        f"started: {_local(incident['opened_at'])}, {status}",
        "",
        "## The same problem in the last days",
    ]
    earlier = [row for row in history if row["id"] != incident["id"]]
    if not earlier:
        lines.append("(no earlier incidents)")
    for row in earlier[:12]:
        lasted = "still open"
        if row["resolved_at"]:
            began = datetime.fromisoformat(row["opened_at"])
            lasted = _minutes(datetime.fromisoformat(row["resolved_at"]) - began)
        lines.append(f"- {_local(row['opened_at'])}, {lasted}: {row['summary']}")
    if len(earlier) > 12:
        lines.append(f"(+{len(earlier) - 12} more)")
    lines.append(f"total: {len(earlier) + 1} incidents including this one")
    review = json.loads(incident["review"]) if incident["review"] else None
    if review and review["verdict"] != "correct":
        lines += [
            "",
            "## Review by a person (overrides the diagnosis)",
            f"verdict on the diagnosis: {review['verdict']}",
            f"real cause: {review['cause']}",
            f"category: {review['category']}, scope: {review['scope']}",
        ]
        if review.get("note"):
            lines.append(f"note: {review['note']}")
    if incident["diagnosis"] and not (review and review["verdict"] == "wrong"):
        diagnosis = Diagnosis(**json.loads(incident["diagnosis"]))
        lines += [
            "",
            "## Diagnosis",
            f"summary: {diagnosis.summary}",
            f"likely cause: {diagnosis.likely_cause}",
            f"category: {diagnosis.category}, scope: {diagnosis.scope}, "
            f"confidence: {diagnosis.confidence}",
            *[f"evidence: {item}" for item in diagnosis.key_evidence],
            *[f"next step: {item}" for item in diagnosis.next_steps],
        ]
    if incident["evidence"]:
        lines += ["", EvidencePack.from_json(incident["evidence"]).render()]
    return "\n".join(lines)


def new_token() -> str:
    return secrets.token_urlsafe(16)


def _minutes(delta: Any) -> str:
    minutes = max(1, round(delta.total_seconds() / 60))
    if minutes < 120:
        return f"{minutes} min"
    return f"{minutes / 60:.1f} h"


def _local(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp).astimezone().strftime("%d.%m. %H:%M")
