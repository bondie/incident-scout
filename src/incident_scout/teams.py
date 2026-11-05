"""Ticket proposals as Adaptive Cards in a Microsoft Teams channel, posted through a Workflows
(Power Automate) webhook: "Post to a channel when a webhook request is received"."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from typing import Any

import httpx

from .investigator import Diagnosis
from .proposal import Proposal

LABELS: dict[str, dict[str, str]] = {
    "English": {
        "create_ticket": "🎫 Create a ticket",
        "no_ticket": "⏭ No ticket needed",
        "existing_ticket": "🔗 Already in a ticket",
        "rule": "Rule",
        "started": "Started",
        "status": "Status",
        "open": "open",
        "resolved": "resolved",
        "recurrence": "Same problem",
        "times": "times in {days} days",
        "priority": "Priority",
        "ticket": "Ticket",
        "cause": "Likely cause",
        "approve": "Approve",
        "reject": "Reject",
        "detail": "Detail",
        "source": "Telemetry",
        "pending": "Waiting for your decision",
        "approved": "Approved: copy the text below to the PM",
        "rejected": "Rejected",
        "copy": "Copy for the PM",
        "copied": "Copied",
        "description": "Ticket text (JIRA markup)",
        "reason": "Why",
        "diagnosis": "Diagnosis",
    },
    "Czech": {
        "create_ticket": "🎫 Navrhuji založit ticket",
        "no_ticket": "⏭ Ticket není potřeba",
        "existing_ticket": "🔗 Už je v ticketu",
        "rule": "Pravidlo",
        "started": "Začátek",
        "status": "Stav",
        "open": "trvá",
        "resolved": "vyřešeno",
        "recurrence": "Stejný problém",
        "times": "x za {days} dní",
        "priority": "Priorita",
        "ticket": "Ticket",
        "cause": "Pravděpodobná příčina",
        "approve": "Schválit",
        "reject": "Zamítnout",
        "detail": "Detail",
        "source": "Telemetrie",
        "pending": "Čeká na tvoje rozhodnutí",
        "approved": "Schváleno: text níže zkopíruj pro PM",
        "rejected": "Zamítnuto",
        "copy": "Zkopírovat pro PM",
        "copied": "Zkopírováno",
        "description": "Text ticketu (JIRA markup)",
        "reason": "Proč",
        "diagnosis": "Diagnóza",
    },
}


def labels(language: str) -> dict[str, str]:
    return LABELS.get(language, LABELS["English"])


def proposal_card(
    incident: sqlite3.Row,
    proposal: Proposal,
    recurrences: int,
    days: int,
    links: Mapping[str, str],
    language: str = "English",
) -> dict[str, Any]:
    text = labels(language)
    heading = text[proposal.recommendation]
    if proposal.recommendation == "existing_ticket" and proposal.existing_ticket:
        heading = f"{heading}: {proposal.existing_ticket}"
    state = text["resolved"] if incident["resolved_at"] else text["open"]
    facts = [
        {"title": text["rule"], "value": f"{incident['rule']} #{incident['id']}"},
        {"title": text["started"], "value": _local(incident["opened_at"])},
        {"title": text["status"], "value": state},
        {"title": text["recurrence"], "value": f"{recurrences}{text['times'].format(days=days)}"},
        {"title": text["priority"], "value": proposal.priority},
    ]
    body: list[dict[str, Any]] = [
        {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": heading},
        {"type": "TextBlock", "weight": "Bolder", "text": proposal.title, "wrap": True},
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "text": proposal.reason, "wrap": True},
    ]
    if incident["diagnosis"]:
        cause = Diagnosis(**json.loads(incident["diagnosis"])).likely_cause
        body.append(
            {
                "type": "TextBlock",
                "text": f"**{text['cause']}:** {cause}",
                "wrap": True,
                "isSubtle": True,
            }
        )
    actions = [
        {"type": "Action.OpenUrl", "title": text["approve"], "url": links["approve"]},
        {"type": "Action.OpenUrl", "title": text["reject"], "url": links["reject"]},
        {"type": "Action.OpenUrl", "title": text["detail"], "url": links["detail"]},
    ]
    if incident["url"]:
        actions.append({"type": "Action.OpenUrl", "title": text["source"], "url": incident["url"]})
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": actions,
                },
            }
        ],
    }


def post(
    url: str, payload: Mapping[str, Any], transport: httpx.BaseTransport | None = None
) -> None:
    with httpx.Client(transport=transport, timeout=30) as client:
        response = client.post(url, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"Teams webhook answered {response.status_code}: {response.text[:200]}")


def _local(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp).astimezone().strftime("%d.%m. %H:%M")
