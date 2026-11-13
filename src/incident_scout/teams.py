"""Ticket proposals as Adaptive Cards in a Microsoft Teams channel, posted through a Workflows
(Power Automate) webhook: "Post to a channel when a webhook request is received"."""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from .investigator import Diagnosis
from .proposal import Proposal
from .rules import capped
from .state import iso, short_id

GROWTH_WINDOW = timedelta(hours=3)
LOGO_MAX_BYTES = 18 * 1024
CARD_MAX_BYTES = 27 * 1024  # Teams refuses a card of about 28 KB
LOGO_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
PRIORITY_COLOURS = {"medium": "Warning", "high": "Attention", "critical": "Attention"}
_SENTENCE_END = re.compile(
    r"(?<=[.!?])(?<!\bnapř\.)(?<!\btzv\.)(?<!\bč\.)(?<!\bresp\.)(?<!\be\.g\.)(?<!\bi\.e\.)"
    r"\s+(?=[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ])"
)

LABELS: dict[str, dict[str, str]] = {
    "English": {
        "create_ticket": "Create a ticket",
        "no_ticket": "No ticket needed",
        "existing_ticket": "Already in a ticket",
        "priority": "Priority",
        "priority_note": "priority",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
        "ticket": "Ticket",
        "cause": "Likely cause",
        "cause_short": "Cause",
        "approve_ticket": "Approve the ticket",
        "reject_with_reason": "Reject with a reason",
        "decision_reason": "Reason",
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
        "affected": "Affected",
        "badge_recurs_grows": "🔁 Recurs, growing",
        "badge_recurs": "🔁 Recurs",
        "badge_grows": "📈 Growing",
        "badge_lasts": "⏳ Ongoing",
        "badge_resolved": "✅ Resolved",
        "record": "record|records|records",
        "occurrence": "occurrence|occurrences|occurrences",
        "day": "day|days|days",
        "window": "in {days} {day}, {today} today",
        "growing": "growing: +{new} in the last 3 h",
        "since": "since {when}",
        "last_seen": "last {when}",
        "resolved_at": "resolved {when}",
    },
    "Czech": {
        "create_ticket": "Navrhuji založit ticket",
        "no_ticket": "Ticket není potřeba",
        "existing_ticket": "Už je v ticketu",
        "priority": "Priorita",
        "priority_note": "priorita",
        "low": "Nízká",
        "medium": "Střední",
        "high": "Vysoká",
        "critical": "Kritická",
        "ticket": "Ticket",
        "cause": "Pravděpodobná příčina",
        "cause_short": "Příčina",
        "approve_ticket": "Schválit ticket",
        "reject_with_reason": "Zamítnout s důvodem",
        "decision_reason": "Důvod",
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
        "affected": "Zasažené",
        "badge_recurs_grows": "🔁 Opakuje se, přibývá",
        "badge_recurs": "🔁 Opakuje se",
        "badge_grows": "📈 Přibývá",
        "badge_lasts": "⏳ Trvá",
        "badge_resolved": "✅ Vyřešeno",
        "record": "záznam|záznamy|záznamů",
        "occurrence": "výskyt|výskyty|výskytů",
        "day": "den|dny|dní",
        "window": "za {days} {day}, {today} dnes",
        "growing": "přibývá: +{new} za poslední 3 h",
        "since": "od {when}",
        "last_seen": "naposledy {when}",
        "resolved_at": "vyřešeno {when}",
    },
}


@dataclass(frozen=True)
class Header:
    shop: str
    title: str
    logo: str | None = None


@dataclass(frozen=True)
class Scope:
    """How far a problem reaches: the records it hit, or its incidents when it names none."""

    count: int
    today: int
    new: int
    members: tuple[str, ...]
    incidents: int
    since: str

    @property
    def recurs(self) -> bool:
        return self.incidents > 1

    @property
    def growing(self) -> bool:
        return self.new > 0


def labels(language: str) -> dict[str, str]:
    return LABELS.get(language, LABELS["English"])


def scope(
    incident: sqlite3.Row, history: Sequence[sqlite3.Row], now: datetime, records: bool = False
) -> Scope:
    """Records only for rules that name them; any other problem counts its incidents."""
    rows = list({row["id"]: row for row in (*history, incident)}.values())
    opened = [row["opened_at"] for row in rows]
    seen = _first_seen(rows) if records else {}
    if not seen:
        return Scope(len(rows), _today(opened, now), 0, (), len(rows), incident["opened_at"])
    members = tuple(sorted(seen, key=seen.__getitem__))
    start, recent = seen[members[0]], iso(now - GROWTH_WINDOW)
    new = sum(1 for first in seen.values() if first > start and first >= recent)
    since = min(start, *opened)
    return Scope(len(seen), _today(list(seen.values()), now), new, members, len(rows), since)


def _first_seen(rows: Sequence[sqlite3.Row]) -> dict[str, str]:
    seen: dict[str, str] = {}
    for row in rows:
        for member, first in json.loads(row["members"] or "{}").items():
            seen[member] = min(first, seen.get(member, first))
    return seen


def logo(value: str | None) -> str | None:
    """A logo Teams can show: an https URL as it is, a small local png or jpg inlined."""
    if not value:
        return None
    if value.startswith("https://"):
        return value
    path = Path(value).expanduser()
    kind = LOGO_TYPES.get(path.suffix.lower())
    if kind is None or not path.is_file():
        print(
            f"logo {value} skipped: Teams needs a png or jpg file or an https URL", file=sys.stderr
        )
        return None
    data = path.read_bytes()
    if len(data) > LOGO_MAX_BYTES:
        print(f"logo {value} skipped: {len(data) // 1024} KB, at most 18 KB fit", file=sys.stderr)
        return None
    return f"data:{kind};base64,{base64.b64encode(data).decode()}"


def proposal_card(
    incident: sqlite3.Row,
    proposal: Proposal,
    header: Header,
    reach: Scope,
    days: int,
    links: Mapping[str, str],
    language: str = "English",
) -> dict[str, Any]:
    text = labels(language)
    ref = short_id(incident["id"])
    covered = proposal.recommendation == "existing_ticket" and bool(proposal.existing_ticket)
    parts = (
        _covered(proposal, links, text)
        if covered
        else _full(incident, proposal, reach, days, links, text)
    )
    footer = f"{ref} · {incident['rule']}"
    body = [
        _header(header, incident, reach, text),
        *parts,
        {"type": "TextBlock", "text": footer, "size": "Small", "isSubtle": True, "wrap": True},
    ]
    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "fallbackText": f"🎫 {ref} · {proposal.title}",
                    "body": body,
                },
            }
        ],
    }
    if header.logo and card_bytes(card) > CARD_MAX_BYTES:
        print(f"{ref}: logo left out, the card would exceed what Teams accepts", file=sys.stderr)
        plain = replace(header, logo=None)
        return proposal_card(incident, proposal, plain, reach, days, links, language)
    return card


def _full(
    incident: sqlite3.Row,
    proposal: Proposal,
    reach: Scope,
    days: int,
    links: Mapping[str, str],
    text: Mapping[str, str],
) -> list[dict[str, Any]]:
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": proposal.title,
            "size": "Large",
            "weight": "Bolder",
            "wrap": True,
        },
        {"type": "TextBlock", "text": _sentence(proposal.reason), "wrap": True},
        _numbers(incident, proposal, reach, days, text),
    ]
    if len(reach.members) > 1:
        affected = f"{text['affected']}: {capped(reach.members)}"
        body.append({"type": "TextBlock", "text": affected, "size": "Small", "wrap": True})
    cause = _cause(incident)
    if cause:
        body.append(
            {
                "type": "Container",
                "style": "emphasis",
                "items": [
                    {"type": "TextBlock", "text": text["cause_short"], "weight": "Bolder"},
                    {
                        "type": "TextBlock",
                        "text": _sentence(cause),
                        "wrap": True,
                        "spacing": "Small",
                    },
                ],
            }
        )
    body.append(
        {
            "type": "TextBlock",
            "text": _recommendation(proposal, text),
            "size": "Medium",
            "weight": "Bolder",
            "color": "Accent",
            "wrap": True,
            "spacing": "Large",
        }
    )
    body.append(
        {"type": "ActionSet", "actions": _actions(incident, links, text), "spacing": "Small"}
    )
    return body


def _covered(
    proposal: Proposal, links: Mapping[str, str], text: Mapping[str, str]
) -> list[dict[str, Any]]:
    """A problem an existing ticket covers needs no decision, only a way to the detail."""
    detail = {"type": "Action.OpenUrl", "title": text["detail"], "url": links["detail"]}
    return [
        {
            "type": "TextBlock",
            "text": _recommendation(proposal, text),
            "weight": "Bolder",
            "wrap": True,
        },
        {"type": "TextBlock", "text": proposal.title, "wrap": True, "spacing": "None"},
        {"type": "TextBlock", "text": _sentence(proposal.reason), "size": "Small", "wrap": True},
        {"type": "ActionSet", "actions": [detail]},
    ]


def card_bytes(card: Mapping[str, Any]) -> int:
    """The size of the card as `post` sends it."""
    return len(json.dumps(card, ensure_ascii=False, separators=(",", ":")).encode())


def post(
    url: str, payload: Mapping[str, Any], transport: httpx.BaseTransport | None = None
) -> None:
    with httpx.Client(transport=transport, timeout=30) as client:
        response = client.post(url, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"Teams webhook answered {response.status_code}: {response.text[:200]}")


def _header(
    header: Header, incident: sqlite3.Row, reach: Scope, text: Mapping[str, str]
) -> dict[str, Any]:
    style, badge = _badge(incident, reach)
    columns: list[dict[str, Any]] = []
    if header.logo:
        image = {"type": "Image", "url": header.logo, "width": "32px", "altText": header.shop}
        columns.append(
            {
                "type": "Column",
                "width": "auto",
                "verticalContentAlignment": "Center",
                "items": [image],
            }
        )
    names: list[dict[str, Any]] = []
    if header.shop and not header.logo:
        names.append(
            {"type": "TextBlock", "text": header.shop, "weight": "Bolder", "size": "Medium"}
        )
    names.append({"type": "TextBlock", "text": header.title, "spacing": "None", "wrap": True})
    columns.append(
        {
            "type": "Column",
            "width": "stretch",
            "verticalContentAlignment": "Center",
            "items": names,
        }
    )
    status = {"type": "TextBlock", "text": text[badge], "weight": "Bolder", "size": "Small"}
    columns.append(
        {
            "type": "Column",
            "width": "auto",
            "verticalContentAlignment": "Center",
            "items": [{"type": "Container", "style": style, "items": [status]}],
        }
    )
    return {"type": "ColumnSet", "columns": columns}


def _badge(incident: sqlite3.Row, reach: Scope) -> tuple[str, str]:
    if incident["resolved_at"]:
        return "good", "badge_resolved"
    if reach.recurs and reach.growing:
        return "attention", "badge_recurs_grows"
    if reach.recurs:
        return "attention", "badge_recurs"
    if reach.growing:
        return "attention", "badge_grows"
    return "warning", "badge_lasts"


def _numbers(
    incident: sqlite3.Row, proposal: Proposal, reach: Scope, days: int, text: Mapping[str, str]
) -> dict[str, Any]:
    unit = _plural(text, "record" if reach.members else "occurrence", reach.count)
    count = {
        "type": "TextBlock",
        "text": f"{reach.count} {unit}",
        "size": "Large",
        "weight": "Bolder",
        "color": "Attention" if reach.growing else "Default",
    }
    window = text["window"].format(days=days, day=_plural(text, "day", days), today=reach.today)
    extent = [count, _small(window)]
    if reach.growing:
        extent.append(_small(text["growing"].format(new=reach.new)))
    opened = datetime.fromisoformat(reach.since).astimezone()
    last = "resolved_at" if incident["resolved_at"] else "last_seen"
    ended = datetime.fromisoformat(incident[last]).astimezone()
    duration = [
        {"type": "TextBlock", "text": text["since"].format(when=_when(opened)), "weight": "Bolder"},
        _small(text[last].format(when=_later(ended, opened))),
    ]
    priority = [
        {
            "type": "TextBlock",
            "text": text.get(proposal.priority, proposal.priority),
            "weight": "Bolder",
            "color": PRIORITY_COLOURS.get(proposal.priority, "Default"),
        },
        _small(text["priority_note"]),
    ]
    return {
        "type": "ColumnSet",
        "columns": [
            {"type": "Column", "width": "stretch", "items": items}
            for items in (extent, duration, priority)
        ],
    }


def _actions(
    incident: sqlite3.Row, links: Mapping[str, str], text: Mapping[str, str]
) -> list[dict[str, Any]]:
    actions = [
        {
            "type": "Action.OpenUrl",
            "title": text["approve_ticket"],
            "url": links["approve"],
            "style": "positive",
        },
        {
            "type": "Action.OpenUrl",
            "title": text["reject_with_reason"],
            "url": links["reject_form"],
        },
        {"type": "Action.OpenUrl", "title": text["detail"], "url": links["detail"]},
    ]
    if incident["url"]:
        actions.append({"type": "Action.OpenUrl", "title": text["source"], "url": incident["url"]})
    return actions


def _recommendation(proposal: Proposal, text: Mapping[str, str]) -> str:
    heading = text.get(proposal.recommendation, proposal.recommendation)
    if proposal.recommendation == "existing_ticket" and proposal.existing_ticket:
        return f"{heading}: {proposal.existing_ticket}"
    return heading


def _cause(incident: sqlite3.Row) -> str:
    """The reviewed cause when a person corrected the diagnosis, else the diagnosis."""
    review = json.loads(incident["review"]) if incident["review"] else {}
    if review.get("verdict") in ("wrong", "partial"):
        return str(review["cause"])
    if not incident["diagnosis"]:
        return ""
    return Diagnosis(**json.loads(incident["diagnosis"])).likely_cause


def _sentence(text: str) -> str:
    return _SENTENCE_END.split(text.strip(), maxsplit=1)[0]


def _small(text: str) -> dict[str, Any]:
    return {"type": "TextBlock", "text": text, "size": "Small", "spacing": "None", "wrap": True}


def _plural(text: Mapping[str, str], key: str, count: int) -> str:
    one, few, many = text[key].split("|")
    if count == 1:
        return one
    if 2 <= count <= 4:
        return few
    return many


def _today(moments: Sequence[str], now: datetime) -> int:
    day = now.astimezone().date()
    return sum(1 for moment in moments if datetime.fromisoformat(moment).astimezone().date() == day)


def _when(moment: datetime) -> str:
    return f"{moment.day}. {moment.month}. {moment:%H:%M}"


def _later(moment: datetime, opened: datetime) -> str:
    if moment.date() == opened.date():
        return f"{moment:%H:%M}"
    return _when(moment)
