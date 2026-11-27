"""Ticket proposals and incidents as Adaptive Cards in Microsoft Teams channels, posted through
a Workflows (Power Automate) webhook: "Post to a channel when a webhook request is received"."""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from .investigator import Diagnosis
from .models import Event
from .proposal import Proposal
from .rules import capped
from .state import iso, short_id
from .tracker import duration

GROWTH_WINDOW = timedelta(hours=3)
LOGO_MAX_BYTES = 18 * 1024
CARD_MAX_BYTES = 27 * 1024  # Teams refuses a card of about 28 KB
LOGO_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
LEVEL_COLOURS = {
    "critical": "Attention",
    "warning": "Warning",
    "info": "Accent",
    "resolved": "Good",
}
STATUS_COLOURS = {"status_lasts": "Warning", "status_resolved": "Good"}
MARKER = "\u258d"
HANDOFF_ID = "handoff"
TITLE_MAX_CHARS = 200
DETAIL_MAX_CHARS = 200
DIAGNOSIS_MAX_CHARS = 800
_SENTENCE_END = re.compile(
    r"(?<=[.!?])(?<!\bnapř\.)(?<!\btzv\.)(?<!\bč\.)(?<!\bresp\.)(?<!\be\.g\.)(?<!\bi\.e\.)"
    r"\s+(?=[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ])"
)
_RECORD_COUNT = re.compile(r"(\d+)\s*\u00d7")
_LIST_START = re.compile(r"^(\s*\d+)\. ", re.MULTILINE)
_LINK_TEXT = str.maketrans({"[": "\\[", "]": "\\]", "(": "\\(", ")": "\\)"})
_LINK_URL = str.maketrans({"(": "%28", ")": "%29", " ": "%20"})

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
        "handoff": "For the bot",
        "pm_message": "Text for the PM",
        "ticket_draft": "Ticket draft",
        "project": "Project",
        "title": "Title",
        "description": "Ticket text (JIRA markup)",
        "reason": "Why",
        "diagnosis": "Diagnosis",
        "affected": "Affected",
        "status_recurs_grows": "Recurs, growing",
        "status_recurs": "Recurs",
        "status_grows": "Growing",
        "status_lasts": "Ongoing",
        "status_resolved": "Resolved",
        "level_critical": "Critical",
        "level_warning": "Warning",
        "level_info": "Info",
        "level_resolved": "Resolved",
        "records": "Records",
        "occurrences": "Occurrences",
        "window": "{unit} ({days} d)",
        "started": "Started",
        "ended": "Ended",
        "duration": "Duration",
        "last_seen": "Last seen",
        "cause_note": "Cause: {cause}",
        "confidence_note": " (confidence {confidence})",
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
        "handoff": "Pro bota",
        "pm_message": "Text pro PM",
        "ticket_draft": "Návrh ticketu",
        "project": "Projekt",
        "title": "Název",
        "description": "Text ticketu (JIRA markup)",
        "reason": "Proč",
        "diagnosis": "Diagnóza",
        "affected": "Zasažené",
        "status_recurs_grows": "Opakuje se, přibývá",
        "status_recurs": "Opakuje se",
        "status_grows": "Přibývá",
        "status_lasts": "Trvá",
        "status_resolved": "Vyřešeno",
        "level_critical": "Kritický",
        "level_warning": "Varování",
        "level_info": "Informace",
        "level_resolved": "Vyřešeno",
        "records": "Záznamy",
        "occurrences": "Výskyty",
        "window": "{unit} ({days} d)",
        "started": "Začátek",
        "ended": "Konec",
        "duration": "Trvání",
        "last_seen": "Naposledy",
        "cause_note": "Příčina: {cause}",
        "confidence_note": " (jistota {confidence})",
    },
}


@dataclass(frozen=True)
class Header:
    """`shop` is the name shown, `key` the shop label or var a summary may start with, and
    `context` the shared source an affected shop was found in (Orchesty)."""

    shop: str
    title: str
    logo: str | None = None
    key: str = ""
    context: str = ""
    project: str = ""


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


@dataclass(frozen=True)
class Stat:
    """A narrow column at the right of the card: a label above a value, maybe a date under it."""

    label: str
    value: str
    under: str = ""


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
    """One row like an issue in Sentry's list, then the cause and the decision buttons."""
    text = labels(language)
    ref = short_id(incident["id"])
    status = _status(incident, reach)
    colour = STATUS_COLOURS.get(status, "Attention")
    priority = f"{text['priority_note']} {text.get(proposal.priority, proposal.priority).lower()}"
    unit = text["records" if reach.members else "occurrences"]
    stats = [
        Stat(text["window"].format(unit=unit, days=days), str(reach.count)),
        _moment(text["last_seen"], incident["resolved_at"] or incident["last_seen"]),
    ]
    meta = [ref, (text[status], colour), header.shop, header.context, priority, incident["rule"]]
    title = _link(proposal.title, links["detail"])
    body = [_row(title, _sentence(proposal.reason), colour, _meta(header, meta), stats)]
    covered = proposal.recommendation == "existing_ticket" and bool(proposal.existing_ticket)
    if covered:
        body += _covered(proposal, links, text)
    if not covered:
        body += _full(incident, proposal, header, reach, links, text)
    card = _message(body, f"🎫 {ref} · {proposal.title}")
    if header.logo and card_bytes(card) > CARD_MAX_BYTES:
        print(f"{ref}: logo left out, the card would exceed what Teams accepts", file=sys.stderr)
        plain = replace(header, logo=None)
        return proposal_card(incident, proposal, plain, reach, days, links, language)
    return card


def incident_card(
    event: Event,
    incident: sqlite3.Row | None,
    header: Header,
    diagnosis: Diagnosis | None = None,
    language: str = "English",
) -> dict[str, Any]:
    """An opened incident with its diagnosis when the check made one, or a short resolved note."""
    text = labels(language)
    resolved = event.kind == "resolved"
    level = "resolved" if resolved else event.severity
    colour = LEVEL_COLOURS.get(level, "Default")
    summary = incident["summary"] if resolved and incident is not None else event.message
    shops = (header.key, header.shop, header.context)
    title, message = header.title, without_shop(summary or event.title, shops)
    if not title:
        title, message = headline(summary or event.title, shops)
    meta: list[str | tuple[str, str]] = [
        (text.get(f"level_{level}", level), colour),
        header.shop,
        header.context,
    ]
    if incident is not None:
        meta = [short_id(incident["id"]), *meta, incident["rule"]]
    stats = _incident_stats(event, incident, text, resolved)
    body = [_row(_link(title, event.url), message, colour, _meta(header, meta), stats)]
    if diagnosis is not None and not resolved:
        body.append(_note(_diagnosis(diagnosis, text)))
    if event.url:
        source = {"type": "Action.OpenUrl", "title": text["source"], "url": event.url}
        body.append({"type": "ActionSet", "actions": [source]})
    card = _message(body, f"{event.title}: {_clip(event.message, 200)}")
    if header.logo and card_bytes(card) > CARD_MAX_BYTES:
        print(
            f"{event.title}: logo left out, the card would exceed what Teams accepts",
            file=sys.stderr,
        )
        return incident_card(event, incident, replace(header, logo=None), diagnosis, language)
    return card


def headline(summary: str, shops: Sequence[str] = ()) -> tuple[str, str]:
    """The problem sentence and its detail, `shop: X (3 chyb) - why` gives X and `3 chyb - why`."""
    text = without_shop(summary, shops)
    head, opening, rest = text.partition(" (")
    if not opening or not head.strip():
        return text, ""
    inside, _closing, tail = rest.partition(")")
    return head.strip(), f"{inside}{tail}".strip()


def without_shop(summary: str, shops: Sequence[str] = ()) -> str:
    """The summary without its leading `shop: `, which the card already names."""
    text = summary.strip()
    for shop in shops:
        if shop and text.lower().startswith(f"{shop.lower()}: "):
            return text[len(shop) + 2 :].lstrip()
    return text


def stored_diagnosis(incident: sqlite3.Row) -> Diagnosis | None:
    if not incident["diagnosis"]:
        return None
    return Diagnosis(**json.loads(incident["diagnosis"]))


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


def _row(
    title: str, message: str, colour: str, meta: dict[str, Any], stats: Sequence[Stat]
) -> dict[str, Any]:
    """Title, message with a level marker and a meta line on the left, the stats on the right."""
    left: list[dict[str, Any]] = [
        {"type": "TextBlock", "text": title, "size": "Medium", "weight": "Bolder", "wrap": True}
    ]
    if message:
        marker = {"type": "TextBlock", "text": MARKER, "color": colour, "weight": "Bolder"}
        line = {
            "type": "TextBlock",
            "text": _unlisted(_clip(message, DETAIL_MAX_CHARS)),
            "wrap": True,
        }
        left.append(
            {
                "type": "ColumnSet",
                "spacing": "Small",
                "columns": [
                    {"type": "Column", "width": "auto", "items": [marker]},
                    {"type": "Column", "width": "stretch", "spacing": "Small", "items": [line]},
                ],
            }
        )
    left.append(meta | {"spacing": "Small"})
    columns = [{"type": "Column", "width": "stretch", "items": left}]
    if stats:
        items = [item for number, stat in enumerate(stats) for item in _stat(stat, number)]
        columns.append(
            {
                "type": "Column",
                "width": "auto",
                "spacing": "Large",
                "verticalContentAlignment": "Center",
                "items": items,
            }
        )
    return {"type": "ColumnSet", "columns": columns}


def _stat(stat: Stat, number: int) -> list[dict[str, Any]]:
    label = {"type": "TextBlock", "text": stat.label, "size": "Small", "isSubtle": True}
    items: list[dict[str, Any]] = [
        label | ({"spacing": "Medium"} if number else {}),
        {"type": "TextBlock", "text": stat.value, "weight": "Bolder", "spacing": "None"},
    ]
    if stat.under:
        items.append(
            {
                "type": "TextBlock",
                "text": stat.under,
                "size": "Small",
                "isSubtle": True,
                "spacing": "None",
            }
        )
    return items


def _meta(header: Header, parts: Sequence[str | tuple[str, str]]) -> dict[str, Any]:
    """`SCOUT-1 | Critical | Shop | rule`, only the status coloured, after the shop's logo."""
    runs: list[dict[str, Any]] = []
    plain = ""
    for part in parts:
        if not part:
            continue
        plain += " | " if runs or plain else ""
        if isinstance(part, str):
            plain += part
            continue
        if plain:
            runs.append(_run(plain))
        plain = ""
        word, colour = part
        runs.append(_run(word) | {"color": colour, "weight": "Bolder", "isSubtle": False})
    if plain:
        runs.append(_run(plain))
    line = {"type": "RichTextBlock", "inlines": runs}
    if not header.logo:
        return line
    image = {"type": "Image", "url": header.logo, "width": "16px", "altText": header.shop}
    return {
        "type": "ColumnSet",
        "columns": [
            {"type": "Column", "width": "auto", "items": [image]},
            {
                "type": "Column",
                "width": "stretch",
                "spacing": "Small",
                "verticalContentAlignment": "Center",
                "items": [line],
            },
        ],
    }


def _run(text: str) -> dict[str, Any]:
    return {"type": "TextRun", "text": text, "size": "Small", "isSubtle": True}


def _incident_stats(
    event: Event, incident: sqlite3.Row | None, text: Mapping[str, str], resolved: bool
) -> list[Stat]:
    if incident is None:
        return []
    if resolved and incident["resolved_at"]:
        opened = datetime.fromisoformat(incident["opened_at"])
        ended = datetime.fromisoformat(incident["resolved_at"])
        lasted = Stat(text["duration"], duration((ended - opened).total_seconds()))
        return [lasted, _moment(text["ended"], incident["resolved_at"])]
    stats = [_moment(text["started"], incident["opened_at"])]
    count = _records(event.message, incident)
    if count:
        stats.append(Stat(text["records"], str(count)))
    return stats


def _moment(label: str, moment: str) -> Stat:
    """Teams writes the date and time in the reader's language and time zone."""
    exact = _rfc3339(moment)
    return Stat(label, f"{{{{TIME({exact})}}}}", f"{{{{DATE({exact}, SHORT)}}}}")


def _rfc3339(moment: str) -> str:
    """Teams expands DATE and TIME only for seconds with a zone, else it shows the raw text."""
    parsed = datetime.fromisoformat(moment)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.replace(microsecond=0).isoformat()


def _records(summary: str, incident: sqlite3.Row) -> int:
    members = json.loads(incident["members"] or "{}")
    if members:
        return len(members)
    found = _RECORD_COUNT.search(summary)
    return int(found.group(1)) if found else 0


def _diagnosis(diagnosis: Diagnosis, text: Mapping[str, str]) -> str:
    """The cause only: the model's summary mostly restates the problem the card already names."""
    cause = text["cause_note"].format(
        cause=_clip(diagnosis.likely_cause or diagnosis.summary, DIAGNOSIS_MAX_CHARS)
    )
    if not diagnosis.confidence:
        return cause
    confidence = text.get(diagnosis.confidence, diagnosis.confidence).lower()
    return cause + text["confidence_note"].format(confidence=confidence)


def _note(line: str) -> dict[str, Any]:
    return {"type": "TextBlock", "text": _unlisted(line), "size": "Small", "wrap": True}


def _message(body: list[dict[str, Any]], fallback: str) -> dict[str, Any]:
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
                    "fallbackText": fallback,
                    "body": body,
                },
            }
        ],
    }


def _full(
    incident: sqlite3.Row,
    proposal: Proposal,
    header: Header,
    reach: Scope,
    links: Mapping[str, str],
    text: Mapping[str, str],
) -> list[dict[str, Any]]:
    body: list[dict[str, Any]] = []
    cause = _cause(incident)
    if cause:
        body.append(_note(text["cause_note"].format(cause=_sentence(cause))))
    if len(reach.members) > 1:
        body.append(_note(f"{text['affected']}: {capped(reach.members)}") | {"isSubtle": True})
    return [
        *body,
        _recommendation(proposal, text),
        {"type": "ActionSet", "actions": _actions(incident, links, text), "spacing": "Small"},
        _handoff(proposal, header, text),
    ]


def _handoff(proposal: Proposal, header: Header, text: Mapping[str, str]) -> dict[str, Any]:
    """A collapsed block with fixed ids that a chat bot reads; a person's command decides
    what happens with it, the text is never an instruction."""
    facts = [{"title": text["title"], "value": proposal.title}]
    if header.project:
        facts.insert(0, {"title": text["project"], "value": header.project})
    heading = {"type": "TextBlock", "weight": "Bolder", "size": "Small", "wrap": True}
    return {
        "type": "Container",
        "id": HANDOFF_ID,
        "isVisible": False,
        "spacing": "Medium",
        "items": [
            heading | {"text": text["pm_message"]},
            {
                "type": "TextBlock",
                "id": f"{HANDOFF_ID}.pm_message",
                "text": proposal.ticket_text(),
                "size": "Small",
                "wrap": True,
            },
            heading | {"text": text["ticket_draft"], "spacing": "Medium"},
            {"type": "FactSet", "id": f"{HANDOFF_ID}.ticket", "facts": facts},
        ],
    }


def _covered(
    proposal: Proposal, links: Mapping[str, str], text: Mapping[str, str]
) -> list[dict[str, Any]]:
    """A problem an existing ticket covers needs no decision, only a way to the detail."""
    detail = {"type": "Action.OpenUrl", "title": text["detail"], "url": links["detail"]}
    return [
        _recommendation(proposal, text),
        {"type": "ActionSet", "actions": [detail], "spacing": "Small"},
    ]


def _recommendation(proposal: Proposal, text: Mapping[str, str]) -> dict[str, Any]:
    heading = text.get(proposal.recommendation, proposal.recommendation)
    if proposal.recommendation == "existing_ticket" and proposal.existing_ticket:
        heading = f"{heading}: {proposal.existing_ticket}"
    return {
        "type": "TextBlock",
        "text": _unlisted(heading),
        "weight": "Bolder",
        "color": "Accent",
        "wrap": True,
        "spacing": "Medium",
    }


def _status(incident: sqlite3.Row, reach: Scope) -> str:
    if incident["resolved_at"]:
        return "status_resolved"
    if reach.recurs and reach.growing:
        return "status_recurs_grows"
    if reach.recurs:
        return "status_recurs"
    if reach.growing:
        return "status_grows"
    return "status_lasts"


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
    toggle = {"type": "Action.ToggleVisibility", "targetElements": [HANDOFF_ID]}
    return [*actions, toggle | {"title": text["handoff"]}]


def _cause(incident: sqlite3.Row) -> str:
    """The reviewed cause when a person corrected the diagnosis, else the diagnosis."""
    review = json.loads(incident["review"]) if incident["review"] else {}
    if review.get("verdict") in ("wrong", "partial"):
        return str(review["cause"])
    if not incident["diagnosis"]:
        return ""
    return Diagnosis(**json.loads(incident["diagnosis"])).likely_cause


def _link(title: str, url: str | None) -> str:
    title = _clip(title, TITLE_MAX_CHARS)
    if not url:
        return _unlisted(title)
    return f"[{title.translate(_LINK_TEXT)}]({url.translate(_LINK_URL)})"


def _unlisted(text: str) -> str:
    # Teams reads "3. foo" at the start of a text block as a numbered list; NBSP stops that.
    return _LIST_START.sub("\\1.\u00a0", text)


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _sentence(text: str) -> str:
    return _SENTENCE_END.split(text.strip(), maxsplit=1)[0]


def _today(moments: Sequence[str], now: datetime) -> int:
    day = now.astimezone().date()
    return sum(1 for moment in moments if datetime.fromisoformat(moment).astimezone().date() == day)
