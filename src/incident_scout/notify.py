from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from datetime import datetime
from typing import Any, Protocol

import httpx

from . import teams
from .models import Event

Runner = Callable[..., Any]
Poster = Callable[[str, Mapping[str, Any]], None]
TEAMS_KINDS: tuple[str, ...] = ("opened", "resolved")


class Notifier(Protocol):
    def send(self, event: Event) -> None: ...


class ConsoleNotifier:
    def send(self, event: Event) -> None:
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{stamp} {event.kind:<14} {event.title} | {event.message}", flush=True)


class DesktopNotifier:
    """macOS Notification Center through terminal-notifier, or osascript when it is missing."""

    def __init__(
        self,
        runner: Runner = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self.runner = runner
        self.which = which

    def send(self, event: Event) -> None:
        tool = self.which("terminal-notifier")
        if tool is None:
            script = (
                f"display notification {_quote(event.message)} with title {_quote(event.title)}"
            )
            self.runner(["/usr/bin/osascript", "-e", script], check=False, timeout=15)
            return
        command = [
            tool,
            "-title",
            event.title,
            "-message",
            event.message or " ",
            "-group",
            event.group,
        ]
        if event.url:
            command += ["-open", event.url]
        if event.kind == "opened" and event.severity == "critical":
            command += ["-sound", "Basso"]
        self.runner(command, check=False, timeout=15, capture_output=True)


class NtfyNotifier:
    """Push notifications through an ntfy server (https://ntfy.sh or self-hosted)."""

    def __init__(
        self,
        url: str,
        topic: str,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.topic = topic
        self.token = token
        self.transport = transport

    def send(self, event: Event) -> None:
        priority = 3
        if event.kind == "opened":
            priority = {"critical": 5, "warning": 4}.get(event.severity, 3)
        body: dict[str, Any] = {
            "topic": self.topic,
            "title": event.title,
            "message": event.message or event.title,
            "priority": priority,
        }
        if event.url:
            body["click"] = event.url
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        with httpx.Client(transport=self.transport, timeout=10) as client:
            client.post(self.url, json=body, headers=headers).raise_for_status()


class TeamsNotifier:
    """Incident cards in a Teams channel. It takes a whole check at once, so a diagnosis made
    in the same check joins the card of the incident it explains instead of arriving alone."""

    def __init__(
        self,
        url: str,
        incident: Callable[[int], sqlite3.Row | None],
        header: Callable[[sqlite3.Row], teams.Header],
        language: str = "English",
        kinds: Collection[str] = TEAMS_KINDS,
        poster: Poster | None = None,
    ) -> None:
        self.url = url
        self.incident = incident
        self.header = header
        self.language = language
        self.kinds = kinds
        self.poster = poster

    def post(self, events: Sequence[Event], max_events: int = 5) -> None:
        diagnosed = {event.incident_id for event in events if event.kind == "diagnosed"}
        wanted = [e for e in events if e.kind in self.kinds and e.kind != "diagnosed"]
        send = self.poster or teams.post
        for event in limited(wanted, max_events):
            try:
                send(self.url, self.card(event, event.incident_id in diagnosed))
            except Exception as error:  # Teams being down must not break the check
                print(f"notifier {type(self).__name__} failed: {error}", file=sys.stderr)

    def card(self, event: Event, diagnosed: bool = False) -> dict[str, Any]:
        row = self.incident(event.incident_id) if event.incident_id is not None else None
        if row is None:
            return teams.incident_card(
                event, None, teams.Header("", event.title), None, self.language
            )
        diagnosis = teams.stored_diagnosis(row) if diagnosed else None
        return teams.incident_card(event, row, self.header(row), diagnosis, self.language)


def limited(events: Sequence[Event], max_events: int) -> list[Event]:
    """A storm is cut down to one summary event."""
    batch = list(events)
    if len(batch) <= max_events:
        return batch
    hidden = len(batch) - (max_events - 1)
    return [
        *batch[: max_events - 1],
        Event(
            "opened",
            "warning",
            f"… and {hidden} more",
            "Run `scout status` for the full list.",
            group="overflow",
        ),
    ]


def dispatch(notifiers: Sequence[Notifier], events: Sequence[Event], max_events: int = 5) -> None:
    """Send events to every notifier; a storm is cut down to one summary notification."""
    for event in limited(events, max_events):
        for notifier in notifiers:
            try:
                notifier.send(event)
            except Exception as error:  # a broken channel must not stop the others
                print(f"notifier {type(notifier).__name__} failed: {error}", file=sys.stderr)


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
