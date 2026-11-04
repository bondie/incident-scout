from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any, Protocol

import httpx

from .models import Event

Runner = Callable[..., Any]


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


def dispatch(notifiers: Sequence[Notifier], events: Sequence[Event], max_events: int = 5) -> None:
    """Send events to every notifier; a storm is cut down to one summary notification."""
    batch = list(events)
    if len(batch) > max_events:
        hidden = len(batch) - (max_events - 1)
        batch = [
            *batch[: max_events - 1],
            Event(
                "opened",
                "warning",
                f"… and {hidden} more",
                "Run `scout status` for the full list.",
                group="overflow",
            ),
        ]
    for event in batch:
        for notifier in notifiers:
            try:
                notifier.send(event)
            except Exception as error:  # a broken channel must not stop the others
                print(f"notifier {type(notifier).__name__} failed: {error}", file=sys.stderr)


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
