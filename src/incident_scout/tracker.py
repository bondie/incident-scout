from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from .models import Event, Finding, Severity
from .rules import Rule
from .state import Store

ICONS: dict[str, str] = {"critical": "🔴", "warning": "🟠", "info": "🔵"}


@dataclass(frozen=True)
class CheckResult:
    findings: list[Finding]
    rules: Sequence[str]
    errors: Mapping[str, str] = field(default_factory=dict)

    @property
    def blind(self) -> bool:
        return bool(self.rules) and set(self.errors) >= set(self.rules)


def process(
    store: Store,
    result: CheckResult,
    rules: Mapping[str, Rule],
    now: datetime,
    blind_after: int = 3,
    resolve_after: int = 2,
) -> list[Event]:
    """Turn one check into state changes; only changes produce events, so nothing repeats."""
    if result.blind:
        return _blind(store, result, now, blind_after)

    events: list[Event] = []
    blind_since = store.run_succeeded(now)
    if blind_since:
        events.append(
            Event(
                "restored",
                "info",
                "👁 Monitoring sees again",
                f"Telemetry is reachable again (blind since {_local(blind_since)}).",
                group="health",
            )
        )
    events += _rule_health(store, result, blind_after)

    current = {finding.fingerprint: finding for finding in result.findings}
    for fingerprint, finding in current.items():
        incident = store.open_incident(fingerprint)
        if incident is not None:
            store.touch(incident["id"], finding, now)
            continue
        streak, first_seen = store.bump_pending(finding, now)
        rule = rules.get(finding.rule)
        if rule is not None and streak < rule.for_runs:
            continue
        store.open(finding, now, first_seen)
        events.append(_opened(finding))

    evaluated = [name for name in result.rules if name not in result.errors]
    store.drop_pending(current, evaluated)

    for incident in store.open_incidents():
        if incident["fingerprint"] in current or incident["rule"] in result.errors:
            continue
        if incident["rule"] in rules and store.miss(incident["id"]) < resolve_after:
            continue
        store.resolve(incident["id"], now)
        events.append(_resolved(incident, now))
    return events


def _blind(store: Store, result: CheckResult, now: datetime, blind_after: int) -> list[Event]:
    error = next(iter(result.errors.values()), "no rules could be evaluated")
    failed_runs = store.run_failed(now, error)
    if failed_runs != blind_after:
        return []
    store.mark_blind(now)
    return [
        Event(
            "blind",
            "warning",
            "👁 Monitoring is blind",
            f"Telemetry has been unreachable for {failed_runs} checks: {error[:200]}. "
            "Open incidents are kept until it is back. VPN?",
            group="health",
        )
    ]


def _rule_health(store: Store, result: CheckResult, threshold: int) -> list[Event]:
    events = []
    for rule in result.rules:
        error = result.errors.get(rule)
        if error is None:
            if store.rule_succeeded(rule) >= threshold:
                events.append(
                    Event("rule_recovered", "info", f"✅ Rule {rule} works again", "", group=rule)
                )
            continue
        if store.rule_failed(rule, error) == threshold:
            events.append(
                Event(
                    "rule_failing",
                    "warning",
                    f"⚠️ Rule {rule} keeps failing",
                    error[:300],
                    group=rule,
                )
            )
    return events


def _opened(finding: Finding) -> Event:
    return Event(
        "opened",
        finding.severity,
        f"{ICONS.get(finding.severity, '')} {finding.rule}".strip(),
        finding.summary,
        group=finding.fingerprint,
        url=finding.url,
    )


def _resolved(incident: sqlite3.Row, now: datetime) -> Event:
    lasted = now - datetime.fromisoformat(incident["opened_at"])
    severity: Severity = "info"
    return Event(
        "resolved",
        severity,
        f"✅ {incident['rule']} resolved",
        f"{incident['summary']} (lasted {_duration(lasted.total_seconds())})",
        group=incident["fingerprint"],
        url=incident["url"],
    )


def _duration(seconds: float) -> str:
    minutes = max(1, round(seconds / 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _local(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp).astimezone().strftime("%d.%m. %H:%M")
