from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import cast

from .models import Event, Finding, Severity
from .rules import Rule, capped, digest_summary
from .sources.base import parse_duration
from .state import Store, iso

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
        rule = rules.get(finding.rule)
        incident = store.open_incident(fingerprint)
        if incident is not None:
            known = _problems(incident)
            problems = _gathered(known, finding, now)
            store.touch(incident["id"], finding, now, _summary(rule, finding, problems), problems)
            fresh = [problem for problem in problems if problem not in known]
            if fresh and incident["announced_at"]:
                events.append(_grew(incident, finding, fresh))
            continue
        streak, first_seen = store.bump_pending(finding, now)
        if rule is not None and streak < rule.for_runs:
            continue
        problems = _gathered({}, finding, now)
        held = bool(rule and rule.hold)
        summary = _summary(rule, finding, problems)
        incident_id = store.open(finding, now, first_seen, held, summary, problems)
        if not held:
            events.append(_opened(finding, incident_id, summary))

    evaluated = [name for name in result.rules if name not in result.errors]
    store.drop_pending(current, evaluated)

    for incident in store.open_incidents():
        rule = rules.get(incident["rule"])
        if incident["announced_at"] or rule is None or not _held_long_enough(rule, incident, now):
            continue
        store.announce(incident["id"], now)
        events.append(_announced(incident))

    for incident in store.open_incidents():
        if incident["fingerprint"] in current or incident["rule"] in result.errors:
            continue
        rule = rules.get(incident["rule"])
        if rule is not None and not incident["announced_at"]:
            continue
        limit = (rule.resolve_after if rule else None) or resolve_after
        if rule is not None and store.miss(incident["id"]) < limit:
            continue
        store.resolve(incident["id"], now)
        if incident["announced_at"]:
            events.append(_resolved(incident, now))
    return events


def _problems(incident: sqlite3.Row) -> dict[str, dict[str, str]]:
    return cast(dict[str, dict[str, str]], json.loads(incident["problems"] or "{}"))


def _gathered(
    known: Mapping[str, Mapping[str, str]], finding: Finding, now: datetime
) -> dict[str, dict[str, str]]:
    """Every problem an incident has met, each with its records and when they were first seen."""
    merged = {problem: dict(records) for problem, records in known.items()}
    for problem, records in finding.problems.items():
        hit = merged.setdefault(problem, {})
        for record in records:
            hit.setdefault(record, iso(now))
    return merged


def _summary(rule: Rule | None, finding: Finding, problems: Mapping[str, Mapping[str, str]]) -> str:
    if rule is None or not problems:
        return finding.summary
    return digest_summary(rule, finding, {problem: list(hit) for problem, hit in problems.items()})


def _held_long_enough(rule: Rule, incident: sqlite3.Row, now: datetime) -> bool:
    hold = timedelta(seconds=parse_duration(rule.hold)) if rule.hold else timedelta(0)
    return now - datetime.fromisoformat(incident["opened_at"]) >= hold


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


def _opened(finding: Finding, incident_id: int, summary: str) -> Event:
    return Event(
        "opened",
        finding.severity,
        f"{ICONS.get(finding.severity, '')} {finding.rule}".strip(),
        summary,
        group=finding.fingerprint,
        url=finding.url,
        incident_id=incident_id,
    )


def _announced(incident: sqlite3.Row) -> Event:
    """A held incident is told once its hold is over, with all it gathered meanwhile."""
    severity = cast(Severity, incident["severity"])
    return Event(
        "opened",
        severity,
        f"{ICONS.get(severity, '')} {incident['rule']}".strip(),
        incident["summary"],
        group=incident["fingerprint"],
        url=incident["url"],
        incident_id=incident["id"],
    )


def _grew(incident: sqlite3.Row, finding: Finding, fresh: Sequence[str]) -> Event:
    return Event(
        "grew",
        finding.severity,
        f"🆕 {incident['rule']} #{incident['id']}",
        f"new: {capped(list(fresh))}",
        group=incident["fingerprint"],
        url=finding.url,
        incident_id=incident["id"],
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
        incident_id=incident["id"],
    )


def _duration(seconds: float) -> str:
    minutes = max(1, round(seconds / 60))
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _local(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp).astimezone().strftime("%d.%m. %H:%M")
