"""Deterministic evidence collection: what a human would look at first after an alert.

The investigator model only ever sees this pack, so a diagnosis can be checked against it and
the same pack can be replayed against different models.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime
from string import Template
from typing import Literal

from .engine import with_offset
from .models import Series
from .rules import cloudwatch
from .sources.base import Telemetry

EvidenceKind = Literal["promql", "logql", "logql_top", "cloudwatch", "logs_insights", "ecs_events"]
STEP = 300


@dataclass(frozen=True)
class EvidenceQuery:
    """One thing to look at around an incident.

    `promql`, `logql` and `cloudwatch` give a timeline over the window (keep logql to one or
    two series), `logql_top` gives one total per series over the whole window, written as
    `[$window]`. `logs_insights` gives a timeline when it groups by `bin(...)` and totals
    otherwise. `ecs_events` lists deployments and service events of the ECS cluster named
    by the query. `$label` placeholders take the incident's labels, e.g. `shop="$shop"`.
    A query only runs for incidents of rules on its `source`.
    """

    name: str
    kind: EvidenceKind
    query: str
    limit: int = 8
    source: str = "default"
    log_groups: tuple[str, ...] = ()


@dataclass
class Section:
    name: str
    lines: list[str]


@dataclass
class EvidencePack:
    rule: str
    severity: str
    summary: str
    labels: dict[str, str]
    started_at: float
    window_start: float
    window_end: float
    sections: list[Section] = field(default_factory=list)

    def render(self) -> str:
        head = [
            "## Incident",
            f"rule: {self.rule} ({self.severity})",
            f"alert: {self.summary}",
            f"labels: {', '.join(f'{k}={v}' for k, v in self.labels.items()) or '-'}",
            f"started: {_clock(self.started_at, full=True)}",
            f"evidence window: {_clock(self.window_start)} - {_clock(self.window_end)}",
        ]
        body = [f"\n## {s.name}\n" + "\n".join(s.lines or ["(no data)"]) for s in self.sections]
        return "\n".join(head + body)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> EvidencePack:
        data = json.loads(text)
        data["sections"] = [Section(**s) for s in data.get("sections", [])]
        return cls(**data)


PrecedentFinder = Callable[[str], list[str]]


async def collect(
    telemetry: Telemetry,
    queries: Sequence[EvidenceQuery],
    rule: str,
    severity: str,
    summary: str,
    labels: Mapping[str, str],
    started_at: float,
    before: int = 1800,
    after: int = 600,
    precedents: PrecedentFinder | None = None,
    precedents_from: str | None = None,
    now: float | None = None,
) -> EvidencePack:
    now = now or time.time()
    window_end = min(started_at + after, now)
    window_start = started_at - before
    pack = EvidencePack(rule, severity, summary, dict(labels), started_at, window_start, window_end)
    for query in queries:
        text = Template(query.query).safe_substitute(labels)
        try:
            lines = await _section(telemetry, query, text, window_start, window_end, now)
        except Exception as error:
            lines = [f"(query failed: {type(error).__name__}: {str(error)[:150]})"]
        pack.sections.append(Section(query.name, lines))
    if precedents is not None:
        try:
            found = precedents(_search_text(pack, summary, precedents_from))
        except Exception as error:
            found = [f"(search failed: {type(error).__name__})"]
        pack.sections.append(Section("Similar past tickets", found))
    return pack


def _search_text(pack: EvidencePack, summary: str, section_name: str | None) -> str:
    """Seed the precedent search with the top error message when there is one."""
    section = next((s for s in pack.sections if s.name == section_name), None)
    if section is None or not section.lines or section.lines[0].startswith("("):
        return summary
    line = section.lines[0]
    return line.split("message=", 1)[1] if "message=" in line else line.strip()


async def _section(
    telemetry: Telemetry, query: EvidenceQuery, text: str, start: float, end: float, now: float
) -> list[str]:
    if query.kind == "promql":
        series = await telemetry.query_range(text, start, end, STEP)
        return _timeline(series, start, end, query.limit)
    if query.kind == "cloudwatch":
        series = await cloudwatch(telemetry).metrics(text, start, end, STEP)
        return _timeline(series, start, end, query.limit)
    if query.kind == "ecs_events":
        events = await cloudwatch(telemetry).service_events(text, start, end)
        return [f"{_clock(moment)}  {name}: {message}" for moment, name, message in events][
            -query.limit :
        ]
    if query.kind == "logs_insights":
        series = await cloudwatch(telemetry).log_query(query.log_groups, text, start, end)
        if "bin(" in text:
            return _timeline(series, start, end, query.limit)
        return _totals(series, query.limit)
    offset = int(now - end)
    window = int(end - start)
    if query.kind == "logql_top":
        text = text.replace("$window", f"{window}s")
        series = await telemetry.logs(with_offset(text, offset), "10s")
        return _totals(series, query.limit)
    series = await telemetry.logs(with_offset(text, offset), f"{max(1, window // 60)}m")
    shifted = [Series(s.labels, [(t - offset, v) for t, v in s.points]) for s in series]
    return _timeline(shifted, start, end, query.limit)


def _totals(series: Sequence[Series], limit: int) -> list[str]:
    top = sorted(series, key=lambda s: -s.last)[:limit]
    return [f"{s.last:>6.0f}x  {_labels(s.labels)}" for s in top]


def _timeline(series: Sequence[Series], start: float, end: float, limit: int) -> list[str]:
    """One row per series, one column per five minutes; '.' where there is no sample."""
    columns = [start + STEP * i for i in range(int((end - start) // STEP) + 1)]
    shown = list(series)[:limit]
    width = max([len("time"), *(len(_labels(s.labels) or "value") for s in shown)])
    lines = [f"{'time':<{width}} " + " ".join(f"{_clock(c):>6}" for c in columns)]
    for item in shown:
        cells = []
        for column in columns:
            near = [v for t, v in item.points if abs(t - column) <= STEP / 2]
            cells.append(f"{_number(max(near)):>6}" if near else f"{'.':>6}")
        lines.append(f"{_labels(item.labels) or 'value':<{width}} " + " ".join(cells))
    if len(series) > limit:
        lines.append(f"(+{len(series) - limit} more series)")
    return lines if len(lines) > 1 else []


def _labels(labels: Mapping[str, str]) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(labels.items()) if k != "__name__")


def _number(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return f"{value:.2f}"


def _clock(timestamp: float, full: bool = False) -> str:
    moment = datetime.fromtimestamp(timestamp).astimezone()
    return moment.strftime("%Y-%m-%d %H:%M %Z") if full else moment.strftime("%H:%M")


def labels_from_key(key: str) -> dict[str, str]:
    """Rebuild labels from a finding key such as `shop=a,job=node`."""
    pairs = (part.split("=", 1) for part in key.split(",") if "=" in part)
    return dict(pairs)
