from __future__ import annotations

import math
import re
from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass

from .models import Finding, Series
from .rules import Rule, evaluate, series_key
from .sources.base import Telemetry
from .tracker import CheckResult

BACKTEST_CHUNK = 86400
LOGS_CHUNK = 12 * 3600
LOKI_DEFAULT_POINTS = 250  # Loki picks step = range / 250 when the caller cannot set one
_RANGE_SELECTOR = re.compile(r"\[(\d+[smhdw])\]")


async def run_check(
    connection: AbstractAsyncContextManager[Telemetry], rules: Sequence[Rule]
) -> CheckResult:
    """Evaluate every rule; a failing rule is recorded, never fatal for the others."""
    names = [rule.name for rule in rules]
    try:
        async with connection as telemetry:
            findings: list[Finding] = []
            errors: dict[str, str] = {}
            for rule in rules:
                try:
                    findings += await evaluate(rule, telemetry)
                except Exception as error:
                    errors[rule.name] = describe(error)
            return CheckResult(findings, names, errors)
    except Exception as error:
        return CheckResult([], names, dict.fromkeys(names, describe(error)))


def describe(error: BaseException) -> str:
    """Name the innermost cause; transport errors arrive wrapped in exception groups."""
    while isinstance(error, BaseExceptionGroup) and error.exceptions:
        error = error.exceptions[0]
    return f"{type(error).__name__}: {error}".strip().rstrip(":")


@dataclass(frozen=True)
class Episode:
    rule: str
    key: str
    start: float
    end: float
    peak: float
    points: int

    @property
    def minutes(self) -> float:
        return (self.end - self.start) / 60


async def backtest(
    rule: Rule, telemetry: Telemetry, start: float, end: float, step: int
) -> list[Episode]:
    """Replay a rule over history and group the moments it fired into episodes."""
    if rule.kind == "alertmanager":
        raise ValueError("Alertmanager rules have no history; replay ALERTS{} as a promql rule")
    series: list[Series] = []
    if rule.kind == "logql":
        series, step = await _replay_logs(rule.query, telemetry, start, end, step)
    if rule.kind == "promql":
        chunk_start = start
        while chunk_start < end:
            chunk_end = min(end, chunk_start + BACKTEST_CHUNK)
            series += await telemetry.query_range(rule.query, chunk_start, chunk_end, step)
            chunk_start = chunk_end
    return episodes(rule, series, step)


async def _replay_logs(
    query: str, telemetry: Telemetry, start: float, end: float, step: int
) -> tuple[list[Series], int]:
    """Log queries only look back from now, so older chunks are reached with `offset`.

    Chunks stay short because the server picks the step from the range; a long range would
    step over short spikes entirely.
    """
    series: list[Series] = []
    cursor = end
    while cursor > start:
        span = min(LOGS_CHUNK, cursor - start)
        offset = int(end - cursor)
        hours = math.ceil(span / 3600)
        step = max(step, hours * 3600 // LOKI_DEFAULT_POINTS)
        for item in await telemetry.logs(with_offset(query, offset), f"{hours}h"):
            points = [(t - offset, v) for t, v in item.points if start <= t - offset <= cursor]
            if points:
                series.append(Series(item.labels, points))
        cursor -= span
    return series, step


def with_offset(query: str, seconds: int) -> str:
    """Shift every range selector of a query back in time."""
    if seconds <= 0:
        return query
    return _RANGE_SELECTOR.sub(lambda m: f"[{m.group(1)}] offset {seconds}s", query)


def episodes(rule: Rule, series: Sequence[Series], step: int) -> list[Episode]:
    by_key: dict[str, list[tuple[float, float]]] = {}
    for item in series:
        by_key.setdefault(series_key(rule, item.labels), []).extend(item.points)
    result = []
    for key, raw in by_key.items():
        points = sorted(set(raw))
        if not points:
            continue
        group = [points[0]]
        for point in points[1:]:
            if point[0] - group[-1][0] > 2 * step:
                result.append(_episode(rule.name, key, group))
                group = []
            group.append(point)
        result.append(_episode(rule.name, key, group))
    return sorted(result, key=lambda episode: episode.start)


def _episode(rule: str, key: str, points: list[tuple[float, float]]) -> Episode:
    return Episode(rule, key, points[0][0], points[-1][0], max(v for _, v in points), len(points))
