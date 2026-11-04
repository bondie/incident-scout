from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import TypeVar

import pytest

from incident_scout.models import Alert, Series
from incident_scout.state import Store

T = TypeVar("T")
T0 = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def minutes(n: float) -> datetime:
    return T0 + timedelta(minutes=n)


class FakeTelemetry:
    """Answers queries from dictionaries; an Exception value makes that query fail."""

    def __init__(
        self,
        metrics: dict[str, list[Series] | Exception] | None = None,
        logs: dict[str, list[Series] | Exception] | None = None,
        alerts: list[Alert] | Exception | None = None,
        ranges: dict[str, list[Series]] | None = None,
    ) -> None:
        self.metrics = metrics or {}
        self.log_results = logs or {}
        self.alert_results = alerts if alerts is not None else []
        self.ranges = ranges or {}
        self.log_calls: list[tuple[str, str]] = []
        self.range_calls: list[tuple[str, float, float, int]] = []

    async def __aenter__(self) -> FakeTelemetry:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        return _answer(self.metrics.get(promql, []))

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        self.range_calls.append((promql, start, end, step))
        return [
            Series(s.labels, [p for p in s.points if start <= p[0] < end])
            for s in self.ranges.get(promql, [])
        ]

    async def logs(self, logql: str, since: str) -> list[Series]:
        self.log_calls.append((logql, since))
        return _answer(self.log_results.get(logql, []))

    async def alerts(self) -> list[Alert]:
        return _answer(self.alert_results)


def _answer(value: T | Exception) -> T:
    if isinstance(value, Exception):
        raise value
    return value


def series(value: float, **labels: str) -> Series:
    return Series(dict(labels), [(T0.timestamp(), value)])


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    store = Store(tmp_path / "state.db")
    yield store
    store.close()
