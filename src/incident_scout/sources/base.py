from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Protocol

from ..models import Alert, Series

_DURATION = re.compile(r"^(\d+)([smhdw])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class SourceError(RuntimeError):
    pass


class Telemetry(Protocol):
    async def query(self, promql: str, at: float | None = None) -> list[Series]: ...

    async def query_range(
        self, promql: str, start: float, end: float, step: int
    ) -> list[Series]: ...

    async def logs(self, logql: str, since: str) -> list[Series]: ...

    async def alerts(self) -> list[Alert]: ...


def parse_duration(text: str) -> int:
    match = _DURATION.match(text.strip())
    if not match:
        raise ValueError(f"Invalid duration {text!r}, expected e.g. 30s, 5m, 2h, 7d")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def parse_series(payload: Mapping[str, Any]) -> list[Series]:
    """Read a Prometheus or Loki query response (vector or matrix)."""
    if payload.get("status") not in (None, "success"):
        raise SourceError(f"Query failed: {payload.get('error') or payload.get('status')}")
    data = payload.get("data") or {}
    kind = data.get("resultType")
    if kind == "vector":
        return [
            Series(dict(item["metric"]), [(float(item["value"][0]), float(item["value"][1]))])
            for item in data.get("result", [])
        ]
    if kind == "matrix":
        return [
            Series(dict(item["metric"]), [(float(t), float(v)) for t, v in item["values"]])
            for item in data.get("result", [])
            if item.get("values")
        ]
    if kind == "scalar":
        timestamp, value = data["result"]
        return [Series({}, [(float(timestamp), float(value))])]
    raise SourceError(f"Unsupported result type {kind!r}; log stream queries need a metric query")


def parse_alerts(payload: Any) -> list[Alert]:
    """Read Alertmanager API v2 alerts, or the `data.alerts` shape of the v1 and Prometheus APIs."""
    items = payload
    if isinstance(payload, Mapping):
        items = (payload.get("data") or {}).get("alerts", payload.get("alerts", []))
    return [
        Alert(
            labels=dict(item.get("labels") or {}),
            annotations=dict(item.get("annotations") or {}),
            starts_at=item.get("startsAt") or item.get("activeAt"),
            url=item.get("generatorURL"),
        )
        for item in items or []
    ]
