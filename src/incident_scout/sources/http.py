from __future__ import annotations

import time
from types import TracebackType
from typing import Any

import httpx

from ..models import Alert, Series
from .base import SourceError, parse_alerts, parse_duration, parse_series


class HttpTelemetry:
    """Telemetry straight from the Prometheus (or VictoriaMetrics), Loki and Alertmanager APIs."""

    def __init__(
        self,
        prometheus_url: str | None = None,
        loki_url: str | None = None,
        alertmanager_url: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.prometheus_url = (prometheus_url or "").rstrip("/")
        self.loki_url = (loki_url or "").rstrip("/")
        self.alertmanager_url = (alertmanager_url or "").rstrip("/")
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport)

    async def __aenter__(self) -> HttpTelemetry:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        params: dict[str, Any] = {"query": promql}
        if at is not None:
            params["time"] = at
        return parse_series(await self._get(self.prometheus_url, "/api/v1/query", params))

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        params = {"query": promql, "start": start, "end": end, "step": step}
        return parse_series(await self._get(self.prometheus_url, "/api/v1/query_range", params))

    async def logs(self, logql: str, since: str) -> list[Series]:
        end = time.time()
        params = {
            "query": logql,
            "start": int((end - parse_duration(since)) * 1e9),
            "end": int(end * 1e9),
        }
        return parse_series(await self._get(self.loki_url, "/loki/api/v1/query_range", params))

    async def alerts(self) -> list[Alert]:
        params = {"active": "true", "silenced": "false", "inhibited": "false"}
        return parse_alerts(await self._get(self.alertmanager_url, "/api/v2/alerts", params))

    async def _get(self, base: str, path: str, params: dict[str, Any]) -> Any:
        if not base:
            raise SourceError(f"No URL configured for {path}")
        try:
            response = await self._client.get(base + path, params=params)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise SourceError(f"{base}{path}: {error}") from error
        return response.json()
