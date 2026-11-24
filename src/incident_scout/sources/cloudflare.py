from __future__ import annotations

import re
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

import httpx

from ..models import Alert, Series
from .base import SourceError

URL = "https://api.cloudflare.com/client/v4/graphql"
GROUPS = 50
_DIMENSION = re.compile(r"^[A-Za-z_]\w*$")
_QUERY = """
query($zone: String!, $filter: ZoneHttpRequestsAdaptiveGroupsFilter_InputObject!,
      $limit: uint64!) {
  viewer {
    zones(filter: {zoneTag: $zone}) {
      httpRequestsAdaptiveGroups(limit: $limit, filter: $filter, orderBy: [count_DESC]) {
        count%s
      }
    }
  }
}
"""


class CloudflareTelemetry:
    """Requests of one Cloudflare zone from the GraphQL Analytics API, e.g. partner bots the
    WAF challenged. Adaptive analytics are sampled, so counts are estimates."""

    def __init__(
        self,
        zone: str,
        token: str,
        url: str = URL,
        timeout: float = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.zone = zone
        self.url = url
        headers = {"Authorization": f"Bearer {token}"}
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport)

    async def __aenter__(self) -> CloudflareTelemetry:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def count(
        self,
        query: dict[str, Any],
        since_seconds: int,
        now: float,
        group_by: tuple[str, ...] = (),
    ) -> list[Series]:
        """Requests matching the `query` filter in the last `since_seconds`, in total or per
        combination of the `group_by` dimensions."""
        for name in group_by:
            if not _DIMENSION.match(name):
                raise SourceError(f"Invalid Cloudflare dimension {name!r}")
        window = {"datetime_geq": _iso(now - since_seconds), "datetime_lt": _iso(now)}
        dimensions = f" dimensions {{ {' '.join(group_by)} }}" if group_by else ""
        variables = {"zone": self.zone, "filter": {"AND": [query, window]}, "limit": GROUPS}
        groups = await self._groups(_QUERY % dimensions, variables)
        if not group_by:
            return [Series({}, [(now, float(sum(int(g.get("count", 0)) for g in groups)))])]
        return [
            Series(
                {name: _label(group.get("dimensions", {}).get(name)) for name in group_by},
                [(now, float(group.get("count", 0)))],
            )
            for group in groups
        ]

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        raise _unsupported("promql")

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        raise _unsupported("promql")

    async def logs(self, logql: str, since: str) -> list[Series]:
        raise _unsupported("logql")

    async def alerts(self) -> list[Alert]:
        raise _unsupported("alertmanager")

    async def _groups(self, query: str, variables: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            response = await self._client.post(
                self.url, json={"query": query, "variables": variables}
            )
        except httpx.HTTPError as error:
            raise SourceError(f"{self.url}: {error}") from error
        try:
            payload = response.json()
        except ValueError as error:
            raise SourceError(f"{self.url}: HTTP {response.status_code}, not JSON") from error
        if not isinstance(payload, dict):
            raise SourceError(f"{self.url}: HTTP {response.status_code}, unexpected reply")
        errors = payload.get("errors") or []
        if errors or response.is_error:
            reason = "; ".join(str(e.get("message", e)) for e in errors if isinstance(e, dict))
            raise SourceError(f"{self.url}: HTTP {response.status_code}: {reason or 'error'}")
        zones = ((payload.get("data") or {}).get("viewer") or {}).get("zones") or []
        if not zones:
            raise SourceError(f"Zone {self.zone} not found, or the token cannot read it")
        return list(zones[0].get("httpRequestsAdaptiveGroups") or [])


def _iso(moment: float) -> str:
    return datetime.fromtimestamp(int(moment), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _label(value: Any) -> str:
    return "" if value is None else str(value)


def _unsupported(kind: str) -> SourceError:
    return SourceError(f"A cloudflare source has no {kind}; use cloudflare or tls rules")
