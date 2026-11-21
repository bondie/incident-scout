from __future__ import annotations

import json
import re
from types import TracebackType
from typing import Any

import httpx

from ..models import Alert, Series
from .base import SourceError

BUCKETS = 50
_NOT_A_LABEL = re.compile(r"\W+")


class ElasticsearchTelemetry:
    """Counts of matching documents in an Elasticsearch index, e.g. error logs per node."""

    def __init__(
        self,
        url: str,
        index: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.index = index
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout, transport=transport)

    async def __aenter__(self) -> ElasticsearchTelemetry:
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
        index: str | None,
        query: dict[str, Any],
        since_seconds: int,
        now: float,
        group_by: str | None = None,
        time_field: str = "timestamp",
    ) -> list[Series]:
        """Documents matching `query` in the last `since_seconds`, in total or per `group_by`."""
        target = index or self.index
        if not target:
            raise SourceError("An elasticsearch rule needs an index, on the rule or its source")
        window = {
            "gte": int((now - since_seconds) * 1000),
            "lte": int(now * 1000),
            "format": "epoch_millis",
        }
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": True,
            "query": {"bool": {"filter": [query, {"range": {time_field: window}}]}},
        }
        if group_by:
            body["aggs"] = {"groups": {"terms": {"field": group_by, "size": BUCKETS}}}
        payload = await self._search(target, body)
        if not group_by:
            return [Series({}, [(now, float(_total(payload)))])]
        label = label_name(group_by)
        buckets = ((payload.get("aggregations") or {}).get("groups") or {}).get("buckets") or []
        return [
            Series({label: str(bucket["key"])}, [(now, float(bucket["doc_count"]))])
            for bucket in buckets
        ]

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        raise _unsupported("promql")

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        raise _unsupported("promql")

    async def logs(self, logql: str, since: str) -> list[Series]:
        raise _unsupported("logql")

    async def alerts(self) -> list[Alert]:
        raise _unsupported("alertmanager")

    async def _search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.url}/{index}/_search"
        try:
            response = await self._client.post(url, json=body)
        except httpx.HTTPError as error:
            raise SourceError(f"{url}: {error}") from error
        try:
            payload = response.json()
        except ValueError as error:
            raise SourceError(f"{url}: HTTP {response.status_code}, not JSON") from error
        if response.is_error or not isinstance(payload, dict):
            raise SourceError(f"{url}: HTTP {response.status_code}: {_reason(payload)}")
        shards = payload.get("_shards") or {}
        if payload.get("timed_out") or shards.get("failed"):
            raise SourceError(
                f"{url}: partial result, so the count is too low: {_partial(payload)}"
            )
        return payload


def label_name(field: str) -> str:
    """`node.keyword` becomes `node`, so it can be a `{node}` placeholder in summaries."""
    return _NOT_A_LABEL.sub("_", field.removesuffix(".keyword")).strip("_") or "group"


def _total(payload: dict[str, Any]) -> int:
    total = (payload.get("hits") or {}).get("total")
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total or 0)


def _reason(payload: Any) -> str:
    """The innermost reason ES gives, e.g. why a terms aggregation on a text field failed."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return json.dumps(payload)[:300]
    causes = error.get("root_cause") or []
    cause = causes[0] if causes and isinstance(causes[0], dict) else error
    caused_by = error.get("caused_by") or {}
    reasons = dict.fromkeys(
        str(item.get("reason")) for item in (cause, caused_by) if item.get("reason")
    )
    return "; ".join(reasons) or str(error.get("type", "unknown error"))


def _partial(payload: dict[str, Any]) -> str:
    shards = payload.get("_shards") or {}
    if not shards.get("failed"):
        return "the search timed out"
    failures = shards.get("failures") or [{}]
    reason = (failures[0].get("reason") or {}).get("reason", "")
    return f"{shards['failed']} of {shards.get('total', '?')} shards failed {reason}".strip()


def _unsupported(kind: str) -> SourceError:
    return SourceError(f"An elasticsearch source has no {kind}; use elasticsearch or tls rules")
