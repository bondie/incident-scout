from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from incident_scout.sources.base import SourceError, parse_alerts, parse_duration, parse_series
from incident_scout.sources.http import HttpTelemetry
from incident_scout.sources.mcp import McpTelemetry

VECTOR = {
    "status": "success",
    "data": {"resultType": "vector", "result": [{"metric": {"shop": "a"}, "value": [10, "1.5"]}]},
}
MATRIX = {
    "status": "success",
    "data": {
        "resultType": "matrix",
        "result": [
            {"metric": {"shop": "a"}, "values": [[1, "2"], [2, "55"]]},
            {"metric": {"shop": "b"}, "values": []},
        ],
    },
}


def test_parse_vector_matrix_and_scalar():
    (one,) = parse_series(VECTOR)
    assert (one.labels, one.points) == ({"shop": "a"}, [(10.0, 1.5)])
    (two,) = parse_series(MATRIX)
    assert two.last == 55
    (three,) = parse_series({"data": {"resultType": "scalar", "result": [5, "7"]}})
    assert three.last == 7


def test_parse_rejects_failures_and_log_streams():
    with pytest.raises(SourceError, match="bad query"):
        parse_series({"status": "error", "error": "bad query"})
    with pytest.raises(SourceError, match="metric query"):
        parse_series({"status": "success", "data": {"resultType": "streams", "result": []}})


def test_parse_alerts_v2_list_and_wrapped_shapes():
    v2 = [{"labels": {"alertname": "A"}, "annotations": {"summary": "s"}, "startsAt": "t"}]
    assert parse_alerts(v2)[0].annotations == {"summary": "s"}
    wrapped = {"data": {"alerts": [{"labels": {"alertname": "B"}, "activeAt": "t"}]}}
    assert parse_alerts(wrapped)[0].labels == {"alertname": "B"}
    assert parse_alerts([]) == []


def test_parse_duration():
    assert parse_duration("90s") == 90
    assert parse_duration("5m") == 300
    assert parse_duration("7d") == 604800
    with pytest.raises(ValueError, match="Invalid duration"):
        parse_duration("soon")


@dataclass
class Text:
    text: str


@dataclass
class ToolResult:
    content: list[Text]
    is_error: bool = False


class FakeSession:
    def __init__(self, replies: dict[str, Any]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> ToolResult:
        self.calls.append((name, arguments or {}))
        reply = self.replies[name]
        if isinstance(reply, ToolResult):
            return reply
        return ToolResult([Text(json.dumps(reply))])


def test_mcp_telemetry_maps_calls_to_tools():
    session = FakeSession(
        {"vm_query": VECTOR, "vm_query_range": MATRIX, "loki_query": MATRIX, "alerts_active": []}
    )

    async def scenario() -> None:
        async with McpTelemetry("https://mcp.example", session=session) as telemetry:
            assert (await telemetry.query("up", at=100))[0].last == 1.5
            assert (await telemetry.query_range("up", 0, 60, 30))[0].last == 55
            assert (await telemetry.logs("{job='app'}", "5m"))[0].last == 55
            assert await telemetry.alerts() == []

    asyncio.run(scenario())
    assert session.calls[0] == ("vm_query", {"query": "up", "time": "100"})
    assert session.calls[1][1]["step"] == "30s"
    assert session.calls[2] == ("loki_query", {"query": "{job='app'}", "since": "5m"})


def test_mcp_telemetry_reports_tool_errors_and_truncated_json():
    session = FakeSession(
        {
            "vm_query": ToolResult([Text("permission denied")], is_error=True),
            "loki_query": ToolResult([Text('{"status": "success", "data": {"res')]),
        }
    )

    async def scenario() -> None:
        telemetry = McpTelemetry("https://mcp.example", session=session)
        with pytest.raises(SourceError, match="permission denied"):
            await telemetry.query("up")
        with pytest.raises(SourceError, match="truncate"):
            await telemetry.logs("x", "1m")

    asyncio.run(scenario())


def test_mcp_telemetry_requires_an_open_session():
    with pytest.raises(SourceError, match="not open"):
        asyncio.run(McpTelemetry("https://mcp.example").query("up"))


def test_http_telemetry_calls_the_standard_apis():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/api/v2/alerts":
            return httpx.Response(200, json=[{"labels": {"alertname": "A"}}])
        if request.url.path.startswith("/loki"):
            return httpx.Response(200, json=MATRIX)
        return httpx.Response(200, json=VECTOR)

    async def scenario() -> None:
        async with HttpTelemetry(
            prometheus_url="http://prom/",
            loki_url="http://loki",
            alertmanager_url="http://am",
            transport=httpx.MockTransport(handler),
        ) as telemetry:
            assert (await telemetry.query("up", at=5))[0].last == 1.5
            assert (await telemetry.query_range("up", 0, 60, 30))[0].last == 1.5
            assert (await telemetry.logs("x", "5m"))[0].last == 55
            assert (await telemetry.alerts())[0].labels == {"alertname": "A"}

    asyncio.run(scenario())
    assert [r.url.path for r in seen] == [
        "/api/v1/query",
        "/api/v1/query_range",
        "/loki/api/v1/query_range",
        "/api/v2/alerts",
    ]
    assert seen[3].url.params["silenced"] == "false"


def test_http_telemetry_errors_become_source_errors():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def scenario() -> None:
        async with HttpTelemetry(
            prometheus_url="http://prom", transport=httpx.MockTransport(handler)
        ) as telemetry:
            with pytest.raises(SourceError, match="503"):
                await telemetry.query("up")
            with pytest.raises(SourceError, match="No URL"):
                await telemetry.alerts()

    asyncio.run(scenario())
