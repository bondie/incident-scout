from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Protocol

from ..models import Alert, Series
from .base import SourceError, parse_alerts, parse_series


@dataclass(frozen=True)
class McpTools:
    """Names of the server's tools. Arguments follow the common observability-server shape:
    query(query, time?), query_range(query, start, end, step), logs(query, since), alerts()."""

    query: str = "vm_query"
    query_range: str = "vm_query_range"
    logs: str = "loki_query"
    alerts: str = "alerts_active"


class ToolSession(Protocol):
    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
    ) -> Any: ...


class McpTelemetry:
    """Telemetry through an MCP server that wraps Prometheus, Loki and Alertmanager."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        tools: McpTools | None = None,
        timeout: float = 60,
        session: ToolSession | None = None,
    ) -> None:
        self.url = url
        self.headers = headers or {}
        self.tools = tools or McpTools()
        self.timeout = timeout
        self._session = session
        self._stack: AsyncExitStack | None = None

    async def __aenter__(self) -> McpTelemetry:
        if self._session is not None:
            return self
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from mcp.shared._httpx_utils import create_mcp_http_client

        stack = AsyncExitStack()
        try:
            http = await stack.enter_async_context(create_mcp_http_client(headers=self.headers))
            streams = await stack.enter_async_context(
                streamable_http_client(self.url, http_client=http)
            )
            session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await session.initialize()
        except BaseException:
            await stack.aclose()
            raise
        self._stack = stack
        self._session = session
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        arguments: dict[str, Any] = {"query": promql}
        if at is not None:
            arguments["time"] = str(int(at))
        return parse_series(await self._call(self.tools.query, arguments))

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        arguments = {
            "query": promql,
            "start": str(int(start)),
            "end": str(int(end)),
            "step": f"{step}s",
        }
        return parse_series(await self._call(self.tools.query_range, arguments))

    async def logs(self, logql: str, since: str) -> list[Series]:
        return parse_series(await self._call(self.tools.logs, {"query": logql, "since": since}))

    async def alerts(self) -> list[Alert]:
        return parse_alerts(await self._call(self.tools.alerts, {}))

    async def _call(self, tool: str, arguments: dict[str, Any]) -> Any:
        if self._session is None:
            raise SourceError("MCP session is not open; use `async with McpTelemetry(...)`")
        result = await self._session.call_tool(tool, arguments, read_timeout_seconds=self.timeout)
        text = "".join(str(getattr(part, "text", "")) for part in result.content)
        if result.is_error:
            raise SourceError(f"{tool} failed: {text[:300]}")
        if not text.lstrip().startswith(("{", "[")):
            raise SourceError(f"{tool}: {text[:300]}")
        try:
            return json.loads(text)
        except ValueError as error:
            raise SourceError(
                f"{tool} returned {len(text)} characters that are not JSON; the server may "
                "truncate large responses, so aggregate the query"
            ) from error
