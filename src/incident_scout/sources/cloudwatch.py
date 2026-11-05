"""Amazon CloudWatch: metrics through Metrics Insights or metric math, logs through Logs Insights
and alarms in the ALARM state, plus ECS deployments and service events for evidence.

boto3 is synchronous, so every call runs in a worker thread.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import quote

import boto3

from ..models import Alert, Series
from .base import SourceError

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient
    from mypy_boto3_ecs import ECSClient
    from mypy_boto3_logs import CloudWatchLogsClient

T = TypeVar("T")
VALUE_FIELD = "value"
DONE = ("Complete", "Failed", "Cancelled", "Timeout", "Unknown")
QUERY_ID = "q"
_SERVICE_PREFIX = re.compile(r"^\(service [^)]*\) ")
_IDS = re.compile(r":?\s*\((?:task|deployment|container-instance) [^)]*\)")
_NAME_SUFFIX = re.compile(r"-[A-Za-z0-9]{10,}$")


@dataclass
class CloudWatchTelemetry:
    profile: str | None = None
    region: str | None = None
    query_timeout: float = 60
    poll_seconds: float = 1.0
    cloudwatch: CloudWatchClient | None = field(default=None, repr=False)
    logs_client: CloudWatchLogsClient | None = field(default=None, repr=False)
    ecs: ECSClient | None = field(default=None, repr=False)

    async def __aenter__(self) -> CloudWatchTelemetry:
        if self.cloudwatch is None or self.logs_client is None or self.ecs is None:
            session = boto3.Session(profile_name=self.profile, region_name=self.region)
            self.cloudwatch = self.cloudwatch or session.client("cloudwatch")
            self.logs_client = self.logs_client or session.client("logs")
            self.ecs = self.ecs or session.client("ecs")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    async def metrics(self, expression: str, start: float, end: float, period: int) -> list[Series]:
        """Series of a Metrics Insights query or metric math expression, one per label."""
        client = self._metrics_client()
        points: dict[str, list[tuple[float, float]]] = {}
        token: str | None = None
        while True:
            request: dict[str, Any] = {
                "MetricDataQueries": [{"Id": QUERY_ID, "Expression": expression, "Period": period}],
                "StartTime": datetime.fromtimestamp(start, UTC),
                "EndTime": datetime.fromtimestamp(end, UTC),
                "ScanBy": "TimestampAscending",
            }
            if token:
                request["NextToken"] = token
            response = await _call(client.get_metric_data, **request)
            for result in response["MetricDataResults"]:
                if result.get("StatusCode") in ("InternalError", "Forbidden"):
                    messages = "; ".join(m.get("Value", "") for m in result.get("Messages", []))
                    raise SourceError(f"CloudWatch {result['StatusCode']}: {messages}")
                series = points.setdefault(result.get("Label", ""), [])
                series += [
                    (stamp.timestamp(), float(value))
                    for stamp, value in zip(result["Timestamps"], result["Values"], strict=True)
                ]
            token = response.get("NextToken")
            if not token:
                break
        return [
            Series({} if label in ("", QUERY_ID) else {"label": label}, values)
            for label, values in points.items()
            if values
        ]

    async def log_query(
        self, groups: Sequence[str], query: str, start: float, end: float
    ) -> list[Series]:
        """Rows of a Logs Insights query as series.

        The number must be named `value`; a `bin(...)` field makes a timeline, every other
        field becomes a label.
        """
        client = self._logs()
        if not groups:
            raise SourceError("A logs_insights query needs log_groups")
        started = await _call(
            client.start_query,
            logGroupNames=list(groups),
            startTime=int(start),
            endTime=int(end),
            queryString=query,
        )
        query_id = started["queryId"]
        deadline = time.monotonic() + self.query_timeout
        while True:
            response = await _call(client.get_query_results, queryId=query_id)
            if response["status"] in DONE:
                break
            if time.monotonic() > deadline:
                await _call(client.stop_query, queryId=query_id)
                raise SourceError(f"Logs Insights query timed out after {self.query_timeout:g} s")
            await asyncio.sleep(self.poll_seconds)
        if response["status"] != "Complete":
            raise SourceError(f"Logs Insights query {response['status'].lower()}")
        return rows_to_series(
            [{cell["field"]: cell["value"] for cell in row} for row in response["results"]], end
        )

    async def alerts(self) -> list[Alert]:
        client = self._metrics_client()
        alerts = []
        token: str | None = None
        while True:
            request: dict[str, Any] = {"StateValue": "ALARM", "AlarmTypes": ["MetricAlarm"]}
            if token:
                request["NextToken"] = token
            response = await _call(client.describe_alarms, **request)
            for alarm in response["MetricAlarms"]:
                name = alarm["AlarmName"]
                labels = {
                    "alertname": name,
                    "namespace": alarm.get("Namespace", ""),
                    "metric": alarm.get("MetricName", ""),
                }
                updated = alarm.get("StateUpdatedTimestamp")
                alerts.append(
                    Alert(
                        labels=labels,
                        annotations={"summary": alarm.get("StateReason", "")},
                        starts_at=updated.isoformat() if updated else None,
                        url=self._alarm_url(name),
                    )
                )
            token = response.get("NextToken")
            if not token:
                return alerts

    async def service_events(
        self, cluster: str, start: float, end: float
    ) -> list[tuple[float, str, str]]:
        """Deployments started and ECS service events of a cluster within a window."""
        if self.ecs is None:
            raise SourceError("Use the CloudWatch source inside `async with`")
        client = self.ecs
        arns: list[str] = []
        token: str | None = None
        while True:
            request: dict[str, Any] = {"cluster": cluster}
            if token:
                request["nextToken"] = token
            listed = await _call(client.list_services, **request)
            arns += listed["serviceArns"]
            token = listed.get("nextToken")
            if not token:
                break
        found: list[tuple[float, str, str]] = []
        for chunk in range(0, len(arns), 10):
            described = await _call(
                client.describe_services, cluster=cluster, services=arns[chunk : chunk + 10]
            )
            for service in described["services"]:
                name = _NAME_SUFFIX.sub("", service.get("serviceName", "?"))
                for deployment in service.get("deployments", []):
                    moment = deployment["createdAt"].timestamp()
                    state = deployment.get("rolloutState", deployment.get("status", ""))
                    found.append((moment, name, f"deployment started ({state.lower()})"))
                for event in service.get("events", []):
                    message = _IDS.sub("", _SERVICE_PREFIX.sub("", event["message"])).strip()
                    found.append((event["createdAt"].timestamp(), name, " ".join(message.split())))
        return sorted(item for item in found if start <= item[0] <= end)

    async def query(self, promql: str, at: float | None = None) -> list[Series]:
        raise _unsupported("promql")

    async def query_range(self, promql: str, start: float, end: float, step: int) -> list[Series]:
        raise _unsupported("promql")

    async def logs(self, logql: str, since: str) -> list[Series]:
        raise _unsupported("logql")

    def _metrics_client(self) -> CloudWatchClient:
        if self.cloudwatch is None:
            raise SourceError("Use the CloudWatch source inside `async with`")
        return self.cloudwatch

    def _logs(self) -> CloudWatchLogsClient:
        if self.logs_client is None:
            raise SourceError("Use the CloudWatch source inside `async with`")
        return self.logs_client

    def _alarm_url(self, name: str) -> str | None:
        region = self.region or (self.cloudwatch.meta.region_name if self.cloudwatch else None)
        if not region:
            return None
        return (
            f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}"
            f"#alarmsV2:alarm/{quote(name, safe='')}"
        )


def rows_to_series(rows: Sequence[dict[str, str]], at: float) -> list[Series]:
    grouped: dict[tuple[tuple[str, str], ...], list[tuple[float, float]]] = {}
    for row in rows:
        if VALUE_FIELD not in row:
            raise SourceError(f"Logs Insights rows need a `{VALUE_FIELD}` field, got {sorted(row)}")
        moment = at
        labels = []
        for name, text in row.items():
            if name.startswith("bin("):
                moment = _log_time(text)
                continue
            if name != VALUE_FIELD and not name.startswith("@"):
                labels.append((name, text))
        grouped.setdefault(tuple(sorted(labels)), []).append((moment, float(row[VALUE_FIELD])))
    return [Series(dict(labels), sorted(points)) for labels, points in grouped.items()]


def _log_time(text: str) -> float:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC).timestamp()


async def _call(method: Callable[..., T], **kwargs: Any) -> T:
    return await asyncio.to_thread(method, **kwargs)


def _unsupported(kind: str) -> SourceError:
    return SourceError(
        f"A cloudwatch source has no {kind}; use cloudwatch, logs_insights or alertmanager rules"
    )
