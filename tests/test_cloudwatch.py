from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from incident_scout import triage
from incident_scout.config import ConfigError, build_telemetry, load_config
from incident_scout.engine import backtest, run_check
from incident_scout.evidence import EvidenceQuery, collect
from incident_scout.models import Finding, Series
from incident_scout.rules import Rule, cloudwatch, evaluate
from incident_scout.sources.base import SourceError
from incident_scout.sources.cloudwatch import CloudWatchTelemetry, rows_to_series
from incident_scout.state import Store
from incident_scout.tracker import CheckResult, process

from .conftest import T0, FakeTelemetry, minutes, series

NOW = T0.timestamp()


def at(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, UTC)


def clients() -> tuple[Any, Any]:
    options: dict[str, Any] = {
        "region_name": "eu-central-1",
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
    }
    return boto3.client("cloudwatch", **options), boto3.client("logs", **options)


def stubbed() -> tuple[CloudWatchTelemetry, Stubber, Stubber]:
    metrics, logs = clients()
    telemetry = CloudWatchTelemetry(
        region="eu-central-1", poll_seconds=0, cloudwatch=metrics, logs_client=logs
    )
    return telemetry, Stubber(metrics), Stubber(logs)


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


class FakeCloudWatch(CloudWatchTelemetry):
    """Answers metric expressions and log queries from dictionaries."""

    def __init__(
        self,
        metrics: dict[str, list[Series]] | None = None,
        logs: dict[str, list[Series]] | None = None,
    ) -> None:
        super().__init__()
        self.metric_results = metrics or {}
        self.log_results = logs or {}
        self.calls: list[tuple[Any, ...]] = []

    async def __aenter__(self) -> FakeCloudWatch:
        return self

    async def metrics(self, expression: str, start: float, end: float, period: int) -> list[Series]:
        self.calls.append(("metrics", expression, start, end, period))
        return self.metric_results.get(expression, [])

    async def log_query(
        self, groups: Sequence[str], query: str, start: float, end: float
    ) -> list[Series]:
        self.calls.append(("logs", tuple(groups), query, start, end))
        return self.log_results.get(query, [])


def test_metrics_follow_pages_and_label_series():
    telemetry, metrics, _ = stubbed()
    query = [{"Id": "q", "Expression": "SELECT 1", "Period": 300}]
    expected = {
        "MetricDataQueries": query,
        "StartTime": at(NOW - 600),
        "EndTime": at(NOW),
        "ScanBy": "TimestampAscending",
    }
    metrics.add_response(
        "get_metric_data",
        {
            "MetricDataResults": [
                {"Id": "q", "Label": "lb-a", "Timestamps": [at(NOW - 600)], "Values": [3.0]},
                {"Id": "q", "Label": "lb-b", "Timestamps": [], "Values": []},
                {"Id": "q", "Label": "q", "Timestamps": [at(NOW - 600)], "Values": [1.0]},
            ],
            "NextToken": "more",
        },
        expected,
    )
    metrics.add_response(
        "get_metric_data",
        {
            "MetricDataResults": [
                {"Id": "q", "Label": "lb-a", "Timestamps": [at(NOW - 300)], "Values": [5.0]}
            ]
        },
        {**expected, "NextToken": "more"},
    )
    with metrics:
        found = run(telemetry.metrics("SELECT 1", NOW - 600, NOW, 300))
    assert found == [
        Series({"label": "lb-a"}, [(NOW - 600, 3.0), (NOW - 300, 5.0)]),
        Series({}, [(NOW - 600, 1.0)]),  # without GROUP BY the label is the query id
    ]


def test_metric_errors_are_reported():
    telemetry, metrics, _ = stubbed()
    metrics.add_response(
        "get_metric_data",
        {
            "MetricDataResults": [
                {
                    "Id": "q",
                    "Label": "x",
                    "Timestamps": [],
                    "Values": [],
                    "StatusCode": "Forbidden",
                    "Messages": [{"Code": "Forbidden", "Value": "no access to AWS/RDS"}],
                }
            ]
        },
    )
    with metrics, pytest.raises(SourceError, match="no access to AWS/RDS"):
        run(telemetry.metrics("SELECT 1", NOW - 300, NOW, 300))


def test_log_queries_poll_until_complete_and_become_series():
    telemetry, _, logs = stubbed()
    query = "stats count(*) as value by bin(5m)"
    logs.add_response(
        "start_query",
        {"queryId": "q1"},
        {
            "logGroupNames": ["/app"],
            "startTime": int(NOW - 600),
            "endTime": int(NOW),
            "queryString": query,
        },
    )
    logs.add_response("get_query_results", {"status": "Running", "results": []}, {"queryId": "q1"})
    rows = [
        [
            {"field": "bin(5m)", "value": "2026-11-03 11:50:00.000"},
            {"field": "value", "value": "4"},
        ],
        [
            {"field": "bin(5m)", "value": "2026-11-03 11:55:00.000"},
            {"field": "value", "value": "9"},
        ],
    ]
    logs.add_response(
        "get_query_results", {"status": "Complete", "results": rows}, {"queryId": "q1"}
    )
    with logs:
        found = run(telemetry.log_query(["/app"], query, NOW - 600, NOW))
    assert found == [Series({}, [(NOW - 600, 4.0), (NOW - 300, 9.0)])]


@pytest.mark.parametrize("status", ["Failed", "Cancelled"])
def test_failed_log_queries_raise(status: str):
    telemetry, _, logs = stubbed()
    logs.add_response("start_query", {"queryId": "q1"})
    logs.add_response("get_query_results", {"status": status, "results": []})
    with logs, pytest.raises(SourceError, match=status.lower()):
        run(telemetry.log_query(["/app"], "stats count(*) as value", NOW - 60, NOW))


def test_slow_log_queries_are_stopped():
    telemetry, _, logs = stubbed()
    telemetry.query_timeout = 0
    logs.add_response("start_query", {"queryId": "q1"})
    logs.add_response("get_query_results", {"status": "Running", "results": []})
    logs.add_response("stop_query", {"success": True}, {"queryId": "q1"})
    with logs, pytest.raises(SourceError, match="timed out"):
        run(telemetry.log_query(["/app"], "stats count(*) as value", NOW - 60, NOW))
    logs.assert_no_pending_responses()


def test_rows_without_a_bin_are_totals_and_need_a_value():
    rows = [{"path": "/a", "value": "7", "@ptr": "x"}, {"path": "/b", "value": "2"}]
    assert rows_to_series(rows, NOW) == [
        Series({"path": "/a"}, [(NOW, 7.0)]),
        Series({"path": "/b"}, [(NOW, 2.0)]),
    ]
    with pytest.raises(SourceError, match="value"):
        rows_to_series([{"count": "1"}], NOW)
    with pytest.raises(SourceError, match="log_groups"):
        run(stubbed()[0].log_query([], "x", 0, 1))


def test_alarms_become_alerts_with_a_console_link():
    telemetry, metrics, _ = stubbed()
    alarm = {
        "AlarmName": "db storage",
        "Namespace": "AWS/RDS",
        "MetricName": "FreeStorageSpace",
        "StateReason": "Threshold crossed",
        "StateUpdatedTimestamp": at(NOW),
    }
    metrics.add_response(
        "describe_alarms",
        {"MetricAlarms": [alarm], "NextToken": "n"},
        {"StateValue": "ALARM", "AlarmTypes": ["MetricAlarm"]},
    )
    metrics.add_response("describe_alarms", {"MetricAlarms": []})
    with metrics:
        (alert,) = run(telemetry.alerts())
    assert alert.labels == {
        "alertname": "db storage",
        "namespace": "AWS/RDS",
        "metric": "FreeStorageSpace",
    }
    assert alert.annotations == {"summary": "Threshold crossed"}
    assert alert.url is not None
    assert alert.url.endswith("#alarmsV2:alarm/db%20storage")


def test_cloudwatch_has_no_promql_or_logql_and_needs_a_context():
    telemetry = CloudWatchTelemetry()
    for call in (
        telemetry.query("up"),
        telemetry.query_range("up", 0, 1, 1),
        telemetry.logs("x", "1m"),
    ):
        with pytest.raises(SourceError, match=r"no (promql|logql)"):
            run(call)
    with pytest.raises(SourceError, match="async with"):
        run(telemetry.metrics("SELECT 1", 0, 1, 60))
    with pytest.raises(SourceError, match="async with"):
        run(telemetry.log_query(["/a"], "x", 0, 1))
    with pytest.raises(SourceError, match="cloudwatch source"):
        cloudwatch(FakeTelemetry())


def test_a_cloudwatch_source_opens_its_own_clients(monkeypatch: pytest.MonkeyPatch):
    made: list[tuple[str | None, str | None, str]] = []

    class Session:
        def __init__(self, profile_name: str | None, region_name: str | None) -> None:
            self.profile, self.region = profile_name, region_name

        def client(self, name: str) -> str:
            made.append((self.profile, self.region, name))
            return name

    monkeypatch.setattr(boto3, "Session", Session)
    telemetry = build_telemetry({"type": "cloudwatch", "profile": "p", "region": "r", "vars": {}})
    run(telemetry.__aenter__())
    assert made == [("p", "r", "cloudwatch"), ("p", "r", "logs"), ("p", "r", "ecs")]
    with pytest.raises(ConfigError, match="unknown option"):
        build_telemetry({"type": "cloudwatch", "role": "x"})


def test_metric_rules_read_the_last_complete_period_and_apply_thresholds():
    rule = Rule(
        "errors",
        "cloudwatch",
        query="SELECT 5xx",
        since="5m",
        above=9,
        summary="{label}: {value:.0f}",
    )
    fake = FakeCloudWatch(
        metrics={
            "SELECT 5xx": [
                Series({"label": "a"}, [(NOW, 12.0)]),
                Series({"label": "b"}, [(NOW, 9.0)]),
            ]
        }
    )
    found = run(evaluate(rule, fake, now=NOW + 200))
    assert [f.summary for f in found] == ["a: 12"]
    _, _, start, end, period = fake.calls[0]
    assert (start, end, period) == (NOW - 300, NOW, 300)

    low = Rule("healthy", "cloudwatch", query="SELECT 5xx", below=10)
    assert [f.value for f in run(evaluate(low, fake, now=NOW))] == [9.0]


def test_log_rules_query_their_groups_over_the_window():
    rule = Rule("5xx", "logs_insights", query="Q", since="5m", log_groups=("/app",))
    fake = FakeCloudWatch(logs={"Q": [Series({}, [(NOW, 14.0)])]})
    (finding,) = run(evaluate(rule, fake, now=NOW))
    assert finding.value == 14.0
    assert fake.calls == [("logs", ("/app",), "Q", NOW - 300, NOW)]


def test_checks_run_every_source_and_name_missing_ones():
    rules = [
        Rule("disk", "promql", query="disk > 0.85"),
        Rule("errors@shop", "cloudwatch", query="SELECT 5xx", source="shop", above=0),
        Rule("orphan", "promql", query="x", source="gone"),
    ]
    connections: dict[str, Any] = {
        "default": FakeTelemetry(metrics={"disk > 0.85": [series(0.9, shop="a")]}),
        "shop": FakeCloudWatch(metrics={"SELECT 5xx": [Series({"label": "lb"}, [(NOW, 3.0)])]}),
    }
    result = run(run_check(connections, rules))
    assert sorted(f.rule for f in result.findings) == ["disk", "errors@shop"]
    assert result.errors == {"orphan": "no connection for its source"}


def test_metric_rules_replay_with_their_period_and_threshold():
    rule = Rule("cpu", "cloudwatch", query="SELECT cpu", since="15m", above=80)
    points = [
        (NOW + 900 * i, value) for i, value in enumerate([50.0, 90.0, 95.0, 40.0, 40.0, 85.0])
    ]
    fake = FakeCloudWatch(metrics={"SELECT cpu": [Series({"label": "server"}, points)]})
    found = run(backtest(rule, fake, NOW, NOW + 5 * 900, 300))
    assert [(e.start, e.end, e.peak) for e in found] == [
        (NOW + 900, NOW + 1800, 95.0),
        (NOW + 4500, NOW + 4500, 85.0),
    ]
    assert fake.calls[0][4] == 900
    with pytest.raises(ValueError, match="cannot be replayed"):
        run(backtest(Rule("l", "logs_insights", query="q"), fake, 0, 1, 60))


def test_a_rule_can_wait_longer_before_resolving(store: Store):
    rules = {"flaky": Rule("flaky", "cloudwatch", query="q", resolve_after=3)}
    problem = Finding("flaky", "label=a", "warning", "a fails", 1)

    def check(at: float, *findings: Finding) -> list[str]:
        result = CheckResult(list(findings), ["flaky"], {})
        return [e.kind for e in process(store, result, rules, minutes(at), resolve_after=1)]

    assert check(0, problem) == ["opened"]
    assert check(5) == []
    assert check(10) == []
    assert check(15, problem) == []  # it came back before three clean checks: same incident
    assert check(20) == []
    assert check(25) == []
    assert check(30) == ["resolved"]


AWS_CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom"}}
vars: {{env: prod}}
sources:
  shop-a: {{type: cloudwatch, profile: scout-a, vars: {{shop: a, logs: /docker-compose/a-$env}}}}
  shop-b: {{type: cloudwatch, profile: scout-b, vars: {{shop: b, logs: /docker-compose/b}}}}
rules:
  - {{name: disk, kind: promql, query: 'disk > 0.9'}}
  - name: errors
    kind: logs_insights
    sources: [shop-a, shop-b]
    log_groups: ['$logs']
    query: 'filter status >= 500 | stats count(*) as value'
    summary: '$shop: {{value}}x 5xx'
  - {{name: cpu, kind: cloudwatch, source: shop-a, query: "SELECT AVG(CPU) WHERE x = '$shop-prod'"}}
investigator:
  model: tiny
  evidence:
    - {{name: Probes, kind: promql, query: 'probe_success'}}
    - name: Errors
      kind: logs_insights
      sources: [shop-a, shop-b]
      log_groups: ['$logs']
      query: 'stats count(*) as value by message'
"""


@pytest.fixture
def aws_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(AWS_CONFIG.format(state=tmp_path / "state.db"))
    return path


def test_rules_and_evidence_repeat_for_every_listed_source(aws_config: Path):
    config = load_config(aws_config)
    rules = {rule.name: rule for rule in config.rules}
    assert list(rules) == ["disk", "errors@shop-a", "errors@shop-b", "cpu"]
    assert rules["errors@shop-a"].log_groups == ("/docker-compose/a-prod",)
    assert rules["errors@shop-b"].summary == "b: {value}x 5xx"
    assert rules["errors@shop-b"].since == "5m"
    assert rules["cpu"].source == "shop-a"
    assert rules["cpu"].query.endswith("x = 'a-prod'")
    assert config.source_options("shop-b")["profile"] == "scout-b"
    with pytest.raises(ConfigError, match="Unknown source"):
        config.source_options("nowhere")
    settings = config.investigator
    assert settings is not None
    assert [(q.name, q.source, q.log_groups) for q in settings.evidence] == [
        ("Probes", "default", ()),
        ("Errors", "shop-a", ("/docker-compose/a-prod",)),
        ("Errors", "shop-b", ("/docker-compose/b",)),
    ]


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        ("sources: {default: {type: http}}", "reserved"),
        ("rules: [{name: x, kind: promql, query: q, source: nowhere}]", "Unknown source"),
        ("rules: [{name: x, kind: promql, query: q, sources: one}]", "must be a list"),
        ("rules: [{name: x, kind: logs_insights, query: q}]", "log_groups is required"),
    ],
)
def test_source_config_errors(tmp_path: Path, snippet: str, message: str):
    path = tmp_path / "config.yaml"
    path.write_text(snippet)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_evidence_runs_on_the_incident_source(aws_config: Path, monkeypatch: pytest.MonkeyPatch):
    fake = FakeCloudWatch(
        logs={"stats count(*) as value by message": [Series({"message": "boom"}, [(NOW, 7.0)])]}
    )
    used: list[Mapping[str, Any]] = []

    def telemetry(options: Mapping[str, Any]) -> FakeCloudWatch:
        used.append(options)
        return fake

    monkeypatch.setattr(triage, "build_telemetry", telemetry)
    pack = run(triage.gather(load_config(aws_config), "errors@shop-b", "warning", "b", {}, NOW))
    assert [s.name for s in pack.sections] == ["Errors"]
    assert pack.sections[0].lines == ["     7x  message=boom"]
    assert used[0]["profile"] == "scout-b"
    assert fake.calls[0][1] == ("/docker-compose/b",)


def test_cloudwatch_and_log_timelines_in_the_evidence():
    fake = FakeCloudWatch(
        metrics={"SELECT req": [Series({"label": "lb"}, [(NOW - 300, 120.0), (NOW, 80.0)])]},
        logs={"stats count(*) as value by bin(5m)": [Series({}, [(NOW, 33.0)])]},
    )
    queries = [
        EvidenceQuery("Requests", "cloudwatch", "SELECT req"),
        EvidenceQuery(
            "5xx", "logs_insights", "stats count(*) as value by bin(5m)", log_groups=("/a",)
        ),
    ]
    pack = run(collect(fake, queries, "r", "warning", "s", {}, NOW, before=600, after=0, now=NOW))
    sections = {s.name: s.lines for s in pack.sections}
    assert sections["Requests"][1].split()[-2:] == ["120", "80"]
    assert sections["5xx"][1].split()[-1] == "33"


def test_log_groups_take_incident_labels_and_are_left_out_without_them():
    fake = FakeCloudWatch(logs={"Q": [Series({"error": "boom"}, [(NOW, 3.0)])]})
    query = EvidenceQuery("Lambda errors", "logs_insights", "Q", log_groups=("/aws/lambda/$label",))
    pack = run(collect(fake, [query], "r", "warning", "s", {"label": "worker"}, NOW, now=NOW))
    assert pack.sections[0].lines == ["     3x  error=boom"]
    assert fake.calls[0][1] == ("/aws/lambda/worker",)
    other = run(collect(fake, [query], "r", "warning", "s", {"shop": "a"}, NOW, now=NOW))
    assert other.sections == []
    assert len(fake.calls) == 1


def test_service_events_list_deployments_and_events_in_the_window():
    options: dict[str, Any] = {
        "region_name": "eu-central-1",
        "aws_access_key_id": "test",
        "aws_secret_access_key": "test",
    }
    ecs = boto3.client("ecs", **options)
    telemetry = CloudWatchTelemetry(ecs=ecs)
    stub = Stubber(ecs)
    arns = [f"arn:aws:ecs:eu-central-1:1:service/shop-prod/svc-{i}" for i in range(11)]
    stub.add_response(
        "list_services", {"serviceArns": arns[:6], "nextToken": "n"}, {"cluster": "shop-prod"}
    )
    stub.add_response(
        "list_services", {"serviceArns": arns[6:]}, {"cluster": "shop-prod", "nextToken": "n"}
    )
    server = {
        "serviceName": "shop-prod-ServerService-Xk29fQ7LmN4p",
        "deployments": [{"createdAt": at(NOW - 120), "rolloutState": "COMPLETED"}],
        "events": [
            {
                "createdAt": at(NOW - 60),
                "message": "(service shop-prod-ServerService-Xk29fQ7LmN4p) has started 1 tasks: "
                "(task 5f2c0a1b2c3d4e5f).",
            },
            {"createdAt": at(NOW - 86400), "message": "(service x) has reached a steady state."},
        ],
    }
    stub.add_response(
        "describe_services",
        {"services": [server]},
        {"cluster": "shop-prod", "services": arns[:10]},
    )
    stub.add_response(
        "describe_services", {"services": []}, {"cluster": "shop-prod", "services": arns[10:]}
    )
    with stub:
        events = run(telemetry.service_events("shop-prod", NOW - 600, NOW))
    assert events == [
        (NOW - 120, "shop-prod-ServerService", "deployment started (completed)"),
        (NOW - 60, "shop-prod-ServerService", "has started 1 tasks."),
    ]
    with pytest.raises(SourceError, match="async with"):
        run(CloudWatchTelemetry().service_events("x", 0, 1))


def test_service_events_in_the_evidence():
    class Deploying(FakeCloudWatch):
        async def service_events(
            self, cluster: str, start: float, end: float
        ) -> list[tuple[float, str, str]]:
            return [(NOW - 300 * i, f"svc-{i}", "deployment started") for i in range(3, 0, -1)]

    query = EvidenceQuery("Deployments", "ecs_events", "shop-prod", limit=2)
    pack = run(collect(Deploying(), [query], "r", "warning", "s", {}, NOW, now=NOW))
    assert [line.split("  ", 1)[1] for line in pack.sections[0].lines] == [
        "svc-2: deployment started",
        "svc-1: deployment started",
    ]
