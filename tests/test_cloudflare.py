from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest

from incident_scout.config import ConfigError, build_telemetry, load_config
from incident_scout.engine import backtest
from incident_scout.rules import Rule, evaluate
from incident_scout.sources.base import SourceError
from incident_scout.sources.cloudflare import CloudflareTelemetry

from .conftest import FakeTelemetry

T = TypeVar("T")
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC).timestamp()
FEED_BLOCKED = {
    "edgeResponseStatus": 403,
    "OR": [{"clientRequestPath_like": "/feed/%"}, {"userAgent_like": "%Zbozi%"}],
}


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def cloudflare(
    groups: Any, status: int = 200, errors: Any = None
) -> tuple[CloudflareTelemetry, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        zones = [] if groups is None else [{"httpRequestsAdaptiveGroups": groups}]
        return httpx.Response(status, json={"data": {"viewer": {"zones": zones}}, "errors": errors})

    transport = httpx.MockTransport(handler)
    return CloudflareTelemetry("zone-1", "secret", transport=transport), requests


def test_requests_are_counted_per_dimension_in_the_window():
    groups = [
        {
            "count": 40,
            "dimensions": {"clientRequestHTTPHost": "shop.example", "edgeResponseStatus": 403},
        },
        {
            "count": 10,
            "dimensions": {"clientRequestHTTPHost": "b.example", "edgeResponseStatus": None},
        },
    ]
    telemetry, requests = cloudflare(groups)
    found = run(
        telemetry.count(FEED_BLOCKED, 86400, NOW, ("clientRequestHTTPHost", "edgeResponseStatus"))
    )
    assert [(s.labels, s.points) for s in found] == [
        ({"clientRequestHTTPHost": "shop.example", "edgeResponseStatus": "403"}, [(NOW, 40.0)]),
        ({"clientRequestHTTPHost": "b.example", "edgeResponseStatus": ""}, [(NOW, 10.0)]),
    ]
    request = requests[0]
    assert str(request.url) == "https://api.cloudflare.com/client/v4/graphql"
    assert request.headers["Authorization"] == "Bearer secret"
    body = json.loads(request.content)
    assert "dimensions { clientRequestHTTPHost edgeResponseStatus }" in body["query"]
    window = {"datetime_geq": "2026-11-23T12:00:00Z", "datetime_lt": "2026-11-24T12:00:00Z"}
    assert body["variables"] == {
        "zone": "zone-1",
        "filter": {"AND": [FEED_BLOCKED, window]},
        "limit": 50,
    }


def test_without_a_group_the_total_is_one_series_even_when_zero():
    telemetry, requests = cloudflare([])
    found = run(telemetry.count(FEED_BLOCKED, 3600, NOW))
    assert [(s.labels, s.points) for s in found] == [({}, [(NOW, 0.0)])]
    assert "dimensions" not in json.loads(requests[0].content)["query"]
    telemetry, _ = cloudflare([{"count": 7}])
    assert run(telemetry.count(FEED_BLOCKED, 3600, NOW))[0].last == 7.0


@pytest.mark.parametrize(
    ("groups", "status", "errors", "message"),
    [
        ([], 200, [{"message": "does not have access to the path"}], "does not have access"),
        ([], 403, None, "HTTP 403"),
        (None, 200, None, "not found, or the token cannot read it"),
    ],
)
def test_cloudflare_errors_become_source_errors(
    groups: Any, status: int, errors: Any, message: str
):
    telemetry, _ = cloudflare(groups, status, errors)
    with pytest.raises(SourceError, match=message):
        run(telemetry.count(FEED_BLOCKED, 3600, NOW))


def test_a_dimension_cannot_inject_into_the_query():
    telemetry, requests = cloudflare([])
    with pytest.raises(SourceError, match="Invalid Cloudflare dimension"):
        run(telemetry.count(FEED_BLOCKED, 3600, NOW, ("count } evil {",)))
    assert requests == []


def test_cloudflare_rules_apply_their_threshold_and_need_their_source():
    rule = Rule(
        "partner-bot-blocked",
        "cloudflare",
        query=json.dumps(FEED_BLOCKED),
        since="24h",
        above=0,
        group_by="clientRequestHTTPHost, userAgent",
        summary="{clientRequestHTTPHost}: {userAgent} blocked {value:.0f}x",
    )
    groups = [
        {
            "count": 20,
            "dimensions": {"clientRequestHTTPHost": "shop.example", "userAgent": "Zbozi"},
        },
        {"count": 0, "dimensions": {"clientRequestHTTPHost": "b.example", "userAgent": "x"}},
    ]
    telemetry, requests = cloudflare(groups)
    findings = run(evaluate(rule, telemetry, now=NOW))
    assert [f.summary for f in findings] == ["shop.example: Zbozi blocked 20x"]
    assert (
        "dimensions { clientRequestHTTPHost userAgent }" in json.loads(requests[0].content)["query"]
    )
    with pytest.raises(SourceError, match="cloudflare source"):
        run(evaluate(rule, FakeTelemetry(), now=NOW))
    with pytest.raises(ValueError, match="cannot be replayed"):
        run(backtest(rule, telemetry, 0, 1, 60))


CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom"}}
sources:
  edge:
    type: cloudflare
    zone: zone-1
    token: secret
    vars: {{feed: /feed/}}
rules:
  - name: partner-bot-blocked
    kind: cloudflare
    source: edge
    query:
      edgeResponseStatus: 403
      clientRequestPath_like: '$feed%'
    group_by: [clientRequestHTTPHost, userAgent]
    since: 24h
    above: 0
  - name: blocked-total
    kind: cloudflare
    source: edge
    query: '{{"edgeResponseStatus": 403}}'
    above: 100
"""


def test_config_reads_cloudflare_sources_and_rules(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db"))
    config = load_config(path)
    rules = {rule.name: rule for rule in config.rules}
    bots = rules["partner-bot-blocked"]
    assert json.loads(bots.query) == {
        "edgeResponseStatus": 403,
        "clientRequestPath_like": "/feed/%",
    }
    assert (bots.group_by, bots.since, bots.above) == ("clientRequestHTTPHost,userAgent", "24h", 0)
    total = rules["blocked-total"]
    assert (json.loads(total.query), total.group_by, total.since) == (
        {"edgeResponseStatus": 403},
        None,
        "5m",
    )
    telemetry = build_telemetry(config.source_options("edge"))
    assert isinstance(telemetry, CloudflareTelemetry)
    assert telemetry.zone == "zone-1"


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        (
            "rules: [{name: x, kind: cloudflare, query: {edgeResponseStatus: 403}}]",
            "above or below",
        ),
        ("rules: [{name: x, kind: cloudflare, query: '[1]', above: 0}]", "filter object"),
        ("rules: [{name: x, kind: cloudflare, query: {a: 1}, above: 0, index: i}]", "only apply"),
    ],
)
def test_cloudflare_config_errors(tmp_path: Path, snippet: str, message: str):
    path = tmp_path / "config.yaml"
    path.write_text(snippet)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_cloudflare_source_options_are_checked():
    with pytest.raises(ConfigError, match=r"zone and source\.token are required"):
        build_telemetry({"type": "cloudflare", "zone": "z"})
    with pytest.raises(ConfigError, match="unknown option"):
        build_telemetry({"type": "cloudflare", "zone": "z", "token": "t", "account": "a"})
