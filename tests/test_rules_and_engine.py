from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar

import pytest

from incident_scout.config import load_config
from incident_scout.engine import backtest, describe, episodes, run_check, with_offset
from incident_scout.models import Alert, Series
from incident_scout.rules import Rule, evaluate, render
from incident_scout.sources.base import SourceError

from .conftest import T0, FakeTelemetry, series

T = TypeVar("T")

ERRORS = Rule(
    "http-5xx",
    "logql",
    query="sum by (shop) (count_over_time({job='app'} |~ `5\\d\\d` [5m])) >= 10",
    severity="critical",
    summary="{shop}: {value:.0f}x 5xx",
    key_labels=("shop",),
)
DISK = Rule("disk", "promql", query="disk > 0.85", summary="{shop}: {value:.0%} full")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def test_promql_rule_reports_every_returned_series():
    telemetry = FakeTelemetry(
        metrics={"disk > 0.85": [series(0.91, shop="a", job="node"), series(0.88, shop="b")]}
    )
    findings = run(evaluate(DISK, telemetry))
    assert [f.summary for f in findings] == ["a: 91% full", "b: 88% full"]
    assert findings[0].key == "job=node,shop=a"
    assert findings[0].fingerprint == "disk|job=node,shop=a"


def test_logql_rule_uses_the_latest_point_and_key_labels():
    window = Series({"shop": "shop-b", "pod": "x"}, [(1.0, 12.0), (2.0, 55.0)])
    telemetry = FakeTelemetry(logs={ERRORS.query: [window]})
    (finding,) = run(evaluate(ERRORS, telemetry))
    assert finding.summary == "shop-b: 55x 5xx"
    assert finding.key == "shop=shop-b"
    assert finding.severity == "critical"
    assert telemetry.log_calls == [(ERRORS.query, "1m")]


def test_alertmanager_rule_filters_and_takes_severity_from_labels():
    rule = Rule("infra", "alertmanager", match={"alertname": "(?!ShopHttpDown$).*"})
    alerts = [
        Alert({"alertname": "TunnelDown", "severity": "critical"}, {"summary": "tunnel is down"}),
        Alert({"alertname": "ShopHttpDown", "severity": "critical"}),
        Alert({"alertname": "Odd", "severity": "page"}),
    ]
    findings = run(evaluate(rule, FakeTelemetry(alerts=alerts)))
    assert [(f.summary, f.severity) for f in findings] == [
        ("TunnelDown: tunnel is down", "critical"),
        ("Odd: alertname=Odd,severity=page", "warning"),
    ]


def test_render_keeps_unknown_placeholders_and_survives_bad_specs():
    assert render("{shop} {value:.1f} {nope}", {"shop": "a", "value": 2}) == "a 2.0 {nope}"
    assert render("{shop:.1f}", {"shop": "text"}) == "text"


def test_one_failing_rule_does_not_hide_the_others():
    telemetry = FakeTelemetry(
        metrics={"disk > 0.85": [series(0.9, shop="a")]},
        logs={ERRORS.query: SourceError("loki is down")},
    )
    result = run(run_check({"default": telemetry}, [ERRORS, DISK]))
    assert [f.rule for f in result.findings] == ["disk"]
    assert result.errors == {"http-5xx": "SourceError: loki is down"}
    assert not result.blind


class Unreachable(FakeTelemetry):
    async def __aenter__(self) -> FakeTelemetry:
        raise ExceptionGroup("transport", [ConnectionError("VPN is off")])


def test_unreachable_telemetry_fails_every_rule():
    result = run(run_check({"default": Unreachable()}, [ERRORS, DISK]))
    assert result.blind
    assert set(result.errors.values()) == {"ConnectionError: VPN is off"}


def test_describe_unwraps_exception_groups():
    nested = ExceptionGroup("outer", [ExceptionGroup("inner", [TimeoutError("slow")])])
    assert describe(nested) == "TimeoutError: slow"


def test_episodes_group_consecutive_points_per_key():
    rule = Rule("down", "promql", query="up == 0", key_labels=("shop",))
    points = [(0.0, 1.0), (60.0, 1.0), (120.0, 1.0), (3600.0, 1.0)]
    found = episodes(rule, [Series({"shop": "a"}, points)], step=60)
    assert [(e.start, e.end, e.points) for e in found] == [(0.0, 120.0, 3), (3600.0, 3600.0, 1)]
    assert found[0].minutes == 2


def test_promql_backtest_replays_history_in_daily_chunks():
    history = [Series({"shop": "a"}, [(T0.timestamp() + 60 * i, 0.9) for i in range(3)])]
    telemetry = FakeTelemetry(ranges={DISK.query: history})
    start = T0.timestamp() - 2 * 86400
    found = run(backtest(DISK, telemetry, start, T0.timestamp() + 600, step=60))
    assert len(telemetry.range_calls) == 3
    assert [(e.key, e.points) for e in found] == [("shop=a", 3)]


def test_logql_backtest_walks_back_with_offsets():
    telemetry = FakeTelemetry(logs={ERRORS.query: [Series({"shop": "a"}, [(T0.timestamp(), 55)])]})
    end = T0.timestamp()
    run(backtest(ERRORS, telemetry, end - 86400, end, step=60))
    assert [since for _, since in telemetry.log_calls] == ["12h", "12h"]
    assert "[5m] offset 43200s" in telemetry.log_calls[1][0]


def test_with_offset_shifts_every_range_selector():
    query = "sum(rate(x[5m])) / sum(rate(y[1h]))"
    assert with_offset(query, 0) == query
    assert with_offset(query, 60) == "sum(rate(x[5m] offset 60s)) / sum(rate(y[1h] offset 60s))"


def test_alertmanager_rules_cannot_be_backtested():
    with pytest.raises(ValueError, match="no history"):
        run(backtest(Rule("a", "alertmanager"), FakeTelemetry(), 0, 1, 60))


CONNECTOR_RULE = r"""
vars: {shop: Kovian}
source: {type: http, loki_url: "http://loki"}
rules:
  - name: connector
    kind: logql
    query: 'failed'
    key_labels: [type, reason]
    rewrite:
      reason:
        - ['\s*\([^)]*\)\.?$', '']
        - ['\s*\[(entityType|externalCode): [^\]]*\]', '']
        - ['(externalCode: )[^)\s]+', '\1…']
        - ['(?:[A-Za-z]+\\\\)+([A-Za-z]+)', '\1']
    summary: '$shop: KARAT {type} se nepropsal na e-shop ({count}x: {code}) - {reason}'
"""


def test_rewritten_series_of_one_problem_become_one_finding(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(CONNECTOR_RULE)
    rule = load_config(path).rule("connector")
    reason = r"App\\Entity\\Customer: First name is too short"
    telemetry = FakeTelemetry(
        logs={
            "failed": [
                series(1, type="customer", code="C1", reason=f"{reason} (x)."),
                series(2, type="customer", code="C2", reason=f"{reason} (EB2-1.5-125-60x104)."),
                series(1, type="customer", code="C3", reason=f"{reason} [externalCode: K7] (x)"),
                series(5, type="order", code="O1", reason="Unknown payment (card)."),
            ]
        }
    )
    customers, orders = run(evaluate(rule, telemetry))
    assert customers.summary == (
        "Kovian: KARAT customer se nepropsal na e-shop (3x: C1, C2, C3) - "
        "Customer: First name is too short"
    )
    assert customers.key == "type=customer,reason=Customer: First name is too short"
    assert customers.value == 4
    assert customers.members == ("C1", "C2", "C3")
    assert customers.labels == {"type": "customer", "reason": "Customer: First name is too short"}
    assert orders.summary == "Kovian: KARAT order se nepropsal na e-shop (1x: O1) - Unknown payment"


def test_merged_labels_show_five_distinct_values_and_how_many_more():
    rule = Rule("import", "logql", query="q", key_labels=("type",), summary="{count} {code}")
    codes = ["c1", "c2", "c1", "c3", "c4", "c5", "c6", "c7", "c8"]
    telemetry = FakeTelemetry(logs={"q": [series(1, type="t", code=code) for code in codes]})
    (finding,) = run(evaluate(rule, telemetry))
    assert finding.summary == "9 c1, c2, c3, c4, c5 +3"
    assert finding.value == 9


def test_without_key_labels_every_series_stays_its_own_finding():
    telemetry = FakeTelemetry(
        metrics={"disk > 0.85": [series(0.9, shop="a"), series(0.8, shop="a"), series(0.7)]}
    )
    findings = run(evaluate(DISK, telemetry))
    assert [(f.key, f.value, f.summary) for f in findings] == [
        ("shop=a", 0.9, "a: 90% full"),
        ("shop=a", 0.8, "a: 80% full"),
        ("", 0.7, "{shop}: 70% full"),
    ]
    assert [f.members for f in findings] == [(), (), ()]


def test_backtests_group_rewritten_series_like_checks():
    rule = Rule(
        "r", "logql", query="q", key_labels=("reason",), rewrite={"reason": ((r" \(.*", ""),)}
    )
    found = episodes(
        rule,
        [
            Series({"reason": "short (x)"}, [(0.0, 1.0)]),
            Series({"reason": "short (y)"}, [(60.0, 1.0)]),
        ],
        step=60,
    )
    assert [(e.key, e.points) for e in found] == [("reason=short", 2)]
