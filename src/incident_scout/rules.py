from __future__ import annotations

import math
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from .models import SEVERITIES, Alert, Finding, Series, Severity
from .sources.base import SourceError, Telemetry, parse_duration
from .sources.cloudwatch import CloudWatchTelemetry

RuleKind = Literal["promql", "logql", "alertmanager", "cloudwatch", "logs_insights"]
METRIC_DELAY = 60  # CloudWatch publishes a period's datapoint about a minute after it ends
_PLACEHOLDER = re.compile(r"\{(\w+)(?::([^}]*))?\}")


@dataclass(frozen=True)
class Rule:
    """A query that returns only what is wrong, like a Prometheus alerting rule.

    `for_runs` is how many consecutive checks must see a problem before it is reported,
    `key_labels` identify one problem (default: every label of the series). `above` and
    `below` keep only series past a threshold, for query languages that cannot filter
    (CloudWatch Metrics Insights). `since` is the look-back of log queries and the period of
    CloudWatch metrics. `resolve_after` overrides the global number of clean checks before an
    incident is resolved, so a problem that recurs every hour stays one incident.
    """

    name: str
    kind: RuleKind
    query: str = ""
    severity: Severity = "warning"
    summary: str = ""
    key_labels: tuple[str, ...] = ()
    for_runs: int = 1
    since: str = "1m"
    match: Mapping[str, str] = field(default_factory=dict)
    url: str | None = None
    source: str = "default"
    log_groups: tuple[str, ...] = ()
    above: float | None = None
    below: float | None = None
    resolve_after: int | None = None

    def breached(self, value: float) -> bool:
        if self.above is not None and value <= self.above:
            return False
        return self.below is None or value < self.below


async def evaluate(rule: Rule, telemetry: Telemetry, now: float | None = None) -> list[Finding]:
    if rule.kind == "alertmanager":
        return [_alert_finding(rule, a) for a in await telemetry.alerts() if _matches(rule, a)]
    series = await _series(rule, telemetry, now or time.time())
    return [_series_finding(rule, s) for s in series if rule.breached(s.last)]


async def _series(rule: Rule, telemetry: Telemetry, now: float) -> Sequence[Series]:
    if rule.kind == "promql":
        return await telemetry.query(rule.query)
    if rule.kind == "logql":
        return await telemetry.logs(rule.query, rule.since)
    window = parse_duration(rule.since)
    if rule.kind == "cloudwatch":
        end = math.floor((now - METRIC_DELAY) / window) * window
        return await cloudwatch(telemetry).metrics(rule.query, end - window, end, window)
    if rule.kind == "logs_insights":
        return await cloudwatch(telemetry).log_query(rule.log_groups, rule.query, now - window, now)
    raise ValueError(f"Unknown rule kind {rule.kind!r}")


def cloudwatch(telemetry: Telemetry) -> CloudWatchTelemetry:
    if not isinstance(telemetry, CloudWatchTelemetry):
        raise SourceError("cloudwatch and logs_insights queries need a cloudwatch source")
    return telemetry


def series_key(rule: Rule, labels: Mapping[str, str]) -> str:
    names = rule.key_labels or tuple(sorted(name for name in labels if name != "__name__"))
    return ",".join(f"{name}={labels.get(name, '')}" for name in names)


def render(template: str, values: Mapping[str, Any]) -> str:
    """Fill `{label}` and `{value:.1f}` placeholders, leaving unknown ones untouched."""

    def substitute(match: re.Match[str]) -> str:
        name, spec = match.group(1), match.group(2) or ""
        if name not in values:
            return match.group(0)
        try:
            return format(values[name], spec)
        except (TypeError, ValueError):
            return str(values[name])

    return _PLACEHOLDER.sub(substitute, template)


def _series_finding(rule: Rule, series: Series) -> Finding:
    key = series_key(rule, series.labels)
    values = {**series.labels, "value": series.last, "rule": rule.name}
    summary = (
        render(rule.summary, values) if rule.summary else f"{rule.name}: {key} = {series.last:g}"
    )
    url = render(rule.url, values) if rule.url else None
    return Finding(rule.name, key, rule.severity, summary, series.last, url)


def _alert_finding(rule: Rule, alert: Alert) -> Finding:
    labels = alert.labels
    name = labels.get("alertname", "alert")
    key = series_key(rule, labels)
    severity = rule.severity
    if labels.get("severity") in SEVERITIES:
        severity = cast(Severity, labels["severity"])
    detail = alert.annotations.get("summary") or alert.annotations.get("description") or key
    values = {**labels, **alert.annotations, "rule": rule.name}
    summary = render(rule.summary, values) if rule.summary else f"{name}: {detail}"
    return Finding(rule.name, key, severity, summary, url=alert.url)


def _matches(rule: Rule, alert: Alert) -> bool:
    return all(
        re.fullmatch(pattern, alert.labels.get(label, "")) for label, pattern in rule.match.items()
    )
