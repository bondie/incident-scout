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
MERGED_SHOWN = 5
_PLACEHOLDER = re.compile(r"\{(\w+)(?::([^}]*))?\}")
Rewrite = Mapping[str, tuple[tuple[str, str], ...]]


@dataclass(frozen=True)
class Rule:
    """A query that returns only what is wrong, like a Prometheus alerting rule.

    `for_runs` is how many consecutive checks must see a problem before it is reported,
    `key_labels` identify one problem (default: every label of the series). `above` and
    `below` keep only series past a threshold, for query languages that cannot filter
    (CloudWatch Metrics Insights). `since` is the look-back of log queries and the period of
    CloudWatch metrics. `resolve_after` overrides the global number of clean checks before an
    incident is resolved, so a problem that recurs every hour stays one incident.
    `rewrite` maps a label to [regex, replacement] pairs applied before the key is computed;
    series that then share a key are merged into one finding. `record_labels` name one record
    such a problem hit (a customer code), so ticket cards count records instead of incidents.
    `title` names the problem on ticket cards; `shop` and `shop_title` default to the vars of
    the rule's source.
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
    rewrite: Rewrite = field(default_factory=dict)
    record_labels: tuple[str, ...] = ()
    title: str = ""
    shop: str = ""
    shop_title: str = ""

    def breached(self, value: float) -> bool:
        if self.above is not None and value <= self.above:
            return False
        return self.below is None or value < self.below


async def evaluate(rule: Rule, telemetry: Telemetry, now: float | None = None) -> list[Finding]:
    if rule.kind == "alertmanager":
        return [_alert_finding(rule, a) for a in await telemetry.alerts() if _matches(rule, a)]
    series = await _series(rule, telemetry, now or time.time())
    problems = [
        Series(rewritten(rule, s.labels), s.points) for s in series if rule.breached(s.last)
    ]
    if not rule.key_labels and not rule.rewrite:
        return [_series_finding(rule, [s]) for s in problems]
    groups: dict[str, list[Series]] = {}
    for item in problems:
        groups.setdefault(series_key(rule, item.labels), []).append(item)
    return [_series_finding(rule, group) for group in groups.values()]


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
    return ",".join(f"{name}={value}" for name, value in key_values(rule, labels).items())


def key_values(rule: Rule, labels: Mapping[str, str]) -> dict[str, str]:
    names = rule.key_labels or tuple(sorted(name for name in labels if name != "__name__"))
    return {name: labels.get(name, "") for name in names}


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


def rewritten(rule: Rule, labels: Mapping[str, str]) -> dict[str, str]:
    result = dict(labels)
    for name, steps in rule.rewrite.items():
        if name not in result:
            continue
        for pattern, replacement in steps:
            result[name] = re.sub(pattern, replacement, result[name])
    return result


def _series_finding(rule: Rule, group: Sequence[Series]) -> Finding:
    key = series_key(rule, group[0].labels)
    value = sum(item.last for item in group)
    labels = {name: _merged(rule, name, group) for name in _names(group)}
    values = {"count": len(group), **labels, "value": value, "rule": rule.name}
    summary = render(rule.summary, values) if rule.summary else f"{rule.name}: {key} = {value:g}"
    url = render(rule.url, values) if rule.url else None
    members = tuple(dict.fromkeys(filter(None, (_member(rule, item) for item in group))))
    own = key_values(rule, group[0].labels)
    return Finding(rule.name, key, rule.severity, summary, value, url, own, members)


def _member(rule: Rule, series: Series) -> str:
    return " / ".join(series.labels[name] for name in rule.record_labels if name in series.labels)


def _names(group: Sequence[Series]) -> list[str]:
    return list(dict.fromkeys(name for item in group for name in item.labels))


def _merged(rule: Rule, name: str, group: Sequence[Series]) -> str:
    """One value, or the distinct values of merged series in first-seen order, capped."""
    values = list(dict.fromkeys(item.labels[name] for item in group if name in item.labels))
    if name in rule.key_labels or len(values) == 1:
        return values[0]
    return capped(values)


def capped(values: Sequence[str]) -> str:
    shown = ", ".join(values[:MERGED_SHOWN])
    hidden = len(values) - MERGED_SHOWN
    if hidden <= 0:
        return shown
    return f"{shown} +{hidden}"


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
    return Finding(
        rule.name, key, severity, summary, url=alert.url, labels=key_values(rule, labels)
    )


def _matches(rule: Rule, alert: Alert) -> bool:
    return all(
        re.fullmatch(pattern, alert.labels.get(label, "")) for label, pattern in rule.match.items()
    )
