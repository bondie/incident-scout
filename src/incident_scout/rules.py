from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, cast

from .models import SEVERITIES, Alert, Finding, Series, Severity
from .sources.base import Telemetry

RuleKind = Literal["promql", "logql", "alertmanager"]
_PLACEHOLDER = re.compile(r"\{(\w+)(?::([^}]*))?\}")


@dataclass(frozen=True)
class Rule:
    """A query that returns only what is wrong, like a Prometheus alerting rule.

    `for_runs` is how many consecutive checks must see a problem before it is reported,
    `key_labels` identify one problem (default: every label of the series).
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


async def evaluate(rule: Rule, telemetry: Telemetry) -> list[Finding]:
    if rule.kind == "promql":
        return [_series_finding(rule, s) for s in await telemetry.query(rule.query)]
    if rule.kind == "logql":
        return [_series_finding(rule, s) for s in await telemetry.logs(rule.query, rule.since)]
    if rule.kind == "alertmanager":
        return [_alert_finding(rule, a) for a in await telemetry.alerts() if _matches(rule, a)]
    raise ValueError(f"Unknown rule kind {rule.kind!r}")


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
