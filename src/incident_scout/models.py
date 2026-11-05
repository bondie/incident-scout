from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "warning", "critical"]
SEVERITIES: tuple[Severity, ...] = ("info", "warning", "critical")


@dataclass(frozen=True)
class Series:
    """One labelled time series; an instant query yields a single point per series."""

    labels: dict[str, str]
    points: list[tuple[float, float]]

    @property
    def last(self) -> float:
        return self.points[-1][1]


@dataclass(frozen=True)
class Alert:
    labels: dict[str, str]
    annotations: dict[str, str] = field(default_factory=dict)
    starts_at: str | None = None
    url: str | None = None


@dataclass(frozen=True)
class Finding:
    """Something a rule considers wrong right now."""

    rule: str
    key: str
    severity: Severity
    summary: str
    value: float | None = None
    url: str | None = None

    @property
    def fingerprint(self) -> str:
        return f"{self.rule}|{self.key}"


@dataclass(frozen=True)
class Event:
    """A state change worth telling a human about."""

    kind: Literal[
        "opened",
        "resolved",
        "diagnosed",
        "diagnosis_failed",
        "reviewed",
        "proposed",
        "approved",
        "rejected",
        "blind",
        "restored",
        "rule_failing",
        "rule_recovered",
    ]
    severity: Severity
    title: str
    message: str
    group: str
    url: str | None = None
    incident_id: int | None = None
