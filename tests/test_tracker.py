from __future__ import annotations

from incident_scout.models import Event, Finding
from incident_scout.rules import Rule
from incident_scout.state import Store
from incident_scout.tracker import CheckResult, process

from .conftest import minutes

RULES = {
    "http-5xx": Rule("http-5xx", "logql", query="q", severity="critical"),
    "disk": Rule("disk", "promql", query="d", for_runs=2),
}
NAMES = list(RULES)
ERRORS = Finding("http-5xx", "shop=a", "critical", "a: 55x 5xx", 55)
DISK = Finding("disk", "shop=a", "warning", "a: 91% full", 0.91)


def check(store: Store, at: float, *findings: Finding, errors: dict[str, str] | None = None):
    result = CheckResult(list(findings), NAMES, errors or {})
    return process(store, result, RULES, minutes(at), blind_after=3, resolve_after=2)


def kinds(events: list[Event]) -> list[str]:
    return [event.kind for event in events]


def test_an_incident_is_reported_once_and_resolved_once(store: Store):
    (opened,) = check(store, 0, ERRORS)
    assert (opened.kind, opened.severity, opened.title) == ("opened", "critical", "🔴 http-5xx")
    assert check(store, 5, ERRORS) == []
    assert check(store, 10) == []
    (resolved,) = check(store, 15)
    assert resolved.kind == "resolved"
    assert resolved.group == ERRORS.fingerprint
    assert "lasted 15 min" in resolved.message
    assert store.open_incidents() == []


def test_a_returning_problem_resets_the_resolve_countdown(store: Store):
    check(store, 0, ERRORS)
    assert check(store, 5) == []
    assert check(store, 10, ERRORS) == []
    assert check(store, 15) == []
    assert kinds(check(store, 20)) == ["resolved"]


def test_for_runs_waits_for_consecutive_sightings(store: Store):
    assert check(store, 0, DISK) == []
    assert kinds(check(store, 5, DISK)) == ["opened"]
    assert store.open_incidents()[0]["opened_at"] == minutes(0).isoformat()


def test_a_single_blip_is_forgotten(store: Store):
    assert check(store, 0, DISK) == []
    assert check(store, 5) == []
    assert store.pending() == []
    assert check(store, 10, DISK) == []


def test_a_failing_rule_keeps_its_incidents_open(store: Store):
    check(store, 0, ERRORS)
    for at in (5, 10):
        assert check(store, at, errors={"http-5xx": "timeout"}) == []
    assert kinds(check(store, 15, errors={"http-5xx": "timeout"})) == ["rule_failing"]
    assert len(store.open_incidents()) == 1


def test_a_rule_that_keeps_failing_is_reported_and_its_recovery_too(store: Store):
    assert check(store, 0, errors={"disk": "bad query"}) == []
    assert check(store, 5, errors={"disk": "bad query"}) == []
    (failing,) = check(store, 10, errors={"disk": "bad query"})
    assert (failing.kind, failing.message) == ("rule_failing", "bad query")
    assert kinds(check(store, 15)) == ["rule_recovered"]
    assert store.failing_rules() == []


def test_blind_monitoring_is_reported_once_then_recovery(store: Store):
    check(store, 0, ERRORS)
    everything_down = dict.fromkeys(NAMES, "ConnectError: no route")
    assert check(store, 5, errors=everything_down) == []
    assert check(store, 10, errors=everything_down) == []
    (blind,) = check(store, 15, errors=everything_down)
    assert blind.kind == "blind"
    assert "no route" in blind.message
    assert check(store, 20, errors=everything_down) == []
    assert len(store.open_incidents()) == 1

    events = check(store, 25, ERRORS)
    assert kinds(events) == ["restored"]
    assert store.health()["blind_since"] is None


def test_incidents_of_removed_rules_are_closed(store: Store):
    orphan = Finding("gone", "x", "warning", "old rule", 1)
    check(store, 0, orphan)
    assert kinds(check(store, 5)) == ["resolved"]


def test_status_queries(store: Store):
    check(store, 0, ERRORS)
    check(store, 5)
    check(store, 10)
    assert store.recent_incidents()[0]["summary"] == ERRORS.summary
    assert store.health()["last_ok"] == minutes(10).isoformat()
