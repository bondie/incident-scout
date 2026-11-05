from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from incident_scout import cli, triage
from incident_scout.config import load_config
from incident_scout.evaluation import load_cases, score
from incident_scout.evidence import EvidencePack, Section
from incident_scout.investigator import Diagnosis
from incident_scout.models import Event, Finding
from incident_scout.rules import Rule
from incident_scout.state import Store
from incident_scout.tracker import CheckResult, process

from .conftest import T0, minutes
from .test_cli_investigator import CONFIG, DIAGNOSIS, FakeInvestigator

RULES = {"disk": Rule("disk", "promql", query="d")}
DISK = Finding("disk", "shop=a", "warning", "a: 95% full", 0.95)
PACK = EvidencePack(
    "disk",
    "warning",
    "a: 95% full",
    {"shop": "a"},
    T0.timestamp(),
    T0.timestamp() - 1800,
    T0.timestamp() + 600,
    [Section("Top errors", ["  12x  message=No space left on device"])],
)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db"))
    return path


def check(store: Store, at: float, *findings: Finding, errors: dict[str, str] | None = None):
    result = CheckResult(list(findings), list(RULES), errors or {})
    events = process(store, result, RULES, minutes(at), blind_after=2, resolve_after=1)
    store.record(events, minutes(at))
    return events


def test_old_databases_gain_the_new_columns(tmp_path: Path):
    path = tmp_path / "state.db"
    db = sqlite3.connect(path)
    db.execute(
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, "
        "rule TEXT NOT NULL, severity TEXT NOT NULL, summary TEXT NOT NULL, value REAL, "
        "url TEXT, opened_at TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT, "
        "missed_runs INTEGER NOT NULL DEFAULT 0)"
    )
    db.execute(
        "INSERT INTO incidents (fingerprint, rule, severity, summary, opened_at, last_seen) "
        "VALUES ('disk|shop=a', 'disk', 'warning', 'old', '2026-11-01', '2026-11-01')"
    )
    db.commit()
    db.close()
    row = Store(path).incident(1)
    assert row is not None
    assert row["summary"] == "old"
    assert (row["diagnosis"], row["evidence"], row["review"]) == (None, None, None)


def test_the_timeline_holds_the_incident_and_blindness_while_it_was_open(store: Store):
    (opened,) = check(store, 0, DISK)
    assert opened.incident_id == 1
    blind = {"disk": "connection refused"}
    assert check(store, 5, errors=blind) == []
    assert [e.kind for e in check(store, 10, errors=blind)] == ["blind"]
    assert [e.kind for e in check(store, 15, DISK)] == ["restored"]
    (resolved,) = check(store, 20)
    assert resolved.incident_id == 1
    check(store, 25, errors=blind)
    check(store, 30, errors=blind)  # blind again after the incident: not part of its timeline

    incident = store.incident(1)
    assert incident is not None
    assert [row["kind"] for row in store.timeline(incident)] == [
        "opened",
        "blind",
        "restored",
        "resolved",
    ]


def test_evidence_is_kept_when_the_model_fails(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    config = load_config(config_path)
    store = Store(config.state_path)
    pushed: list[Event] = []
    monkeypatch.setattr(triage, "investigator", lambda _c, _m=None: FakeInvestigator(fail=True))
    monkeypatch.setattr(cli, "_incident_pack", lambda _config, _row: PACK)
    monkeypatch.setattr(cli, "dispatch", lambda _notifiers, events, *_: pushed.extend(events))
    events = check(store, 0, DISK)

    cli._investigate_new(config, store, events, T0)

    incident = store.incident(1)
    assert incident is not None
    assert EvidencePack.from_json(incident["evidence"]) == PACK
    assert incident["diagnosis"] is None
    assert [row["kind"] for row in store.timeline(incident)] == ["opened", "diagnosis_failed"]
    assert pushed == []
    assert "model crashed" in capsys.readouterr().out


def test_a_successful_diagnosis_is_kept_with_its_evidence_and_announced(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
):
    config = load_config(config_path)
    store = Store(config.state_path)
    pushed: list[Event] = []
    monkeypatch.setattr(triage, "investigator", lambda _c, _m=None: FakeInvestigator())
    monkeypatch.setattr(cli, "_incident_pack", lambda _config, _row: PACK)
    monkeypatch.setattr(cli, "dispatch", lambda _notifiers, events, *_: pushed.extend(events))
    monkeypatch.setattr(cli, "_push_notifiers", lambda _config: [])

    cli._investigate_new(config, store, check(store, 0, DISK), T0)

    incident = store.incident(1)
    assert incident is not None
    assert incident["evidence"] is not None
    assert json.loads(incident["diagnosis"])["likely_cause"] == DIAGNOSIS.likely_cause
    (follow_up,) = pushed
    assert follow_up.title == "🔎 disk #1"


def diagnosed_incident(config_path: Path) -> Store:
    store = Store(load_config(config_path).state_path)
    store.open(DISK, T0)
    store.save_evidence(1, PACK.to_json())
    store.save_diagnosis(1, DIAGNOSIS.to_json(), T0)
    return store


def scout(config_path: Path, *args: str) -> int:
    return cli.main(["--config", str(config_path), *args])


def test_review_show_history_and_export_close_the_loop(
    config_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    store = diagnosed_incident(config_path)
    review = [
        "review",
        "1",
        "--verdict",
        "wrong",
        "--cause",
        "Logy zaplnily disk",
        "--category",
        "resources",
        "--keywords",
        "disk, místo",
        "--keywords",
        "log",
    ]
    assert scout(config_path, *review) == 0
    stored = json.loads(store.incident(1)["review"])  # type: ignore[index]
    assert stored["scope"] == "single_shop"  # taken over from the diagnosis
    assert stored["keywords"] == [["disk", "místo"], ["log"]]
    assert stored["model"] == "tiny"

    assert scout(config_path, "show", "1", "--pack") == 0
    shown = capsys.readouterr().out
    assert "still open" in shown
    assert "reviewed" in shown
    assert "cause: MySQL refuses connections." in shown
    assert "keywords: (disk | místo) AND (log)" in shown
    assert "No space left on device" in shown

    assert scout(config_path, "history", "--since", "30d") == 0
    listed = capsys.readouterr().out
    assert "#1" in listed
    assert "(diagnosed, wrong)" in listed

    assert scout(config_path, "export-case", "1", "--out", str(tmp_path)) == 0
    (case,) = load_cases([tmp_path / "incident-1-disk.yaml"])
    assert (case.categories, case.scope) == (("resources",), "single_shop")
    assert case.pack == PACK
    right = Diagnosis(**{**DIAGNOSIS.__dict__, "category": "resources"})
    assert not score(case, right).cause
    fixed = Diagnosis(
        **{
            **right.__dict__,
            "likely_cause": "Logy zaplnily místo na disku.",
            "key_evidence": ["12x No space left on device"],
        }
    )
    assert score(case, fixed).total == 1.0


def test_review_defaults_and_refusals(
    config_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    store = diagnosed_incident(config_path)
    assert scout(config_path, "review", "1", "--verdict", "partial") == 2
    assert "--cause" in capsys.readouterr().err
    assert scout(config_path, "export-case", "1", "--out", str(tmp_path / "x.yaml")) == 1
    assert "a review" in capsys.readouterr().err

    assert scout(config_path, "review", "1", "--verdict", "correct") == 0
    stored = json.loads(store.incident(1)["review"])  # type: ignore[index]
    assert stored["cause"] == DIAGNOSIS.likely_cause
    assert scout(config_path, "export-case", "1", "--out", str(tmp_path / "x.yaml")) == 1
    assert "--keywords" in capsys.readouterr().err

    for command in ("show", "review", "export-case"):
        extra = {"review": ["--verdict", "wrong"], "export-case": ["--out", "x"]}.get(command, [])
        assert scout(config_path, command, "9", *extra) == 1


def test_investigating_a_stored_incident_reuses_its_evidence(
    config_path: Path, monkeypatch: pytest.MonkeyPatch
):
    store = diagnosed_incident(config_path)

    def no_telemetry(_config: object, _row: object) -> EvidencePack:
        raise AssertionError("the stored pack should be used")

    fake = FakeInvestigator()
    monkeypatch.setattr(cli, "_incident_pack", no_telemetry)
    monkeypatch.setattr(triage, "investigator", lambda _c, _m=None: fake)
    assert scout(config_path, "investigate", "--incident", "1") == 0
    assert fake.packs == [PACK]
    incident = store.incident(1)
    assert incident is not None
    assert [row["kind"] for row in store.timeline(incident)] == ["diagnosed"]
