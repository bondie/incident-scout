from __future__ import annotations

import json
from pathlib import Path

import pytest

from incident_scout import cli, triage
from incident_scout.config import ConfigError, load_config
from incident_scout.evidence import EvidencePack, Section
from incident_scout.investigator import Diagnosis, InvestigationError
from incident_scout.models import Event, Finding
from incident_scout.state import Store

from .conftest import T0

CASES = Path(__file__).parents[1] / "eval" / "cases"
CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom"}}
vars: {{fleet: 'shop=~"prod-.*"'}}
notify: {{desktop: false}}
investigator:
  model: tiny
  language: Czech
  max_per_hour: 1
  precedents_command: ['~/bin/tp', search]
  precedents_from: Top errors
  evidence:
    - {{name: Probes, kind: promql, query: 'probe_success{{$fleet}}'}}
    - {{name: Top errors, kind: logql_top, query: 'topk(3, x{{shop="$shop"}} [$window])'}}
rules:
  - {{name: disk, kind: promql, query: 'disk > 0.9'}}
"""
DIAGNOSIS = Diagnosis(
    "Shop A is down.",
    "single_shop",
    "dependency",
    "MySQL refuses connections.",
    "high",
    ["SQLSTATE[HY000] [2002]"],
    ["Restart MySQL"],
    model="tiny",
    seconds=2.0,
)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db"))
    return path


class FakeInvestigator:
    def __init__(self, fail: bool = False) -> None:
        self.packs: list[EvidencePack] = []
        self.fail = fail
        self.unloaded = False

    def diagnose(self, pack: EvidencePack) -> Diagnosis:
        if self.fail:
            raise InvestigationError("model crashed")
        self.packs.append(pack)
        return DIAGNOSIS

    def warm_up(self) -> None:
        return None

    def unload(self) -> None:
        self.unloaded = True


def saved_pack(tmp_path: Path) -> Path:
    pack = EvidencePack("disk", "warning", "a: 95%", {"shop": "a"}, T0.timestamp(), 0, 1)
    pack.sections.append(Section("Top errors", ["  12x  message=No space left"]))
    path = tmp_path / "pack.json"
    path.write_text(pack.to_json())
    return path


def test_investigator_config_is_parsed(config_path: Path):
    settings = load_config(config_path).investigator
    assert settings is not None
    assert settings.evidence[0].query == 'probe_success{shop=~"prod-.*"}'
    assert "$shop" in settings.evidence[1].query
    assert settings.precedents_command[0] == str(Path.home() / "bin/tp")


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        ("investigator: {language: Czech}", "model is required"),
        ("investigator: {model: m, evidence: [{name: a, kind: sql, query: x}]}", "kind must be"),
    ],
)
def test_investigator_config_errors(tmp_path: Path, snippet: str, message: str):
    path = tmp_path / "config.yaml"
    path.write_text(snippet)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_investigate_a_saved_pack(
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    fake = FakeInvestigator()
    monkeypatch.setattr(triage, "investigator", lambda _config, _model=None: fake)
    args = ["--config", str(config_path), "investigate", "--pack", str(saved_pack(tmp_path))]
    assert cli.main([*args, "--show-pack"]) == 0
    out = capsys.readouterr().out
    assert "## Top errors" in out
    assert "cause: MySQL refuses connections." in out
    assert fake.packs[0].summary == "a: 95%"


def test_investigate_needs_a_target(config_path: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(["--config", str(config_path), "investigate"]) == 2
    assert "Give --incident" in capsys.readouterr().err
    assert cli.main(["--config", str(config_path), "investigate", "--incident", "7"]) == 1


def test_investigate_reports_model_failures(
    config_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    monkeypatch.setattr(triage, "investigator", lambda _c, _m=None: FakeInvestigator(fail=True))
    args = ["--config", str(config_path), "investigate", "--pack", str(saved_pack(tmp_path))]
    assert cli.main(args) == 1
    assert "model crashed" in capsys.readouterr().err


def test_new_incidents_are_diagnosed_within_the_hourly_budget(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    config = load_config(config_path)
    store = Store(config.state_path)
    fake = FakeInvestigator()
    monkeypatch.setattr(triage, "investigator", lambda _config, _model=None: fake)
    monkeypatch.setattr(cli, "_incident_pack", lambda _config, row: saved_pack_obj(row))
    monkeypatch.setattr(cli, "_push_notifiers", lambda _config: [])
    first = Finding("disk", "shop=a", "warning", "a: 95%", 0.95)
    second = Finding("disk", "shop=b", "warning", "b: 97%", 0.97)
    events = []
    for finding in (first, second):
        store.open(finding, T0)
        events.append(Event("opened", "warning", "disk", finding.summary, finding.fingerprint))
    cli._investigate_new(config, store, events, T0)
    out = capsys.readouterr()
    assert "diagnosed" in out.out
    assert "hourly budget" in out.err
    row = store.open_incident(first.fingerprint)
    assert row is not None
    assert json.loads(row["diagnosis"])["likely_cause"] == "MySQL refuses connections."
    assert store.open_incident(second.fingerprint)["diagnosis"] is None  # type: ignore[index]


def saved_pack_obj(row: object) -> EvidencePack:
    return EvidencePack("disk", "warning", "a: 95%", {"shop": "a"}, T0.timestamp(), 0, 1)


def test_eval_and_report_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    fake = FakeInvestigator()
    monkeypatch.setattr(cli, "OllamaInvestigator", lambda **_kwargs: fake)
    out = tmp_path / "results.json"
    case = CASES / "database-down.yaml"
    assert (
        cli.main(
            [
                "--config",
                str(tmp_path / "none.yaml"),
                "eval",
                str(case),
                "--models",
                "tiny",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    printed = capsys.readouterr().out
    assert "| `tiny` | 1.00 |" in printed
    assert fake.unloaded
    rows = json.loads(out.read_text())
    assert rows[0]["case"] == "database-down"

    assert cli.main(["report", str(out), "--cases", str(case)]) == 0
    assert "| database-down | CSKG |" in capsys.readouterr().out


def test_command_precedents_formats_ticket_precedent_output():
    import sys

    results = [
        {
            "key": "DB-1",
            "title": "MySQL down",
            "status": "Done",
            "time_spent_hours": 2,
            "snippet": "restarted\n the  server",
        },
        {"key": "DB-2", "title": "Slow", "status": "Closed", "resolution": "Fixed"},
    ]
    script = f"import json; print(json.dumps({results!r}))"
    find = triage.command_precedents([sys.executable, "-c", script])
    assert find("query") == [
        "DB-1: MySQL down [Done, 2 h] restarted the server",
        "DB-2: Slow [Closed Fixed] ",
    ]
    empty = triage.command_precedents([sys.executable, "-c", "print('[]')"])
    assert empty("query") == ["(no similar tickets)"]


def test_gather_uses_configured_evidence(config_path: Path, monkeypatch: pytest.MonkeyPatch):
    from .conftest import FakeTelemetry

    monkeypatch.setattr(triage, "build_telemetry", lambda _source: FakeTelemetry())
    monkeypatch.setattr(triage, "command_precedents", lambda _cmd: lambda _text: ["DB-1"])
    import asyncio

    pack = asyncio.run(
        triage.gather(load_config(config_path), "disk", "warning", "a", {"shop": "a"}, 0.0)
    )
    assert [s.name for s in pack.sections] == ["Probes", "Top errors", "Similar past tickets"]
    assert triage.started_at("2026-11-03T12:00:00+00:00") == T0.timestamp()
    assert triage.investigator(load_config(config_path), "other").model == "other"


def test_triage_requires_the_investigator_section(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("rules: []\n")
    with pytest.raises(ConfigError, match="investigator"):
        triage.investigator(load_config(path))
