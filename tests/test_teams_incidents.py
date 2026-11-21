from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from incident_scout import cli, teams, triage
from incident_scout.config import ConfigError, load_config
from incident_scout.models import Event, Finding, Series
from incident_scout.notify import TeamsNotifier
from incident_scout.state import Store

from .conftest import T0, FakeTelemetry
from .test_cards import content, texts
from .test_cli_investigator import DIAGNOSIS, FakeInvestigator
from .test_history import PACK

DISK = Finding("disk", "shop=a", "critical", "a: 95% full", 0.95, url="https://grafana/disk")
HEADER = teams.Header("Kovian", "Disk full")


class Poster:
    def __init__(self, fail: int = 0) -> None:
        self.cards: list[dict[str, Any]] = []
        self.fail = fail

    def __call__(self, url: str, payload: Mapping[str, Any]) -> None:
        if self.fail:
            self.fail -= 1
            raise RuntimeError("Teams webhook answered 502")
        assert url == "https://teams.example/alerts"
        self.cards.append(dict(payload))


def notifier(store: Store, poster: Poster, **options: Any) -> TeamsNotifier:
    return TeamsNotifier(
        "https://teams.example/alerts",
        store.incident,
        lambda _incident: HEADER,
        "Czech",
        poster=poster,
        **options,
    )


def opened(incident_id: int, finding: Finding = DISK) -> Event:
    return Event(
        "opened",
        finding.severity,
        f"🔴 {finding.rule}",
        finding.summary,
        group=finding.fingerprint,
        url=finding.url,
        incident_id=incident_id,
    )


def diagnosed(incident_id: int) -> Event:
    return Event(
        "diagnosed",
        "critical",
        f"🔎 disk #{incident_id}",
        f"{DIAGNOSIS.likely_cause} [{DIAGNOSIS.confidence}]",
        group=DISK.fingerprint,
        incident_id=incident_id,
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "state.db")


def test_an_opened_incident_without_a_diagnosis(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)

    notifier(store, poster).post([opened(incident_id)])

    (card,) = poster.cards
    lines = texts(content(card)["body"])
    assert lines == [
        "Kovian",
        "Disk full",
        "🔴 Kritický",
        "a: 95% full",
        "poprvé zaznamenáno 3. 11. 13:00",
        f"SCOUT-{incident_id} · disk",
    ]
    actions = content(card)["body"][-2]["actions"]
    assert actions == [
        {"type": "Action.OpenUrl", "title": "Telemetrie", "url": "https://grafana/disk"}
    ]
    assert content(card)["body"][0]["columns"][-1]["items"][0]["style"] == "attention"


def test_a_diagnosis_from_the_same_check_joins_the_opened_card(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)

    notifier(store, poster).post([opened(incident_id), diagnosed(incident_id)])

    (card,) = poster.cards
    lines = texts(content(card)["body"])
    assert lines[lines.index("Diagnóza") :] == [
        "Diagnóza",
        "Shop A is down.",
        "Pravděpodobná příčina",
        "MySQL refuses connections.",
        "Jistota: Vysoká",
        f"SCOUT-{incident_id} · disk",
    ]


def test_a_diagnosis_arriving_alone_is_not_posted(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)

    notifier(store, poster).post([diagnosed(incident_id)])

    assert poster.cards == []


def test_a_resolved_incident_says_how_long_it_lasted(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.resolve(incident_id, T0 + timedelta(minutes=65))
    event = Event(
        "resolved",
        "info",
        "✅ disk resolved",
        "a: 95% full (lasted 1 h 5 min)",
        group=DISK.fingerprint,
        incident_id=incident_id,
    )

    notifier(store, poster).post([event])

    (card,) = poster.cards
    assert texts(content(card)["body"]) == [
        "Kovian",
        "Disk full",
        "✅ Vyřešeno",
        "a: 95% full",
        "trvalo 1 h 5 min · vyřešeno 14:05",
        f"SCOUT-{incident_id} · disk",
    ]
    assert content(card)["fallbackText"] == "✅ disk resolved: a: 95% full (lasted 1 h 5 min)"


def test_only_the_configured_kinds_are_posted_and_storms_are_capped(store: Store):
    poster = Poster()
    events = []
    for shop in "abcdefg":
        finding = Finding("disk", f"shop={shop}", "warning", f"{shop}: 95% full", 0.95)
        incident_id = store.open(finding, T0)
        events += [opened(incident_id, finding), diagnosed(incident_id)]
    grew = Event("grew", "warning", "🆕 disk #1", "new: x", group="disk|shop=a", incident_id=1)

    notifier(store, poster).post([*events, grew], max_events=3)

    first, second, overflow = (texts(content(card)["body"]) for card in poster.cards)
    assert first[3] == "a: 95% full"
    assert second[3] == "b: 95% full"
    assert overflow == ["… and 5 more", "🟠 Varování", "Run `scout status` for the full list."]


def test_a_failing_webhook_is_logged_and_the_next_card_still_goes(
    store: Store, capsys: pytest.CaptureFixture[str]
):
    poster = Poster(fail=1)
    first = store.open(DISK, T0)
    second = store.open(Finding("disk", "shop=b", "warning", "b: 97% full", 0.97), T0)

    notifier(store, poster).post([opened(first), opened(second)])

    assert len(poster.cards) == 1
    assert "notifier TeamsNotifier failed: Teams webhook answered 502" in capsys.readouterr().err


def test_long_texts_are_clipped_and_the_logo_dropped_to_fit(
    store: Store, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    logo = tmp_path / "logo.png"
    logo.write_bytes(os.urandom(17 * 1024))
    poster = Poster()
    huge = Finding("disk", "shop=a", "critical", "Přetečení disku " * 2000, 0.95)
    incident_id = store.open(huge, T0)
    long_cause = "Příčina " * 2000
    store.save_diagnosis(
        incident_id, json.dumps({**json.loads(DIAGNOSIS.to_json()), "likely_cause": long_cause}), T0
    )
    header = teams.Header("Kovian", "Disk full", teams.logo(str(logo)))
    notifier_with_logo = TeamsNotifier(
        "https://teams.example/alerts", store.incident, lambda _row: header, "Czech", poster=poster
    )

    notifier_with_logo.post([opened(incident_id, huge), diagnosed(incident_id)])

    (card,) = poster.cards
    assert teams.card_bytes(card) <= teams.CARD_MAX_BYTES
    assert "Image" not in json.dumps(card)
    lines = texts(content(card)["body"])
    assert lines[3].endswith("…")
    assert len(lines[3]) == teams.SUMMARY_MAX_CHARS
    assert any(line.endswith("…") and line.startswith("Příčina") for line in lines)
    assert "logo left out" in capsys.readouterr().err


CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom", vars: {{shop: kovian}}}}
notify:
  desktop: false
  teams_url: ${{TEAMS_ALERTS_URL}}
{kinds}
investigator: {{model: tiny, language: Czech}}
rules:
  - {{name: disk, kind: promql, query: 'disk > 0.9', severity: critical, title: Disk full}}
"""


def write_config(tmp_path: Path, kinds: str = "") -> Path:
    (tmp_path / ".env").write_text("TEAMS_ALERTS_URL=https://teams.example/alerts\n")
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db", kinds=kinds))
    return path


def test_teams_settings_come_from_the_env_next_to_the_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("TEAMS_ALERTS_URL", raising=False)
    config = load_config(write_config(tmp_path))
    assert config.notify.teams_url == "https://teams.example/alerts"
    assert config.notify.teams_kinds == ("opened", "resolved")

    config = load_config(write_config(tmp_path, "  teams_kinds: [opened, resolved, blind]"))
    assert config.notify.teams_kinds == ("opened", "resolved", "blind")


@pytest.mark.parametrize(
    ("kinds", "message"),
    [
        ("teams_kinds: opened", "must be a list"),
        ("teams_kinds: [opened, exploded]", "unknown exploded"),
        ("teams_kinds: [opened, diagnosed]", "joins `opened`"),
    ],
)
def test_teams_kinds_are_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kinds: str, message: str
):
    monkeypatch.delenv("TEAMS_ALERTS_URL", raising=False)
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(tmp_path, f"  {kinds}"))


def test_a_check_posts_one_card_with_the_diagnosis_then_one_when_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("TEAMS_ALERTS_URL", raising=False)
    path = write_config(tmp_path)
    telemetry = FakeTelemetry(metrics={"disk > 0.9": [Series({"shop": "a"}, [(0.0, 0.95)])]})
    posts: list[dict[str, Any]] = []
    monkeypatch.setattr(cli, "build_telemetry", lambda _source: telemetry)
    monkeypatch.setattr(cli, "_push_notifiers", lambda _config: [])
    monkeypatch.setattr(cli, "_incident_pack", lambda _config, _row: PACK)
    monkeypatch.setattr(triage, "investigator", lambda _c, _m=None: FakeInvestigator())
    monkeypatch.setattr(teams, "post", lambda _url, payload: posts.append(dict(payload)))

    assert cli.main(["--config", str(path), "check"]) == 0
    (card,) = posts
    lines = texts(content(card)["body"])
    assert lines[:3] == ["Kovian", "Disk full", "🔴 Kritický"]
    assert "MySQL refuses connections." in lines

    telemetry.metrics.clear()
    for _ in range(2):
        assert cli.main(["--config", str(path), "check"]) == 0
    assert len(posts) == 2
    assert texts(content(posts[1])["body"])[2] == "✅ Vyřešeno"
