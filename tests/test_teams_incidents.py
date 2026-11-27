from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from incident_scout import cli, teams, triage
from incident_scout.config import ConfigError, load_config
from incident_scout.models import Event, Finding, Series
from incident_scout.notify import TeamsNotifier
from incident_scout.proposal import Proposal
from incident_scout.state import Store

from .conftest import T0, FakeTelemetry
from .test_cards import (
    card_config,
    content,
    image,
    marker,
    message,
    meta,
    moment,
    oom,
    orchesty_config,
    runs,
    stats,
    status,
    title,
)
from .test_cli_investigator import DIAGNOSIS, FakeInvestigator
from .test_history import PACK
from .test_tickets import PROPOSAL

DISK = Finding("disk", "shop=a", "critical", "a: 95% full", 0.95, url="https://grafana/disk")
HEADER = teams.Header("Kovian", "Disk full", key="a")


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


def notes(card: dict[str, Any]) -> list[str]:
    """The small lines under the card's row, the cause among them."""
    return [item["text"] for item in content(card)["body"][1:] if item["type"] == "TextBlock"]


def buttons(card: dict[str, Any]) -> list[dict[str, Any]]:
    found = [item for item in content(card)["body"] if item["type"] == "ActionSet"]
    return [action for item in found for action in item["actions"]]


def test_an_opened_incident_without_a_diagnosis(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)

    notifier(store, poster).post([opened(incident_id)])

    (card,) = poster.cards
    assert title(card) == "[Disk full](https://grafana/disk)"
    assert message(card) == "95% full"
    assert marker(card)["color"] == "Attention"
    assert meta(card) == f"SCOUT-{incident_id} | Kritický | Kovian | disk"
    assert status(card) == ("Kritický", "Attention")
    assert stats(card) == [("Začátek", *moment(T0))]
    assert notes(card) == []
    assert buttons(card) == [
        {"type": "Action.OpenUrl", "title": "Telemetrie", "url": "https://grafana/disk"}
    ]
    assert content(card)["fallbackText"] == "🔴 disk: a: 95% full"


def test_an_incident_card_has_no_stripe_boxes_or_badges(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)

    notifier(store, poster).post([opened(incident_id), diagnosed(incident_id)])

    shown = json.dumps(poster.cards[0])
    assert '"Container"' not in shown
    assert '"style"' not in shown
    assert '"bleed"' not in shown


def test_records_are_counted_from_the_incident_or_its_summary(store: Store):
    poster = Poster()
    named = Finding(
        "import",
        "type=customer",
        "warning",
        "a: import failed (2×: C1, C2) – Entity not found",
        members=("C1", "C2", "C3"),
    )
    counted = Finding("orders", "shop=a", "warning", "a: order failed (4×: O1)")
    plain = Finding("http", "shop=a", "warning", "a: 37x HTTP 5xx za 5 min")
    ids = [store.open(finding, T0) for finding in (named, counted, plain)]

    notifier(store, poster).post(
        [opened(i, finding) for i, finding in zip(ids, (named, counted, plain), strict=True)]
    )

    first, second, third = poster.cards
    assert stats(first)[1] == ("Záznamy", "3", "")
    assert stats(second)[1] == ("Záznamy", "4", "")
    assert [label for label, _value, _under in stats(third)] == ["Začátek"]
    assert status(first) == ("Varování", "Warning")


def test_a_diagnosis_from_the_same_check_joins_the_opened_card(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)

    notifier(store, poster).post([opened(incident_id), diagnosed(incident_id)])

    (card,) = poster.cards
    assert notes(card) == ["Příčina: MySQL refuses connections. (jistota vysoká)"]
    assert content(card)["body"][1]["size"] == "Small"
    assert content(card)["body"][-1]["type"] == "ActionSet"


def test_a_diagnosis_without_a_cause_shows_its_summary(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    vague = json.dumps({**json.loads(DIAGNOSIS.to_json()), "likely_cause": "", "confidence": ""})
    store.save_diagnosis(incident_id, vague, T0)

    notifier(store, poster).post([opened(incident_id), diagnosed(incident_id)])

    assert notes(poster.cards[0]) == ["Příčina: Shop A is down."]


def test_a_diagnosis_arriving_alone_is_not_posted(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)

    notifier(store, poster).post([diagnosed(incident_id)])

    assert poster.cards == []


def test_a_resolved_incident_says_how_long_it_lasted(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)
    ended = T0 + timedelta(minutes=65)
    store.resolve(incident_id, ended)
    event = Event(
        "resolved",
        "info",
        "✅ disk resolved",
        "a: 95% full (lasted 1 h 5 min)",
        group=DISK.fingerprint,
        incident_id=incident_id,
    )

    notifier(store, poster).post([event, diagnosed(incident_id)])

    (card,) = poster.cards
    assert title(card) == "Disk full"
    assert message(card) == "95% full"
    assert meta(card) == f"SCOUT-{incident_id} | Vyřešeno | Kovian | disk"
    assert status(card) == ("Vyřešeno", "Good")
    assert stats(card) == [("Trvání", "1 h 5 min", ""), ("Konec", *moment(ended))]
    assert notes(card) == []
    assert buttons(card) == []
    assert content(card)["fallbackText"] == "✅ disk resolved: a: 95% full (lasted 1 h 5 min)"


def test_without_a_rule_title_the_headline_names_the_problem(store: Store):
    poster = Poster()
    finding = Finding("disk", "shop=a", "warning", "a: disk full (3 chyb za 2 h)", 3.0)
    incident_id = store.open(finding, T0)
    untitled = TeamsNotifier(
        "https://teams.example/alerts",
        store.incident,
        lambda _row: teams.Header("Kovian", "", key="a"),
        "Czech",
        poster=poster,
    )

    untitled.post([opened(incident_id, finding)])

    assert (title(poster.cards[0]), message(poster.cards[0])) == ("disk full", "3 chyb za 2 h")


def test_the_title_links_to_the_telemetry_with_brackets_escaped(store: Store):
    poster = Poster()
    url = "https://kibana/app/discover#/?_g=(time:(from:now-15m))&q=a b"
    finding = Finding("disk", "shop=a", "warning", "a: full", 1.0, url=url)
    incident_id = store.open(finding, T0)
    bracketed = TeamsNotifier(
        "https://teams.example/alerts",
        store.incident,
        lambda _row: teams.Header("Kovian", "Import [ERP] (KARAT)", key="a"),
        "Czech",
        poster=poster,
    )

    bracketed.post([opened(incident_id, finding)])

    (card,) = poster.cards
    assert title(card) == (
        "[Import \\[ERP\\] \\(KARAT\\)]"
        "(https://kibana/app/discover#/?_g=%28time:%28from:now-15m%29%29&q=a%20b)"
    )
    assert buttons(card)[0]["url"] == url


@pytest.mark.parametrize(
    ("summary", "shops", "expected"),
    [
        (
            "prod-hetzner-albra: ERP customer se nepropsal na e-shop "
            "(1×: 193CEE5D-4E57-4B9E-5715-802A0BE114F9) – Entity not found",
            ("prod-hetzner-albra", "Albra"),
            (
                "ERP customer se nepropsal na e-shop",
                "1×: 193CEE5D-4E57-4B9E-5715-802A0BE114F9 – Entity not found",
            ),
        ),
        (
            "kovian: Orchesty nestahuje data z KARATu (3 chyb za 2 h)",
            ("kovian", "Kovian"),
            ("Orchesty nestahuje data z KARATu", "3 chyb za 2 h"),
        ),
        (
            "Orchesty orchesty-haspl-prod: kontejner detector spadl na paměť (OOMKilled)",
            ("orchesty", "Orchesty"),
            ("Orchesty orchesty-haspl-prod: kontejner detector spadl na paměť", "OOMKilled"),
        ),
        (
            "Orchesty: RAM nodu n1 obsazená na 95%",
            ("orchesty", "Orchesty"),
            ("RAM nodu n1 obsazená na 95%", ""),
        ),
        ("haspl: 37x HTTP 5xx za 5 min", ("haspl", "Hašpl"), ("37x HTTP 5xx za 5 min", "")),
        (
            "kovian: TLS karat.kovian.sk:29092 platí do 2026-11-20 23:59:59 UTC (-0.4 dní)",
            ("kovian", "Kovian"),
            ("TLS karat.kovian.sk:29092 platí do 2026-11-20 23:59:59 UTC", "-0.4 dní"),
        ),
        ("Kovian: web neodpovídá", ("kovian", "Kovian"), ("web neodpovídá", "")),
        ("other: disk full", ("kovian", "Kovian"), ("other: disk full", "")),
        ("(1×) only a detail", (), ("(1×) only a detail", "")),
    ],
)
def test_the_headline_drops_the_shop_and_moves_brackets_to_the_detail(
    summary: str, shops: tuple[str, ...], expected: tuple[str, str]
):
    assert teams.headline(summary, shops) == expected


def test_a_long_detail_is_clipped(store: Store):
    poster = Poster()
    long = Finding("disk", "shop=a", "warning", "a: disk full (" + "x" * 500 + ")")
    notifier(store, poster).post([opened(store.open(long, T0), long)])
    shown = message(poster.cards[0])
    assert (len(shown), shown[-1]) == (teams.DETAIL_MAX_CHARS, "…")


def test_english_labels(store: Store):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)
    english = TeamsNotifier(
        "https://teams.example/alerts", store.incident, lambda _row: HEADER, poster=poster
    )
    english.post([opened(incident_id), diagnosed(incident_id)])
    (card,) = poster.cards
    assert meta(card) == f"SCOUT-{incident_id} | Critical | Kovian | disk"
    assert stats(card) == [("Started", *moment(T0))]
    assert notes(card) == ["Cause: MySQL refuses connections. (confidence high)"]
    assert buttons(card)[0]["title"] == "Telemetry"

    store.resolve(incident_id, T0 + timedelta(minutes=5))
    resolved = Event("resolved", "info", "✅ disk", "a: 95% full", "disk", None, incident_id)
    english.post([resolved])
    assert status(poster.cards[1]) == ("Resolved", "Good")
    assert stats(poster.cards[1])[0] == ("Duration", "5 min", "")


def test_only_the_configured_kinds_are_posted_and_storms_are_capped(store: Store):
    poster = Poster()
    events = []
    for shop in "abcdefg":
        finding = Finding("disk", f"shop={shop}", "warning", f"{shop}: 95% full", 0.95)
        incident_id = store.open(finding, T0)
        events += [opened(incident_id, finding), diagnosed(incident_id)]
    grew = Event("grew", "warning", "🆕 disk #1", "new: x", group="disk|shop=a", incident_id=1)

    notifier(store, poster).post([*events, grew], max_events=3)

    first, second, overflow = poster.cards
    assert message(first) == "95% full"
    assert message(second) == "b: 95% full"
    assert (title(overflow), message(overflow)) == (
        "… and 5 more",
        "Run `scout status` for the full list.",
    )
    assert (meta(overflow), stats(overflow)) == ("Varování", [])


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
    store: Store,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
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
    header = teams.Header("Kovian", "Disk full " * 100, teams.logo(str(logo)), "a")
    notifier_with_logo = TeamsNotifier(
        "https://teams.example/alerts", store.incident, lambda _row: header, "Czech", poster=poster
    )
    events = [opened(incident_id, huge), diagnosed(incident_id)]

    notifier_with_logo.post(events)
    monkeypatch.setattr(teams, "CARD_MAX_BYTES", teams.card_bytes(poster.cards[0]) - 1)
    notifier_with_logo.post(events)

    with_logo, plain = poster.cards
    assert image(with_logo) is not None
    assert image(plain) is None
    assert teams.card_bytes(plain) <= teams.CARD_MAX_BYTES
    assert "logo left out" in capsys.readouterr().err
    assert (len(title(plain)), title(plain)[-1]) == (teams.TITLE_MAX_CHARS, "…")
    assert len(message(plain)) == teams.DETAIL_MAX_CHARS
    (cause,) = notes(plain)
    assert cause.startswith("Příčina: Příčina")
    assert "…" in cause
    assert len(cause) < teams.DIAGNOSIS_MAX_CHARS + 40


def test_an_orchesty_incident_names_the_shop_it_hit(tmp_path: Path):
    config = orchesty_config(tmp_path)
    store = Store(config.state_path)
    cards = []
    for namespace in ("orchesty-albra-prod", "orchesty-haspl-prod", "monitoring"):
        incident = store.incident(store.open(oom(namespace), T0))
        assert incident is not None
        event = opened(incident["id"], oom(namespace))
        cards.append(teams.incident_card(event, incident, cli._card_header(config, incident)))
    albra, haspl, cluster = cards
    assert meta(albra) == "SCOUT-1 | Critical | Albra | Orchesty | oom@orchesty"
    assert meta(haspl) == "SCOUT-2 | Critical | Hašpl | Orchesty | oom@orchesty"
    assert meta(cluster) == "SCOUT-3 | Critical | Orchesty | oom@orchesty"
    assert [image(card) is not None for card in cards] == [True, True, False]
    assert (
        message(haspl)
        == "Orchesty orchesty-haspl-prod: kontejner detector spadl na paměť (OOMKilled)"
    )


@pytest.mark.parametrize(
    ("vars_", "message_"),
    [
        ("{shop: orchesty, shop_label: namespace, shop_pattern: '(oops'}", "not a regex"),
        ("{shop: orchesty, shop_label: namespace, shop_pattern: '^orchesty-(.+)$'}", "group"),
        ("{shop: orchesty, shop_pattern: '^(?P<shop>.+)$'}", "needs shop_label"),
    ],
)
def test_a_shop_pattern_is_checked(tmp_path: Path, vars_: str, message_: str):
    path = tmp_path / "config.yaml"
    path.write_text(
        "source: {type: http, prometheus_url: 'http://prom', vars: " + vars_ + "}\n"
        "rules:\n  - {name: oom, kind: promql, query: oom}\n"
    )
    with pytest.raises(ConfigError, match=message_):
        load_config(path)


def test_a_shop_label_without_a_pattern_names_the_shop_as_it_is(tmp_path: Path):
    config = orchesty_config(tmp_path)
    plain = replace(config, rules=[replace(config.rules[0], shop_pattern="")])
    store = Store(config.state_path)
    incident = store.incident(store.open(oom("haspl"), T0))
    assert incident is not None
    header = cli._card_header(plain, incident)
    assert (header.shop, header.key, header.context) == ("Hašpl", "orchesty", "Orchesty")

    (tmp_path / "config.yaml").write_text("shop_aliases: [albra]")
    with pytest.raises(ConfigError, match="shop_aliases must map"):
        load_config(tmp_path / "config.yaml")


def shown_to_people(card: dict[str, Any]) -> dict[str, Any]:
    """The card without the collapsed block for a chat bot, which keeps the text exact."""
    return {**card, "body": [item for item in card["body"] if item.get("id") != "handoff"]}


def test_no_text_on_any_card_starts_like_a_numbered_list(store: Store, tmp_path: Path):
    poster = Poster()
    listy = Finding("disk", "shop=a", "warning", "3. pokus selhal\n4. pokus taky", 1.0)
    incident_id = store.open(listy, T0)
    cause = json.dumps({**json.loads(DIAGNOSIS.to_json()), "likely_cause": "1. krok\n2. krok"})
    store.save_diagnosis(incident_id, cause, T0)
    untitled = TeamsNotifier(
        "https://teams.example/alerts",
        store.incident,
        lambda _row: teams.Header("", "", key="a"),
        "Czech",
        poster=poster,
    )
    untitled.post([opened(incident_id, listy), diagnosed(incident_id)])
    store.resolve(incident_id, T0 + timedelta(hours=1))
    untitled.post([Event("resolved", "info", "✅", "3. x", "disk", None, incident_id)])
    config = card_config(tmp_path)
    proposal = Proposal("existing_ticket", "12. 11.", "5. den padá.", "1. Import", "high", "")
    incident = store.incident(incident_id)
    assert incident is not None
    proposals = [
        cli._card(config, store, incident, proposal, "tok", T0),
        cli._card(
            config, store, incident, replace(proposal, recommendation="create_ticket"), "tok", T0
        ),
    ]

    lines = [
        line
        for card in [*poster.cards, *proposals]
        for text in runs(shown_to_people(content(card)))
        for line in text.splitlines()
    ]
    assert lines
    assert [line for line in lines if re.match(r"\s*\d+\. ", line)] == []


def test_dates_reach_teams_in_the_exact_form_its_date_functions_take(store: Store, tmp_path: Path):
    poster = Poster()
    incident_id = store.open(DISK, T0)
    notifier(store, poster).post([opened(incident_id)])
    store.resolve(incident_id, T0 + timedelta(minutes=5))
    notifier(store, poster).post([Event("resolved", "info", "✅", "x", "disk", None, incident_id)])
    incident = store.incident(incident_id)
    assert incident is not None
    config = card_config(tmp_path)
    proposal_card = cli._card(config, store, incident, PROPOSAL, "tok", T0)

    shown = json.dumps([*poster.cards, proposal_card])
    moments = re.findall(r"\{\{(?:DATE|TIME)\(([^,)]*)", shown)
    assert len(moments) == 6
    exact = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+-]\d\d:\d\d)")
    assert all(exact.fullmatch(moment) for moment in moments)
    assert re.findall(r"\{\{DATE\([^)]*\)\}\}", shown)[0].endswith(", SHORT)}}")


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
    assert (title(card), status(card)) == ("Disk full", ("Kritický", "Attention"))
    assert notes(card) == ["Příčina: MySQL refuses connections. (jistota vysoká)"]

    telemetry.metrics.clear()
    for _ in range(2):
        assert cli.main(["--config", str(path), "check"]) == 0
    assert len(posts) == 2
    assert status(posts[1]) == ("Vyřešeno", "Good")
