from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from incident_scout import cli, teams, triage
from incident_scout.config import Config, load_config
from incident_scout.models import Finding
from incident_scout.proposal import Proposal
from incident_scout.rules import Rule, evaluate
from incident_scout.state import Store

from .conftest import T0, FakeTelemetry, series
from .test_cli_investigator import DIAGNOSIS
from .test_tickets import ANSWER, PROPOSAL, Calls, actions, calls, page_server, scout

__all__ = ["calls", "page_server"]

CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom", vars: {{shop: kovian{title}}}}}
notify: {{desktop: false}}
investigator: {{model: tiny, language: Czech}}
tickets: {{teams_url: "https://teams.example/hook", recurring_days: 7, port: 8766}}
{logos}
rules:
  - {{name: import, kind: logql, query: 'failed', key_labels: [type],
      title: Import zákazníků z KARATu}}
"""
IMPORT = Finding("import", "type=customer", "warning", "3x import failed", 3.0)


def card_config(tmp_path: Path, logos: str = "", title: str = "") -> Config:
    path = tmp_path / "config.yaml"
    shop_title = f", shop_title: {title}" if title else ""
    path.write_text(CONFIG.format(state=tmp_path / "state.db", logos=logos, title=shop_title))
    return load_config(path)


def content(card: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = card["attachments"][0]["content"]
    return found


def texts(element: Any) -> list[str]:
    """Every TextBlock text in an element tree, in order."""
    if isinstance(element, list):
        return [text for item in element for text in texts(item)]
    if not isinstance(element, dict):
        return []
    own = [element["text"]] if element.get("type") == "TextBlock" else []
    children = [element[key] for key in ("body", "columns", "items") if key in element]
    return own + texts(children)


def badge(card: dict[str, Any]) -> tuple[str, str]:
    container = content(card)["body"][0]["columns"][-1]["items"][0]
    return container["style"], container["items"][0]["text"]


def card_for(config: Config, store: Store, incident_id: int, proposal: Proposal = PROPOSAL):
    incident = store.incident(incident_id)
    assert incident is not None
    return cli._card(config, store, incident, proposal, "tok", T0 + timedelta(hours=1))


def test_the_card_header_names_the_shop_and_problem_with_a_logo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    logo = tmp_path / "kovian.png"
    logo.write_bytes(b"\x89PNG small")
    config = card_config(tmp_path, logos=f"logos: {{kovian: {logo}}}")
    store = Store(config.state_path)
    card = card_for(config, store, store.open(IMPORT, T0))
    image, names, _badge = content(card)["body"][0]["columns"]
    assert image["items"][0]["url"].startswith("data:image/png;base64,")
    assert image["items"][0]["altText"] == "Kovian"
    assert [block["text"] for block in names["items"]] == ["Import zákazníků z KARATu"]
    assert "isSubtle" not in names["items"][0]
    assert content(card)["fallbackText"] == "🎫 SCOUT-1 · Shop A: disk runs full"

    logo.write_bytes(b"x" * 31 * 1024)
    big = card_for(config, store, 1)
    assert len(content(big)["body"][0]["columns"]) == 2
    assert "at most 30 KB" in capsys.readouterr().err

    titled = card_config(tmp_path, title="Kovian.sk")
    plain = card_for(titled, store, 1)
    header = content(plain)["body"][0]["columns"]
    assert [column["items"][0]["type"] for column in header] == ["TextBlock", "Container"]
    assert header[0]["items"][0]["text"] == "Kovian.sk"
    assert teams.logo("https://cdn.example/logo.png") == "https://cdn.example/logo.png"


def test_a_shop_label_names_the_shop_when_the_source_has_no_shop_var(tmp_path: Path):
    logo = tmp_path / "shop-b.jpg"
    logo.write_bytes(b"jpeg")
    config = card_config(tmp_path, logos=f"logos: {{Shop-B: {logo}}}")
    config = replace(config, rules=[Rule("import", "logql", query="q", title="Import")])
    store = Store(config.state_path)
    labelled = Finding(**{**IMPORT.__dict__, "labels": {"shop": "shop-b", "type": "customer"}})
    card = card_for(config, store, store.open(labelled, T0))
    image, names, _badge = content(card)["body"][0]["columns"]
    assert image["items"][0]["url"].startswith("data:image/jpeg;base64,")
    assert image["items"][0]["altText"] == "Shop-b"
    assert [block["text"] for block in names["items"]] == ["Import"]


def test_the_card_counts_records_and_shows_cause_priority_and_id(tmp_path: Path):
    config = card_config(tmp_path)
    store = Store(config.state_path)
    first = Finding(**{**IMPORT.__dict__, "members": ("C1", "C2")})
    incident_id = store.open(first, T0)
    store.touch(incident_id, Finding(**{**IMPORT.__dict__, "members": ("C2", "C3")}), T0)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)
    card = card_for(config, store, incident_id)
    body = content(card)["body"]
    shown = texts(body)
    assert "3 záznamy" in shown
    assert "za 7 dní, 3 dnes" in shown
    assert "Zasažené: C1, C2, C3" in shown
    assert "Vysoká" in shown
    assert "priorita" in shown
    (cause,) = [item for item in body if item.get("style") == "emphasis"]
    assert [block["text"] for block in cause["items"]] == ["Příčina", DIAGNOSIS.likely_cause]
    assert not any(block.get("isSubtle") for block in cause["items"])
    assert body[-1] == {
        "type": "TextBlock",
        "text": "SCOUT-1 · import",
        "size": "Small",
        "isSubtle": True,
        "wrap": True,
    }
    assert badge(card) == ("warning", "⏳ Trvá")


def test_the_card_dates_the_problem_from_its_first_record(tmp_path: Path):
    config = card_config(tmp_path)
    store = Store(config.state_path)
    first = store.open(Finding(**{**IMPORT.__dict__, "members": ("C1",)}), T0)
    store.resolve(first, T0 + timedelta(minutes=10))
    later = T0 + timedelta(minutes=30)
    incident_id = store.open(Finding(**{**IMPORT.__dict__, "members": ("C2",)}), later)
    shown = texts(content(card_for(config, store, incident_id))["body"])
    assert f"od {teams._when(T0.astimezone())}" in shown
    assert f"od {teams._when(later.astimezone())}" not in shown


def test_the_badge_follows_recurrence_growth_and_resolution(tmp_path: Path):
    config = card_config(tmp_path)
    store = Store(config.state_path)
    single = Finding(**{**IMPORT.__dict__, "members": ("C1",)})
    incident_id = store.open(single, T0)
    assert "Zasažené: C1" not in texts(content(card_for(config, store, incident_id)))

    store.touch(
        incident_id, Finding(**{**IMPORT.__dict__, "members": ("C9",)}), T0 + timedelta(minutes=30)
    )
    growing = card_for(config, store, incident_id)
    assert badge(growing) == ("attention", "📈 Přibývá")
    assert "přibývá: +1 za poslední 3 h" in texts(content(growing))

    store.resolve(incident_id, T0 + timedelta(minutes=40))
    store.open(IMPORT, T0 + timedelta(minutes=50))
    assert badge(card_for(config, store, incident_id)) == ("good", "✅ Vyřešeno")
    assert badge(card_for(config, store, 2)) == ("attention", "🔁 Opakuje se, přibývá")


def test_store_keeps_when_each_record_was_first_seen(store: Store):
    incident_id = store.open(Finding(**{**IMPORT.__dict__, "members": ("C1",)}), T0)
    store.touch(
        incident_id,
        Finding(**{**IMPORT.__dict__, "members": ("C2", "C1")}),
        T0 + timedelta(hours=1),
    )
    incident = store.incident(incident_id)
    assert incident is not None
    assert json.loads(incident["members"]) == {
        "C1": "2026-11-03T12:00:00+00:00",
        "C2": "2026-11-03T13:00:00+00:00",
    }


def answer(**changes: str) -> Proposal:
    return Proposal(**{**ANSWER, **changes})


@pytest.fixture
def drafts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The model answers with the next proposal; Teams posts are recorded."""
    posts: list[dict[str, Any]] = []
    monkeypatch.setattr(teams, "post", lambda _url, payload: posts.append(payload))
    return posts


def test_a_no_ticket_proposal_stays_out_of_teams_and_needs_no_decision(
    tmp_path: Path, drafts: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
):
    config = card_config(tmp_path)
    store = Store(config.state_path)
    incident_id = store.open(IMPORT, T0)
    quiet = answer(recommendation="no_ticket", reason="A one-off spike.")
    monkeypatch.setattr(cli, "draft", lambda *_: quiet)
    incident = store.incident(incident_id)
    assert incident is not None
    cli._make_proposal(config, store, incident, T0, send=True)
    assert drafts == []
    incident = store.incident(incident_id)
    assert incident is not None
    assert Proposal.from_json(incident["proposal"]) == quiet
    assert (incident["decision"], incident["decision_reason"]) == ("rejected", "A one-off spike.")
    assert [row["kind"] for row in store.timeline(incident)] == ["proposed", "rejected"]


def test_an_existing_ticket_gets_a_compact_card_and_covers_the_next_incidents(
    tmp_path: Path, drafts: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
):
    config = card_config(tmp_path)
    store = Store(config.state_path)
    incident_id = store.open(IMPORT, T0)
    known = answer(recommendation="existing_ticket", existing_ticket="KOVIAN-SCOUT-4")
    monkeypatch.setattr(cli, "draft", lambda *_: known)
    incident = store.incident(incident_id)
    assert incident is not None
    cli._make_proposal(config, store, incident, T0, send=True)
    (card,) = drafts
    assert [action["title"] for action in actions(content(card))] == ["Detail"]
    assert "Už je v ticketu: KOVIAN-SCOUT-4" in texts(content(card))
    incident = store.incident(incident_id)
    assert incident is not None
    assert (incident["decision"], incident["decision_ticket"]) == ("rejected", "KOVIAN-SCOUT-4")

    store.resolve(incident_id, T0 + timedelta(minutes=10))
    later = store.open(IMPORT, T0 + timedelta(hours=1))
    cli._propose_due(config, store, T0 + timedelta(hours=2))
    assert len(drafts) == 1
    assert store.has_event(later, "covered")


def test_the_reject_form_keeps_a_reason_and_ticket(page_server: tuple[str, Store]):
    base, store = page_server
    incident_id = store.open(IMPORT, T0)
    store.save_proposal(incident_id, PROPOSAL.to_json(), "secret-token", T0)
    root = f"{base}/incidents/{incident_id}"
    detail = httpx.get(f"{root}?t=secret-token")
    assert '<form id="reject" method="post"' in detail.text
    assert "SCOUT-1 · import" in detail.text

    form = {"t": "guess", "reason": "Known", "ticket": "SHOP-12"}
    assert httpx.post(f"{root}/reject", data=form).status_code == 403
    rejected = httpx.post(f"{root}/reject", data={**form, "t": "secret-token"})
    assert rejected.status_code == 200
    assert "Ticket: SHOP-12 · Důvod: Known" in rejected.text
    incident = store.incident(incident_id)
    assert incident is not None
    assert (incident["decision"], incident["decision_reason"], incident["decision_ticket"]) == (
        "rejected",
        "Known",
        "SHOP-12",
    )


def test_commands_take_the_id_from_the_card(
    tmp_path: Path, calls: Calls, capsys: pytest.CaptureFixture[str]
):
    config = card_config(tmp_path)
    path = tmp_path / "config.yaml"
    store = Store(config.state_path)
    incident_id = store.open(IMPORT, T0)
    store.save_proposal(incident_id, PROPOSAL.to_json(), "tok", T0)
    assert scout(path, "decide", "SCOUT-1", "approve") == 0
    assert scout(path, "show", "scout-1") == 0
    assert capsys.readouterr().out.startswith("SCOUT-1: approved\nSCOUT-1 import (warning)")
    assert scout(path, "history", "--since", "3650d") == 0
    assert "  SCOUT-1    " in capsys.readouterr().out

    assert scout(path, "propose", "SCOUT-1", "--no-send", "--card") == 0
    printed = json.loads(capsys.readouterr().out)
    assert content(printed)["body"][-1]["text"] == "SCOUT-1 · import"
    assert calls.drafts == []
    assert calls.posts == []
    with pytest.raises(SystemExit):
        scout(path, "show", "SCOUT-x")
    assert incident_id == 1


def test_labels_with_commas_reach_the_evidence_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    rule = Rule("import", "logql", query="q", key_labels=("type", "reason"))
    reason = "Name, surname = missing"
    telemetry = FakeTelemetry(logs={"q": [series(1, type="customer", reason=reason, code="C1")]})
    (finding,) = asyncio.run(evaluate(rule, telemetry))
    config = card_config(tmp_path)
    store = Store(config.state_path)
    incident = store.incident(store.open(finding, T0))
    assert incident is not None
    seen: list[dict[str, str]] = []

    async def gather(_config: Any, _rule: str, _sev: str, _sum: str, labels: Any, _at: float):
        seen.append(dict(labels))
        raise RuntimeError("stop")

    monkeypatch.setattr(triage, "gather", gather)
    with pytest.raises(RuntimeError, match="stop"):
        cli._incident_pack(config, incident)
    assert seen == [{"type": "customer", "reason": reason}]
