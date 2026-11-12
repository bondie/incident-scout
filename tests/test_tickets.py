from __future__ import annotations

import json
import plistlib
import threading
from collections.abc import Iterator
from datetime import timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest

from incident_scout import cli, launchd, server, teams, triage
from incident_scout.config import ConfigError, load_config
from incident_scout.investigator import InvestigationError, OllamaInvestigator
from incident_scout.models import Finding
from incident_scout.proposal import Proposal, brief, draft, parse_proposal
from incident_scout.state import Store

from .conftest import T0
from .test_cli_investigator import DIAGNOSIS
from .test_history import PACK

ANSWER: dict[str, Any] = {
    "recommendation": "create_ticket",
    "existing_ticket": "",
    "reason": "Disk fills up again every day.",
    "title": "Shop A: disk runs full",
    "priority": "high",
    "description": "h3. What happens\n* Disk at 95%",
}
PROPOSAL = Proposal(**ANSWER, model="tiny", seconds=3.0)
DISK = Finding("disk", "shop=a", "warning", "a: 95% full", 0.95, url="https://grafana/disk")
CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom"}}
notify: {{desktop: false}}
investigator: {{model: tiny, language: Czech}}
tickets: {{teams_url: "https://teams.example/hook", after_minutes: 30, recurring: 3,
          max_per_hour: 2, port: 8766}}
rules:
  - {{name: disk, kind: promql, query: 'disk > 0.9'}}
"""


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db"))
    return path


class Calls:
    def __init__(self) -> None:
        self.drafts: list[str] = []
        self.posts: list[dict[str, Any]] = []


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> Calls:
    """Fake model and Teams: drafting records the brief, posting records the card."""
    seen = Calls()

    def fake_draft(_investigator: object, incident: Any, history: Any, now: Any) -> Proposal:
        seen.drafts.append(brief(incident, history, now))
        return PROPOSAL

    monkeypatch.setattr(cli, "draft", fake_draft)
    monkeypatch.setattr(teams, "post", lambda _url, payload: seen.posts.append(payload))
    return seen


def opened(store: Store, minutes_ago: float, now: Any = T0) -> int:
    return store.open(DISK, now - timedelta(minutes=minutes_ago))


def test_parse_proposal_is_lenient_about_enums_and_trims():
    data = {
        **ANSWER,
        "recommendation": ["Existing_Ticket"],
        "existing_ticket": " DB-7 ",
        "title": "x" * 200,
    }
    proposal = parse_proposal(json.dumps(data), "m", 2.44)
    assert proposal.recommendation == "existing_ticket"
    assert proposal.existing_ticket == "DB-7"
    assert len(proposal.title) == 120
    assert proposal.seconds == 2.4
    assert Proposal.from_json(proposal.to_json()) == proposal
    with pytest.raises(InvestigationError, match="left out"):
        parse_proposal('{"title": "x"}', "m")


def test_the_brief_holds_history_diagnosis_and_evidence(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    for days_ago in (3, 2):
        earlier = store.open(DISK, T0 - timedelta(days=days_ago))
        store.resolve(earlier, T0 - timedelta(days=days_ago) + timedelta(minutes=40))
    current = opened(store, 20)
    store.save_diagnosis(current, DIAGNOSIS.to_json(), T0)
    store.save_evidence(current, PACK.to_json())
    incident = store.incident(current)
    assert incident is not None
    text = brief(incident, store.same_problem(DISK.fingerprint, T0 - timedelta(days=7)), T0)
    assert "open for 20 min" in text
    assert "40 min: a: 95% full" in text
    assert "total: 3 incidents including this one" in text
    assert "likely cause: MySQL refuses connections." in text
    assert "No space left on device" in text


def test_a_wrong_review_replaces_the_diagnosis_in_the_brief(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    current = opened(store, 20)
    store.save_diagnosis(current, DIAGNOSIS.to_json(), T0)
    review: dict[str, Any] = {
        "verdict": "wrong",
        "cause": "Logs filled the disk.",
        "category": "resources",
        "scope": "single_shop",
        "keywords": [],
        "note": "rotation was off",
        "model": "tiny",
    }
    store.save_review(current, json.dumps(review), T0)
    incident = store.incident(current)
    assert incident is not None
    text = brief(incident, [], T0)
    assert "real cause: Logs filled the disk." in text
    assert "note: rotation was off" in text
    assert "MySQL refuses connections." not in text


def test_a_partial_review_comes_with_the_diagnosis(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    current = opened(store, 20)
    store.save_diagnosis(current, DIAGNOSIS.to_json(), T0)
    review: dict[str, Any] = {
        "verdict": "partial",
        "cause": "MySQL refused connections after a full disk.",
        "category": "resources",
        "scope": "single_shop",
        "keywords": [],
        "note": None,
    }
    store.save_review(current, json.dumps(review), T0)
    incident = store.incident(current)
    assert incident is not None
    text = brief(incident, [], T0)
    assert "verdict on the diagnosis: partial" in text
    assert "likely cause: MySQL refuses connections." in text
    assert "note:" not in text


def test_draft_asks_the_model_with_the_proposal_schema(tmp_path: Path):
    requests: list[dict[str, Any]] = []

    def reply(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"message": {"content": json.dumps(ANSWER)}})

    store = Store(tmp_path / "state.db")
    incident = store.incident(opened(store, 5))
    assert incident is not None
    model = OllamaInvestigator("tiny", language="Czech", transport=httpx.MockTransport(reply))
    proposal = draft(model, incident, [incident], T0)
    assert proposal.title == "Shop A: disk runs full"
    assert requests[0]["format"]["properties"]["recommendation"]["enum"][0] == "create_ticket"
    assert "Czech" in requests[0]["messages"][0]["content"]
    assert "(no earlier incidents)" in requests[0]["messages"][1]["content"]


def test_proposals_wait_for_lasting_or_recurring_problems(config_path: Path, calls: Calls):
    config = load_config(config_path)
    store = Store(config.state_path)
    fresh = opened(store, 10)
    cli._propose_due(config, store, T0)
    assert calls.drafts == []

    cli._propose_due(config, store, T0 + timedelta(minutes=25))
    incident = store.incident(fresh)
    assert incident is not None
    assert Proposal.from_json(incident["proposal"]) == PROPOSAL
    (card,) = calls.posts
    content = card["attachments"][0]["content"]
    assert content["body"][0]["text"] == "🎫 Navrhuji založit ticket"
    approve = content["actions"][0]["url"]
    assert (
        approve == f"http://127.0.0.1:8766/incidents/{fresh}/approve?t={incident['proposal_token']}"
    )
    assert content["actions"][-1]["url"] == "https://grafana/disk"
    assert [row["kind"] for row in store.timeline(incident)] == ["proposed"]

    cli._propose_due(config, store, T0 + timedelta(minutes=60))
    assert len(calls.drafts) == 1  # once per incident


def test_a_recurring_problem_is_proposed_once(config_path: Path, calls: Calls):
    config = load_config(config_path)
    store = Store(config.state_path)
    for days_ago in (2, 1):
        earlier = store.open(DISK, T0 - timedelta(days=days_ago))
        store.resolve(earlier, T0 - timedelta(days=days_ago, minutes=-5))
    third = opened(store, 1)
    cli._propose_due(config, store, T0)
    assert len(calls.drafts) == 1
    assert "total: 3 incidents" in calls.drafts[0]

    store.resolve(third, T0)
    opened(store, 1, now=T0 + timedelta(hours=1))
    cli._propose_due(config, store, T0 + timedelta(hours=1))
    assert len(calls.drafts) == 1  # the same problem already has a proposal


def test_the_hourly_budget_and_failures_never_break_a_check(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    config = load_config(config_path)
    store = Store(config.state_path)
    for key in ("a", "b", "c"):
        store.open(Finding("disk", f"shop={key}", "warning", key, 1.0), T0 - timedelta(hours=1))
    posts: list[object] = []
    monkeypatch.setattr(cli, "draft", lambda *_: PROPOSAL)
    monkeypatch.setattr(teams, "post", lambda _url, payload: posts.append(payload))
    cli._propose_due(config, store, T0)
    assert len(posts) == 2
    assert "hourly budget" in capsys.readouterr().err

    def broken(*_: object) -> Proposal:
        raise InvestigationError("model crashed")

    monkeypatch.setattr(cli, "draft", broken)
    cli._propose_due(config, store, T0 + timedelta(hours=2))
    assert "proposal for #3 failed: model crashed" in capsys.readouterr().err


def test_teams_post_reports_rejected_payloads():
    seen: list[dict[str, Any]] = []

    def accept(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(202)

    teams.post("https://hook", {"type": "message"}, transport=httpx.MockTransport(accept))
    assert seen == [{"type": "message"}]
    refuse = httpx.MockTransport(lambda _request: httpx.Response(400, text="bad card"))
    with pytest.raises(RuntimeError, match="400: bad card"):
        teams.post("https://hook", {}, transport=refuse)


def test_cards_name_an_existing_ticket_and_fall_back_to_english(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    incident = store.incident(store.open(Finding("disk", "shop=a", "warning", "a", 1.0), T0))
    assert incident is not None
    existing = Proposal(
        **{**ANSWER, "recommendation": "existing_ticket", "existing_ticket": "DB-7"}
    )
    links = server.links("http://127.0.0.1:1", 1, "tok")
    card = teams.proposal_card(incident, existing, 1, 7, links, "Klingon")
    content = card["attachments"][0]["content"]
    assert content["body"][0]["text"] == "🔗 Already in a ticket: DB-7"
    assert [action["title"] for action in content["actions"]] == ["Approve", "Reject", "Detail"]


@pytest.fixture
def page_server(tmp_path: Path) -> Iterator[tuple[str, Store]]:
    store = Store(tmp_path / "state.db")
    started: list[ThreadingHTTPServer] = []
    ready = threading.Event()

    def on_ready(running: ThreadingHTTPServer) -> None:
        started.append(running)
        ready.set()

    thread = threading.Thread(
        target=server.serve,
        args=(tmp_path / "state.db", "Czech", 0),
        kwargs={"ready": on_ready},
        daemon=True,
    )
    thread.start()
    ready.wait(5)
    yield f"http://127.0.0.1:{started[0].server_port}", store
    started[0].shutdown()


def test_the_page_records_decisions_behind_a_token(page_server: tuple[str, Store]):
    base, store = page_server
    incident_id = opened(store, 40)
    store.save_diagnosis(incident_id, DIAGNOSIS.to_json(), T0)
    store.save_proposal(incident_id, PROPOSAL.to_json(), "secret-token", T0)
    root = f"{base}/incidents/{incident_id}"

    detail = httpx.get(f"{root}?t=secret-token")
    assert detail.status_code == 200
    assert "Čeká na tvoje rozhodnutí" in detail.text
    assert "h3. What happens" in detail.text
    assert "MySQL refuses connections." in detail.text
    assert f"{root}/approve?t=secret-token" in detail.text

    assert httpx.get(f"{root}/approve?t=guess").status_code == 403
    assert httpx.get(f"{base}/incidents/999?t=x").status_code == 404
    assert httpx.get(f"{base}/elsewhere").status_code == 404

    approved = httpx.get(f"{root}/approve?t=secret-token")
    assert "Schváleno" in approved.text
    incident = store.incident(incident_id)
    assert incident is not None
    assert incident["decision"] == "approved"
    assert httpx.get(f"{root}/reject?t=secret-token").status_code == 200
    incident = store.incident(incident_id)
    assert incident is not None
    assert incident["decision"] == "rejected"
    assert [row["kind"] for row in store.timeline(incident)] == ["approved", "rejected"]


def scout(config_path: Path, *args: str) -> int:
    return cli.main(["--config", str(config_path), *args])


def test_propose_decide_show_and_history_commands(
    config_path: Path, calls: Calls, capsys: pytest.CaptureFixture[str]
):
    store = Store(load_config(config_path).state_path)
    incident_id = opened(store, 5)
    assert scout(config_path, "propose", str(incident_id), "--no-send") == 0
    assert calls.posts == []
    assert "🎫 create_ticket (high): Shop A: disk runs full" in capsys.readouterr().out

    assert scout(config_path, "decide", str(incident_id), "approve") == 0
    assert scout(config_path, "show", str(incident_id)) == 0
    shown = capsys.readouterr().out
    assert "decision: approved" in shown
    assert scout(config_path, "history", "--since", "30d") == 0
    assert "ticket approved" in capsys.readouterr().out

    assert scout(config_path, "decide", "999", "reject") == 1
    assert scout(config_path, "propose", "999") == 1


def test_serve_and_install_follow_the_tickets_config(
    config_path: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    served: list[tuple[Any, ...]] = []
    monkeypatch.setattr(server, "serve", lambda *args: served.append(args))
    assert scout(config_path, "serve") == 0
    assert served[0][1:] == ("Czech", 8766)

    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("shutil.which", lambda _: "/opt/homebrew/bin/uv")
    launched: list[list[str]] = []
    monkeypatch.setattr("subprocess.run", lambda args, **_: launched.append(args))
    assert scout(config_path, "install") == 0
    assert [args[1] for args in launched] == ["bootout", "bootstrap"] * 2
    page = plistlib.loads(launchd.plist_path(launchd.SERVER_LABEL).read_bytes())
    assert page["KeepAlive"] is True
    assert "StartInterval" not in page
    assert page["ProgramArguments"][-1] == "serve"
    assert scout(config_path, "uninstall") == 0
    assert not launchd.plist_path(launchd.SERVER_LABEL).exists()


def test_tickets_need_the_investigator(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("tickets: {after_minutes: 5}\n")
    with pytest.raises(ConfigError, match="investigator"):
        load_config(path)
    path.write_text("rules: []\n")
    with pytest.raises(ConfigError, match="tickets"):
        cli._tickets(load_config(path))
    assert triage  # the investigator factory the commands use
