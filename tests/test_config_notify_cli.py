from __future__ import annotations

import json
import plistlib
from dataclasses import replace
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from incident_scout import cli, launchd
from incident_scout.config import ConfigError, QuietHours, build_telemetry, load_config
from incident_scout.models import Event, Series
from incident_scout.notify import DesktopNotifier, NtfyNotifier, dispatch
from incident_scout.sources.http import HttpTelemetry
from incident_scout.sources.mcp import McpTelemetry

from .conftest import FakeTelemetry

CONFIG = """
env_files: [{env_file}]
state_path: {state}
source:
  type: mcp
  claude_mcp_server: obs
  claude_config: {claude}
vars:
  sel: 'shop=~"prod-.*"'
notify:
  desktop: false
  ntfy_url: https://ntfy.example
  ntfy_topic: ${{NTFY_TOPIC}}
rules:
  - name: disk
    kind: promql
    query: 'disk{{$sel}} > 0.85'
    summary: '{{shop}}: {{value:.0%}}'
    key_labels: [shop]
  - name: infra
    kind: alertmanager
"""


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    env_file = tmp_path / "secrets.env"
    env_file.write_text("export NTFY_TOPIC='ops-alerts'\n# comment\nOBS_TOKEN=abc\n")
    claude = tmp_path / "claude.json"
    claude.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "obs": {"url": "https://obs.example/mcp", "headers": {"Authorization": "x"}}
                }
            }
        )
    )
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(env_file=env_file, state=tmp_path / "state.db", claude=claude))
    return path


def test_config_expands_env_and_vars_and_reads_claude_servers(config_path: Path):
    config = load_config(config_path)
    assert config.rule("disk").query == 'disk{shop=~"prod-.*"} > 0.85'
    assert config.rule("disk").key_labels == ("shop",)
    assert config.notify.ntfy_topic == "ops-alerts"
    telemetry = build_telemetry(config.source)
    assert isinstance(telemetry, McpTelemetry)
    assert telemetry.url == "https://obs.example/mcp"
    assert telemetry.headers == {"Authorization": "x"}


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        ("rules: [{name: a, kind: sql, query: x}]", "kind must be one of"),
        ("rules: [{name: a, kind: promql, query: x, severity: loud}]", "severity must be"),
        ("rules: [{name: a, kind: promql}]", "query is required"),
        ("rules: [{name: a, kind: promql, query: x, colour: red}]", "unknown option"),
        ("rules: [{name: a, kind: promql, query: x}, {name: a, kind: promql, query: y}]", "unique"),
        ("source: {url: '${MISSING_VAR}'}", "MISSING_VAR is not set"),
    ],
)
def test_config_errors_are_explicit(tmp_path: Path, snippet: str, message: str):
    path = tmp_path / "config.yaml"
    path.write_text(snippet)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_missing_config_and_unknown_rule(tmp_path: Path, config_path: Path):
    with pytest.raises(ConfigError, match="No config"):
        load_config(tmp_path / "nope.yaml")
    with pytest.raises(ConfigError, match="Unknown rule"):
        load_config(config_path).rule("nope")


def test_build_telemetry_variants(tmp_path: Path):
    http = build_telemetry({"type": "http", "prometheus_url": "http://prom"})
    assert isinstance(http, HttpTelemetry)
    direct = build_telemetry({"url": "https://mcp.example", "tools": {"query": "promql"}})
    assert isinstance(direct, McpTelemetry)
    assert direct.tools.query == "promql"
    with pytest.raises(ConfigError, match="Unknown source type"):
        build_telemetry({"type": "smoke-signals"})
    with pytest.raises(ConfigError, match="is required"):
        build_telemetry({"type": "mcp"})
    claude = tmp_path / "claude.json"
    claude.write_text("{}")
    with pytest.raises(ConfigError, match="No HTTP MCP server"):
        build_telemetry({"claude_mcp_server": "obs", "claude_config": str(claude)})


EVENT = Event("opened", "critical", "🔴 http-5xx", "a: 55x 5xx", "http-5xx|shop=a", "https://x")


def test_desktop_notifier_prefers_terminal_notifier():
    calls: list[list[str]] = []
    DesktopNotifier(runner=lambda cmd, **_: calls.append(cmd), which=lambda _: "/bin/tn").send(
        EVENT
    )
    assert calls[0][:5] == ["/bin/tn", "-title", "🔴 http-5xx", "-message", "a: 55x 5xx"]
    assert calls[0][7:9] == ["-open", "https://x"]
    assert calls[0][-2:] == ["-sound", "Basso"]


def test_desktop_notifier_falls_back_to_osascript():
    calls: list[list[str]] = []
    quoted = Event("opened", "warning", 'say "hi"', "a\\b", "g")
    DesktopNotifier(runner=lambda cmd, **_: calls.append(cmd), which=lambda _: None).send(quoted)
    assert calls[0][0] == "/usr/bin/osascript"
    assert calls[0][2] == 'display notification "a\\\\b" with title "say \\"hi\\""'


def test_ntfy_notifier_posts_json():
    sent: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append({"auth": request.headers.get("Authorization"), **json.loads(request.content)})
        return httpx.Response(200)

    NtfyNotifier("https://ntfy.example/", "ops", "t", httpx.MockTransport(handler)).send(EVENT)
    assert sent == [
        {
            "auth": "Bearer t",
            "topic": "ops",
            "title": "🔴 http-5xx",
            "message": "a: 55x 5xx",
            "priority": 5,
            "click": "https://x",
        }
    ]


class Recorder:
    def __init__(self, fail: bool = False) -> None:
        self.events: list[Event] = []
        self.fail = fail

    def send(self, event: Event) -> None:
        if self.fail:
            raise RuntimeError("channel down")
        self.events.append(event)


def test_dispatch_caps_storms_and_isolates_broken_channels(capsys: pytest.CaptureFixture[str]):
    good = Recorder()
    dispatch([Recorder(fail=True), good], [EVENT] * 7, max_events=3)
    assert [e.title for e in good.events] == ["🔴 http-5xx", "🔴 http-5xx", "… and 5 more"]
    assert "channel down" in capsys.readouterr().err


@pytest.fixture
def fake_world(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> FakeTelemetry:
    telemetry = FakeTelemetry(
        metrics={'disk{shop=~"prod-.*"} > 0.85': [Series({"shop": "a"}, [(0.0, 0.91)])]},
        ranges={'disk{shop=~"prod-.*"} > 0.85': [Series({"shop": "a"}, [(0.0, 0.91)])]},
    )
    monkeypatch.setattr(cli, "build_telemetry", lambda _source: telemetry)
    monkeypatch.setattr(cli, "_push_notifiers", lambda _config: [])
    return telemetry


def test_cli_check_status_and_dry_run(
    fake_world: FakeTelemetry, config_path: Path, capsys: pytest.CaptureFixture[str]
):
    args = ["--config", str(config_path)]
    assert cli.main([*args, "check", "--dry-run"]) == 0
    assert "warning  disk                 a: 91%" in capsys.readouterr().out

    assert cli.main([*args, "check"]) == 0
    out = capsys.readouterr().out
    assert "opened" in out
    assert "1 findings, 1 open, 1 events" in out

    assert cli.main([*args, "status"]) == 0
    assert "open incidents: 1" in capsys.readouterr().out


def test_cli_backtest(
    fake_world: FakeTelemetry, config_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert cli.main(["--config", str(config_path), "backtest", "--since", "1d"]) == 0
    assert "disk: 0 episodes would notify" in capsys.readouterr().out


def test_cli_reports_config_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    assert cli.main(["--config", str(tmp_path / "nope.yaml"), "status"]) == 2
    assert "No config" in capsys.readouterr().err


def test_cli_notify_test(
    fake_world: FakeTelemetry, config_path: Path, capsys: pytest.CaptureFixture[str]
):
    assert cli.main(["--config", str(config_path), "notify-test"]) == 0
    assert "incident-scout test" in capsys.readouterr().out


def test_launchd_agent_and_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("shutil.which", lambda _: "/opt/homebrew/bin/uv")
    calls: list[list[str]] = []
    target = launchd.install(
        tmp_path / "repo", tmp_path / "c.yaml", 5, runner=lambda cmd, **_: calls.append(cmd)
    )
    plist = plistlib.loads(target.read_bytes())
    assert plist["StartInterval"] == 300
    assert plist["ProgramArguments"][-3:] == ["--config", str(tmp_path / "c.yaml"), "check"]
    assert [c[1] for c in calls] == ["bootout", "bootstrap"]
    assert launchd.uninstall(runner=lambda cmd, **_: None)
    assert not launchd.uninstall(runner=lambda cmd, **_: None)


def test_quiet_hours_window_crosses_midnight():
    night = QuietHours(time(22), time(6), 60)
    late = datetime(2026, 11, 5, 23, 30).astimezone()
    assert night.active(late)
    assert night.active(late.replace(hour=5, minute=59))
    assert not night.active(late.replace(hour=6))
    assert not night.active(late.replace(hour=21, minute=59))
    lunch = QuietHours(time(12), time(13))
    assert lunch.active(late.replace(hour=12, minute=30))
    assert not lunch.active(late.replace(hour=13))


def test_quiet_hours_rest_between_hourly_checks():
    night = QuietHours(time(22), time(6), 60)
    late = datetime(2026, 11, 5, 23, 30).astimezone()
    assert not night.resting(late, None)
    assert night.resting(late, late - timedelta(minutes=30))
    assert not night.resting(late, late - timedelta(minutes=59, seconds=30))
    assert not night.resting(late.replace(hour=12), late - timedelta(minutes=5))


def test_quiet_hours_config_accepts_unquoted_times(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("quiet_hours: {start: 22:00, end: '06:30', interval_minutes: 60}\n")
    assert load_config(path).quiet_hours == QuietHours(time(22), time(6, 30), 60)
    path.write_text("quiet_hours: {start: soon, end: '06:00'}\n")
    with pytest.raises(ConfigError, match="must look like"):
        load_config(path)
    path.write_text("quiet_hours: {end: '06:00'}\n")
    with pytest.raises(ConfigError, match="start is required"):
        load_config(path)


class AlwaysQuiet(QuietHours):
    def active(self, moment: datetime) -> bool:
        return True


def test_cli_check_rests_during_quiet_hours(
    fake_world: FakeTelemetry,
    config_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    quiet = replace(load_config(config_path), quiet_hours=AlwaysQuiet(time(0), time(0), 60))
    monkeypatch.setattr(cli, "load_config", lambda _path: quiet)
    args = ["--config", str(config_path), "check"]
    assert cli.main(args) == 0
    assert "check:" in capsys.readouterr().out
    assert cli.main(args) == 0
    assert capsys.readouterr().out == ""
    assert cli.main([*args, "--force"]) == 0
    assert "check:" in capsys.readouterr().out
