from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from . import launchd
from .config import Config, ConfigError, build_telemetry, default_config_path, load_config
from .engine import backtest, run_check
from .models import Event
from .notify import ConsoleNotifier, DesktopNotifier, Notifier, NtfyNotifier, dispatch
from .sources.base import parse_duration
from .state import Store
from .tracker import CheckResult, process

PROJECT_DIR = Path(__file__).resolve().parents[2]


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except ConfigError as error:
        print(f"config error: {error}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scout", description="Local incident detector.")
    parser.add_argument("--config", type=Path, default=None, help="config file")
    commands = parser.add_subparsers(required=True, metavar="command")

    cmd = commands.add_parser("check", help="evaluate all rules once and notify about changes")
    cmd.add_argument(
        "--dry-run", action="store_true", help="print findings, keep state, notify nobody"
    )
    cmd.set_defaults(handler=_check)

    cmd = commands.add_parser("status", help="open incidents, pending findings and health")
    cmd.set_defaults(handler=_status)

    cmd = commands.add_parser("backtest", help="replay rules over history to tune thresholds")
    cmd.add_argument("--rule", action="append", help="only this rule (repeatable)")
    cmd.add_argument("--since", default="3d", help="how far back, e.g. 24h, 7d")
    cmd.add_argument("--step", default="5m", help="resolution of promql replays")
    cmd.set_defaults(handler=_backtest)

    cmd = commands.add_parser("notify-test", help="send a test notification to every channel")
    cmd.set_defaults(handler=_notify_test)

    cmd = commands.add_parser("install", help="run checks periodically with launchd (macOS)")
    cmd.set_defaults(handler=_install)

    cmd = commands.add_parser("uninstall", help="remove the launchd agent")
    cmd.set_defaults(handler=_uninstall)
    return parser


def _check(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    now = datetime.now(UTC)
    result = _run(config)
    if args.dry_run:
        for finding in result.findings:
            print(f"{finding.severity:<8} {finding.rule:<20} {finding.summary}")
        for rule, error in result.errors.items():
            print(f"error    {rule:<20} {error}", file=sys.stderr)
        return 0
    store = Store(config.state_path)
    rules = {rule.name: rule for rule in config.rules}
    events = process(store, result, rules, now, config.blind_after, config.resolve_after)
    for event in events:
        ConsoleNotifier().send(event)
    dispatch(_push_notifiers(config), events, config.notify.max_per_run)
    open_count = len(store.open_incidents())
    print(
        f"{now.astimezone():%Y-%m-%d %H:%M:%S} check: {len(result.findings)} findings, "
        f"{open_count} open, {len(events)} events, {len(result.errors)} rule errors",
        flush=True,
    )
    return 0


def _run(config: Config) -> CheckResult:
    async def bounded() -> CheckResult:
        return await asyncio.wait_for(
            run_check(build_telemetry(config.source), config.rules), config.timeout_seconds
        )

    try:
        return asyncio.run(bounded())
    except TimeoutError:
        names = [rule.name for rule in config.rules]
        return CheckResult([], names, dict.fromkeys(names, "timed out"))


def _status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    health = store.health()
    print(f"last run {_local(health['last_run'])}, last success {_local(health['last_ok'])}")
    if health["blind_since"]:
        print(f"BLIND since {_local(health['blind_since'])}: {health['last_error']}")
    incidents = store.open_incidents()
    print(f"\nopen incidents: {len(incidents)}")
    for row in incidents:
        print(f"  {row['severity']:<8} since {_local(row['opened_at'])}  {row['summary']}")
    pending = store.pending()
    if pending:
        print(f"\nwaiting for confirmation: {len(pending)}")
        for row in pending:
            print(f"  {row['fingerprint']} seen {row['streak']}x since {_local(row['first_seen'])}")
    failing = store.failing_rules()
    if failing:
        print("\nfailing rules:")
        for row in failing:
            print(f"  {row['rule']} ({row['failed_runs']}x): {row['last_error']}")
    recent = store.recent_incidents(5)
    if recent:
        print("\nrecently resolved:")
        for row in recent:
            print(f"  {_local(row['opened_at'])} - {_local(row['resolved_at'])}  {row['summary']}")
    return 0


def _backtest(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    rules = [config.rule(name) for name in args.rule] if args.rule else config.rules
    end = time.time()
    start = end - parse_duration(args.since)
    step = parse_duration(args.step)

    async def replay() -> int:
        async with build_telemetry(config.source) as telemetry:
            for rule in rules:
                if rule.kind == "alertmanager":
                    continue
                try:
                    found = await backtest(rule, telemetry, start, end, step)
                except Exception as error:
                    print(f"{rule.name}: failed: {error}")
                    continue
                alerting = [
                    e for e in found if e.minutes >= (rule.for_runs - 1) * config.interval_minutes
                ]
                print(f"{rule.name}: {len(alerting)} episodes would notify ({len(found)} raw)")
                for episode in alerting:
                    print(
                        f"   {_local_ts(episode.start)} - {_local_ts(episode.end)} "
                        f"{episode.minutes:5.0f} min  peak {episode.peak:g}  {episode.key}"
                    )
        return 0

    return asyncio.run(replay())


def _notify_test(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    event = Event(
        "opened",
        "warning",
        "🧪 incident-scout test",
        "Notifications work. Incidents will look like this.",
        group="test",
    )
    dispatch(_push_notifiers(config), [event])
    ConsoleNotifier().send(event)
    return 0


def _install(args: argparse.Namespace) -> int:
    config_path = (args.config or default_config_path()).resolve()
    config = load_config(config_path)
    target = launchd.install(PROJECT_DIR, config_path, config.interval_minutes)
    print(f"installed {target}; checks every {config.interval_minutes} min")
    print(f"log: {launchd.log_path()}")
    return 0


def _uninstall(args: argparse.Namespace) -> int:
    removed = launchd.uninstall()
    print("removed" if removed else "no agent was installed")
    return 0


def _push_notifiers(config: Config) -> Sequence[Notifier]:
    notifiers: list[Notifier] = []
    if config.notify.desktop:
        notifiers.append(DesktopNotifier())
    if config.notify.ntfy_url and config.notify.ntfy_topic:
        notifiers.append(
            NtfyNotifier(config.notify.ntfy_url, config.notify.ntfy_topic, config.notify.ntfy_token)
        )
    return notifiers


def _local(timestamp: str | None) -> str:
    if not timestamp:
        return "never"
    return datetime.fromisoformat(timestamp).astimezone().strftime("%d.%m. %H:%M")


def _local_ts(seconds: float) -> str:
    return datetime.fromtimestamp(seconds).astimezone().strftime("%d.%m. %H:%M")


if __name__ == "__main__":
    raise SystemExit(main())
