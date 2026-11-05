from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import launchd, triage
from .config import (
    Config,
    ConfigError,
    InvestigatorConfig,
    build_telemetry,
    default_config_path,
    load_config,
)
from .engine import backtest, run_check
from .evaluation import case_matrix, evaluate, load_cases, markdown_table, rescore
from .evidence import EvidencePack, labels_from_key
from .investigator import Diagnosis, InvestigationError, OllamaInvestigator
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
    cmd.add_argument("--force", action="store_true", help="run even during quiet hours")
    cmd.set_defaults(handler=_check)

    cmd = commands.add_parser("status", help="open incidents, pending findings and health")
    cmd.set_defaults(handler=_status)

    cmd = commands.add_parser("backtest", help="replay rules over history to tune thresholds")
    cmd.add_argument("--rule", action="append", help="only this rule (repeatable)")
    cmd.add_argument("--since", default="3d", help="how far back, e.g. 24h, 7d")
    cmd.add_argument("--step", default="5m", help="resolution of promql replays")
    cmd.set_defaults(handler=_backtest)

    cmd = commands.add_parser(
        "investigate", help="collect evidence for an incident and diagnose it"
    )
    cmd.add_argument("--incident", type=int, help="incident id (see `scout status`)")
    cmd.add_argument("--rule", help="rule name, for an incident from history")
    cmd.add_argument("--label", action="append", default=[], help="label=value (repeatable)")
    cmd.add_argument("--at", help="when it started, local time, e.g. 2026-11-03T13:58")
    cmd.add_argument("--summary", help="alert text for an incident from history")
    cmd.add_argument("--pack", type=Path, help="diagnose a saved evidence pack")
    cmd.add_argument("--save-pack", type=Path, help="write the evidence pack as JSON")
    cmd.add_argument("--show-pack", action="store_true", help="print the evidence pack")
    cmd.add_argument("--no-diagnosis", action="store_true", help="only collect evidence")
    cmd.add_argument("--model", help="Ollama model instead of the configured one")
    cmd.set_defaults(handler=_investigate)

    cmd = commands.add_parser("eval", help="score investigator models on cases with known causes")
    cmd.add_argument("cases", nargs="+", type=Path, help="case files or directories")
    cmd.add_argument("--models", required=True, help="comma-separated Ollama models")
    cmd.add_argument("--think", help="on, off, or a level such as low (default: model default)")
    cmd.add_argument("--language", help="language of the answers (default: from config)")
    cmd.add_argument("--out", type=Path, help="write every diagnosis and score as JSON")
    cmd.set_defaults(handler=_eval)

    cmd = commands.add_parser("report", help="combine and re-score saved eval results")
    cmd.add_argument("results", nargs="+", type=Path, help="JSON files written by `eval --out`")
    cmd.add_argument("--cases", nargs="+", type=Path, required=True, help="case files or dirs")
    cmd.set_defaults(handler=_report)

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
    if args.dry_run:
        result = _run(config)
        for finding in result.findings:
            print(f"{finding.severity:<8} {finding.rule:<20} {finding.summary}")
        for rule, error in result.errors.items():
            print(f"error    {rule:<20} {error}", file=sys.stderr)
        return 0
    store = Store(config.state_path)
    last_run = store.health()["last_run"]
    if (
        not args.force
        and config.quiet_hours is not None
        and config.quiet_hours.resting(now, datetime.fromisoformat(last_run) if last_run else None)
    ):
        return 0
    result = _run(config)
    rules = {rule.name: rule for rule in config.rules}
    events = process(store, result, rules, now, config.blind_after, config.resolve_after)
    for event in events:
        ConsoleNotifier().send(event)
    dispatch(_push_notifiers(config), events, config.notify.max_per_run)
    if config.investigator is not None:
        _investigate_new(config, store, events, now)
    open_count = len(store.open_incidents())
    print(
        f"{now.astimezone():%Y-%m-%d %H:%M:%S} check: {len(result.findings)} findings, "
        f"{open_count} open, {len(events)} events, {len(result.errors)} rule errors",
        flush=True,
    )
    return 0


def _investigate_new(config: Config, store: Store, events: Sequence[Event], now: datetime) -> None:
    """Diagnose freshly opened incidents and follow up on their notification."""
    settings = triage.investigator_config(config)
    for event in events:
        if event.kind != "opened":
            continue
        incident = store.open_incident(event.group)
        if incident is None:
            continue
        if store.diagnoses_since(now - timedelta(hours=1)) >= settings.max_per_hour:
            print("investigation skipped: hourly budget used up", file=sys.stderr)
            return
        try:
            diagnosis = triage.investigator(config).diagnose(_incident_pack(config, incident))
        except Exception as error:  # a failed diagnosis must not break monitoring
            print(f"investigation of {event.group} failed: {error}", file=sys.stderr)
            continue
        store.save_diagnosis(incident["id"], diagnosis.to_json(), now)
        follow_up = Event(
            "diagnosed",
            incident["severity"],
            f"🔎 {incident['rule']}",
            f"{diagnosis.likely_cause} [{diagnosis.confidence}]",
            group=incident["fingerprint"],
            url=incident["url"],
        )
        ConsoleNotifier().send(follow_up)
        dispatch(_push_notifiers(config), [follow_up])


def _incident_pack(config: Config, incident: sqlite3.Row) -> EvidencePack:
    labels = labels_from_key(incident["fingerprint"].split("|", 1)[1])
    return asyncio.run(
        triage.gather(
            config,
            incident["rule"],
            incident["severity"],
            incident["summary"],
            labels,
            triage.started_at(incident["opened_at"]),
        )
    )


def _investigate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident) if args.incident else None
    if args.incident and incident is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    if args.pack:
        pack = EvidencePack.from_json(args.pack.read_text())
    elif incident is not None:
        pack = _incident_pack(config, incident)
    else:
        if not args.rule or not args.at:
            raise ConfigError("Give --incident, --pack, or --rule with --at for history")
        labels = dict(item.split("=", 1) for item in args.label)
        severity = next((r.severity for r in config.rules if r.name == args.rule), "warning")
        summary = args.summary or f"{args.rule}: {', '.join(args.label)}"
        started = datetime.fromisoformat(args.at).astimezone().timestamp()
        pack = asyncio.run(triage.gather(config, args.rule, severity, summary, labels, started))
    if args.save_pack:
        args.save_pack.write_text(pack.to_json())
    if args.show_pack or args.no_diagnosis:
        print(pack.render())
    if args.no_diagnosis:
        return 0
    try:
        diagnosis = triage.investigator(config, args.model).diagnose(pack)
    except InvestigationError as error:
        print(f"investigation failed: {error}", file=sys.stderr)
        return 1
    _print_diagnosis(diagnosis)
    if incident is not None:
        store.save_diagnosis(incident["id"], diagnosis.to_json(), datetime.now(UTC))
    return 0


def _print_diagnosis(diagnosis: Diagnosis) -> None:
    print(f"\n🔎 {diagnosis.summary}")
    print(f"cause: {diagnosis.likely_cause}")
    print(f"       {diagnosis.category}, {diagnosis.scope}, confidence {diagnosis.confidence}")
    for title, items in (("evidence", diagnosis.key_evidence), ("next", diagnosis.next_steps)):
        for item in items:
            print(f"{title:>8}: {item}")
    print(f"({diagnosis.model}, {diagnosis.seconds:.0f} s)")


def _eval(args: argparse.Namespace) -> int:
    try:
        settings = load_config(args.config).investigator or InvestigatorConfig(model="")
    except ConfigError:
        settings = InvestigatorConfig(model="")
    think = {"on": True, "off": False}.get(args.think, args.think)
    cases = load_cases(args.cases)
    print(f"{len(cases)} cases", flush=True)
    reports = []
    for model in [m.strip() for m in args.models.split(",") if m.strip()]:
        judge = OllamaInvestigator(
            model=model,
            url=settings.url,
            language=args.language or settings.language,
            think=think if args.think else settings.think,
            timeout=settings.timeout_seconds,
        )
        print(f"\n== {model}", flush=True)
        try:
            judge.warm_up()
        except Exception as error:
            print(f"   cannot load: {error}", flush=True)
            continue

        def progress(score: object) -> None:
            data = asdict(score)  # type: ignore[call-overload]
            flags = "".join(
                mark if ok else "."
                for mark, ok in zip(
                    "CSGV",
                    (data["category"], data["scope"], data["cause"], data["valid"]),
                    strict=True,
                )
            )
            print(f"   {data['case']:<32} {flags} {data['seconds']:5.0f} s", flush=True)

        reports.append(evaluate(cases, judge.diagnose, model, progress))
        judge.unload()
    print("\n" + markdown_table(reports))
    if args.out:
        rows = [
            {**asdict(score), "total": score.total, "grounded": score.grounded}
            for report in reports
            for score in report.scores
        ]
        args.out.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
    return 0


def _report(args: argparse.Namespace) -> int:
    rows = [row for path in args.results for row in json.loads(path.read_text())]
    reports = rescore(rows, load_cases(args.cases))
    print(markdown_table(reports))
    print()
    print(case_matrix(reports))
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
