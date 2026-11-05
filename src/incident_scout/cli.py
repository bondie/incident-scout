from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from . import launchd, server, teams, triage
from .config import (
    Config,
    ConfigError,
    InvestigatorConfig,
    TicketsConfig,
    build_telemetry,
    default_config_path,
    load_config,
)
from .engine import backtest, run_check
from .evaluation import (
    case_document,
    case_matrix,
    evaluate,
    load_cases,
    markdown_table,
    rescore,
)
from .evidence import EvidencePack, labels_from_key
from .investigator import CATEGORIES, SCOPES, Diagnosis, InvestigationError, OllamaInvestigator
from .models import Event
from .notify import ConsoleNotifier, DesktopNotifier, Notifier, NtfyNotifier, dispatch
from .proposal import Proposal, draft, new_token
from .sources.base import parse_duration
from .state import Store
from .tracker import CheckResult, process

PROJECT_DIR = Path(__file__).resolve().parents[2]
VERDICTS = ("correct", "partial", "wrong")


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

    cmd = commands.add_parser("history", help="incidents of the last days")
    cmd.add_argument("--since", default="7d", help="how far back, e.g. 24h, 30d")
    cmd.add_argument("--rule", help="only this rule")
    cmd.set_defaults(handler=_history)

    cmd = commands.add_parser("show", help="one incident: timeline, diagnosis, review, evidence")
    cmd.add_argument("incident", type=int, help="incident id")
    cmd.add_argument("--pack", action="store_true", help="print the stored evidence pack")
    cmd.set_defaults(handler=_show)

    cmd = commands.add_parser("review", help="record whether the diagnosis was right")
    cmd.add_argument("incident", type=int, help="incident id")
    cmd.add_argument("--verdict", required=True, choices=VERDICTS)
    cmd.add_argument("--cause", help="the real cause (default: the diagnosis, if correct)")
    cmd.add_argument("--category", choices=CATEGORIES, help="real category (default: diagnosis)")
    cmd.add_argument("--scope", choices=SCOPES, help="real scope (default: diagnosis)")
    cmd.add_argument(
        "--keywords",
        action="append",
        default=[],
        help="comma-separated synonyms one of which a right cause must name (repeatable)",
    )
    cmd.add_argument("--note", default="", help="anything worth keeping")
    cmd.set_defaults(handler=_review)

    cmd = commands.add_parser("export-case", help="turn a reviewed incident into an eval case")
    cmd.add_argument("incident", type=int, help="incident id")
    cmd.add_argument("--out", type=Path, required=True, help="case file or directory")
    cmd.set_defaults(handler=_export_case)

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
    cmd.add_argument(
        "--recollect", action="store_true", help="query telemetry again instead of the stored pack"
    )
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

    cmd = commands.add_parser("propose", help="draft a ticket proposal for the PM and send it")
    cmd.add_argument("incident", type=int, help="incident id")
    cmd.add_argument("--no-send", action="store_true", help="print it instead of posting to Teams")
    cmd.set_defaults(handler=_propose)

    cmd = commands.add_parser("decide", help="approve or reject a ticket proposal")
    cmd.add_argument("incident", type=int, help="incident id")
    cmd.add_argument("decision", choices=sorted(server.DECISIONS))
    cmd.set_defaults(handler=_decide)

    cmd = commands.add_parser("serve", help="the local page behind the Teams card buttons")
    cmd.add_argument("--port", type=int, help="default: tickets.port from the config")
    cmd.set_defaults(handler=_serve)

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
    store.record(events, now)
    for event in events:
        ConsoleNotifier().send(event)
    dispatch(_push_notifiers(config), events, config.notify.max_per_run)
    if config.investigator is not None:
        _investigate_new(config, store, events, now)
    if config.tickets is not None:
        _propose_due(config, store, now)
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
        follow_up = _diagnose(config, store, incident, now)
        store.record([follow_up], now)
        ConsoleNotifier().send(follow_up)
        if follow_up.kind == "diagnosed":
            dispatch(_push_notifiers(config), [follow_up])


def _diagnose(config: Config, store: Store, incident: sqlite3.Row, now: datetime) -> Event:
    """Keep the evidence even when the model fails, so the incident can be judged later."""
    try:
        pack = _incident_pack(config, incident)
        store.save_evidence(incident["id"], pack.to_json())
        diagnosis = triage.investigator(config).diagnose(pack)
    except Exception as error:  # a failed diagnosis must not break monitoring
        return Event(
            "diagnosis_failed",
            "info",
            f"investigation of #{incident['id']} failed",
            str(error)[:300],
            group=incident["fingerprint"],
            incident_id=incident["id"],
        )
    store.save_diagnosis(incident["id"], diagnosis.to_json(), now)
    return _diagnosed(incident, diagnosis)


def _diagnosed(incident: sqlite3.Row, diagnosis: Diagnosis) -> Event:
    return Event(
        "diagnosed",
        incident["severity"],
        f"🔎 {incident['rule']} #{incident['id']}",
        f"{diagnosis.likely_cause} [{diagnosis.confidence}]",
        group=incident["fingerprint"],
        url=incident["url"],
        incident_id=incident["id"],
    )


def _propose_due(config: Config, store: Store, now: datetime) -> None:
    """Propose a ticket for incidents that last or keep coming back, once per problem."""
    settings = _tickets(config)
    for incident in store.open_incidents():
        if incident["proposal"]:
            continue
        history = store.same_problem(
            incident["fingerprint"], now - timedelta(days=settings.recurring_days)
        )
        if any(row["proposal"] for row in history):
            continue
        lasted = now - datetime.fromisoformat(incident["opened_at"])
        if lasted < timedelta(minutes=settings.after_minutes) and len(history) < settings.recurring:
            continue
        if store.proposals_since(now - timedelta(hours=1)) >= settings.max_per_hour:
            print("ticket proposals skipped: hourly budget used up", file=sys.stderr)
            return
        try:
            _make_proposal(config, store, incident, now, send=True)
        except Exception as error:  # a failed proposal must not break monitoring
            print(f"proposal for #{incident['id']} failed: {error}", file=sys.stderr)


def _make_proposal(
    config: Config, store: Store, incident: sqlite3.Row, now: datetime, send: bool
) -> Proposal:
    settings = _tickets(config)
    history = store.same_problem(
        incident["fingerprint"], now - timedelta(days=settings.recurring_days)
    )
    proposal = draft(triage.investigator(config), incident, history, now)
    token = new_token()
    store.save_proposal(incident["id"], proposal.to_json(), token, now)
    event = Event(
        "proposed",
        "info",
        f"🎫 {incident['rule']} #{incident['id']}: {proposal.recommendation}",
        proposal.title,
        group=incident["fingerprint"],
        incident_id=incident["id"],
    )
    store.record([event], now)
    ConsoleNotifier().send(event)
    if send and settings.teams_url:
        fresh = store.incident(incident["id"]) or incident
        card = teams.proposal_card(
            fresh,
            proposal,
            len(history),
            settings.recurring_days,
            server.links(f"http://127.0.0.1:{settings.port}", incident["id"], token),
            triage.investigator_config(config).language,
        )
        teams.post(settings.teams_url, card)
    return proposal


def _tickets(config: Config) -> TicketsConfig:
    if config.tickets is None:
        raise ConfigError("No `tickets` section in the config")
    return config.tickets


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
    elif incident is not None and incident["evidence"] and not args.recollect:
        pack = EvidencePack.from_json(incident["evidence"])
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
        now = datetime.now(UTC)
        store.save_evidence(incident["id"], pack.to_json())
        store.save_diagnosis(incident["id"], diagnosis.to_json(), now)
        store.record([_diagnosed(incident, diagnosis)], now)
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

        label = f"{model} think={args.think}" if args.think else model
        report = evaluate(cases, judge.diagnose, label, progress)
        report.scores = [replace(score, model=label) for score in report.scores]
        reports.append(report)
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
        used = dict.fromkeys(rule.source for rule in config.rules)
        connections = {name: build_telemetry(config.source_options(name)) for name in used}
        return await asyncio.wait_for(run_check(connections, config.rules), config.timeout_seconds)

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
        print(
            f"  #{row['id']:<4} {row['severity']:<8} since {_local(row['opened_at'])}  "
            f"{row['summary']}"
        )
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
            print(
                f"  #{row['id']:<4} {_local(row['opened_at'])} - {_local(row['resolved_at'])}  "
                f"{row['summary']}"
            )
    return 0


def _history(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    since = datetime.now(UTC) - timedelta(seconds=parse_duration(args.since))
    rows = store.incidents_since(since, args.rule)
    print(f"{len(rows)} incidents since {since.astimezone():%d.%m. %H:%M}")
    for row in rows:
        review = json.loads(row["review"])["verdict"] if row["review"] else "not reviewed"
        notes = ["diagnosed" if row["diagnosis"] else "no diagnosis", review]
        if row["proposal"]:
            notes.append(f"ticket {row['decision'] or 'proposed'}")
        print(
            f"  #{row['id']:<4} {_local(row['opened_at'])}  {_lasted(row):>9}  "
            f"{row['rule']:<18} {row['summary']}  ({', '.join(notes)})"
        )
    return 0


def _show(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident)
    if incident is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    print(f"#{incident['id']} {incident['rule']} ({incident['severity']})  {incident['summary']}")
    closed = "still open"
    if incident["resolved_at"]:
        closed = f"resolved {_local(incident['resolved_at'])} ({_lasted(incident)})"
    print(f"opened {_local(incident['opened_at'])}, {closed}")
    if incident["url"]:
        print(f"link: {incident['url']}")
    print("\ntimeline:")
    for event in store.timeline(incident):
        print(f"  {_local(event['at'])}  {event['kind']:<16} {event['title']} {event['message']}")
    if incident["diagnosis"]:
        _print_diagnosis(Diagnosis(**json.loads(incident["diagnosis"])))
    if incident["review"]:
        _print_review(json.loads(incident["review"]))
    if incident["proposal"]:
        _print_proposal(Proposal.from_json(incident["proposal"]), incident["decision"])
    if not incident["evidence"]:
        print("\nno evidence stored")
        return 0
    if args.pack:
        print("\n" + EvidencePack.from_json(incident["evidence"]).render())
        return 0
    print("\nevidence stored; --pack prints it")
    return 0


def _review(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident)
    if incident is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    diagnosis = Diagnosis(**json.loads(incident["diagnosis"])) if incident["diagnosis"] else None
    cause = args.cause
    if cause is None and args.verdict == "correct" and diagnosis is not None:
        cause = diagnosis.likely_cause
    if cause is None:
        print("say what the real cause was with --cause", file=sys.stderr)
        return 2
    review = {
        "verdict": args.verdict,
        "cause": cause,
        "category": args.category or (diagnosis.category if diagnosis else None),
        "scope": args.scope or (diagnosis.scope if diagnosis else None),
        "keywords": [group for group in map(_synonyms, args.keywords) if group],
        "note": args.note,
        "model": diagnosis.model if diagnosis else None,
    }
    now = datetime.now(UTC)
    store.save_review(incident["id"], json.dumps(review, ensure_ascii=False), now)
    store.record(
        [
            Event(
                "reviewed",
                "info",
                f"review: {args.verdict}",
                cause,
                group=incident["fingerprint"],
                incident_id=incident["id"],
            )
        ],
        now,
    )
    _print_review(review)
    return 0


def _export_case(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident)
    if incident is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    review = json.loads(incident["review"]) if incident["review"] else {}
    missing = [
        hint
        for hint, ok in (
            ("stored evidence", incident["evidence"]),
            ("a review (`scout review`)", review),
            ("a category and scope in the review", review.get("category") and review.get("scope")),
            ("--keywords in the review", review.get("keywords")),
        )
        if not ok
    ]
    if missing:
        needs = ", ".join(missing)
        print(f"#{incident['id']} cannot be a case yet, it needs {needs}", file=sys.stderr)
        return 1
    case_id = f"incident-{incident['id']}-{incident['rule']}"
    document = case_document(
        case_id,
        EvidencePack.from_json(incident["evidence"]),
        review["category"],
        review["scope"],
        review["keywords"],
        note=" ".join(filter(None, [review["cause"], review.get("note")])),
    )
    target = args.out / f"{case_id}.yaml" if args.out.is_dir() else args.out
    target.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=1000))
    print(f"wrote {target}")
    return 0


def _propose(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident)
    if incident is None:
        print(f"no incident {args.incident}", file=sys.stderr)
        return 1
    try:
        proposal = _make_proposal(config, store, incident, datetime.now(UTC), not args.no_send)
    except InvestigationError as error:
        print(f"proposal failed: {error}", file=sys.stderr)
        return 1
    _print_proposal(proposal, None)
    return 0


def _decide(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    store = Store(config.state_path)
    incident = store.incident(args.incident)
    if incident is None or not incident["proposal"]:
        print(f"no ticket proposal for incident {args.incident}", file=sys.stderr)
        return 1
    server.decide(store, incident, args.decision, datetime.now(UTC))
    print(f"#{args.incident}: {server.DECISIONS[args.decision]}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    settings = _tickets(config)
    port = args.port or settings.port
    language = triage.investigator_config(config).language
    print(f"decision page on http://127.0.0.1:{port}", flush=True)
    server.serve(config.state_path, language, port)
    return 0


def _print_proposal(proposal: Proposal, decision: str | None) -> None:
    ticket = f" {proposal.existing_ticket}" if proposal.existing_ticket else ""
    print(f"\n🎫 {proposal.recommendation}{ticket} ({proposal.priority}): {proposal.title}")
    print(f"     why: {proposal.reason}")
    print(f"decision: {decision or 'pending'}")
    print("\n" + proposal.description)


def _print_review(review: dict[str, Any]) -> None:
    print(f"\nreview: {review['verdict']}")
    print(f"   cause: {review['cause']}")
    print(f"  expect: {review.get('category') or '?'}, {review.get('scope') or '?'}")
    keywords = review.get("keywords") or []
    if keywords:
        groups = " AND ".join("(" + " | ".join(g) + ")" for g in keywords)
        print(f"keywords: {groups}")
    if review.get("note"):
        print(f"    note: {review['note']}")


def _synonyms(group: str) -> list[str]:
    return [word.strip() for word in group.split(",") if word.strip()]


def _lasted(incident: sqlite3.Row) -> str:
    if not incident["resolved_at"]:
        return "open"
    opened = datetime.fromisoformat(incident["opened_at"])
    minutes = round((datetime.fromisoformat(incident["resolved_at"]) - opened).total_seconds() / 60)
    return f"{minutes} min" if minutes < 120 else f"{minutes / 60:.1f} h"


def _backtest(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    rules = [config.rule(name) for name in args.rule] if args.rule else config.rules
    end = time.time()
    start = end - parse_duration(args.since)
    step = parse_duration(args.step)

    async def replay(source: str) -> None:
        async with build_telemetry(config.source_options(source)) as telemetry:
            for rule in rules:
                if rule.source != source or rule.kind == "alertmanager":
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

    for source in dict.fromkeys(rule.source for rule in rules):
        try:
            asyncio.run(replay(source))
        except Exception as error:
            print(f"source {source}: failed: {error}")
    return 0


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
    if config.tickets is not None:
        page = launchd.install(PROJECT_DIR, config_path, config.interval_minutes, command="serve")
        print(f"installed {page}; decision page on http://127.0.0.1:{config.tickets.port}")
    print(f"log: {launchd.log_path()}")
    return 0


def _uninstall(args: argparse.Namespace) -> int:
    removed = launchd.uninstall()
    launchd.uninstall(label=launchd.SERVER_LABEL)
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
