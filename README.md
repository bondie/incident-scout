# incident-scout

[![CI](https://github.com/bondie/incident-scout/actions/workflows/ci.yml/badge.svg)](https://github.com/bondie/incident-scout/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A second pair of eyes on your production, running on your laptop.** incident-scout checks
Prometheus (or VictoriaMetrics), Loki and Alertmanager every five minutes with deterministic
rules. It sends one notification when a problem starts and one when it is gone. It also tells
you when it cannot see anything, instead of staying silent.

Team alerting is usually tuned for outages that last long enough to page someone. Short,
repeated failures and bursts of HTTP 5xx often stay below its thresholds, and those are the
ones a developer wants to hear about. incident-scout is meant for that gap. Every rule can be
**replayed over history first**, so you can see how often it would have fired before it
notifies anybody (illustrative output):

```text
$ scout backtest --since 7d
http-5xx: 2 episodes would notify (2 raw)
   12.03. 17:30 - 12.03. 17:35     5 min  peak 412  app=shop-a
   15.03. 09:10 - 15.03. 09:10     0 min  peak 38  app=shop-b
site-unreachable: 1 episodes would notify (1 raw)
   14.03. 13:40 - 14.03. 14:50    70 min  peak 0.62  instance=shop-a
mysql-down: 0 episodes would notify (1 raw)
```

## Getting started

You need [uv](https://docs.astral.sh/uv/) and access to your telemetry. Notifications use
macOS Notification Center ([terminal-notifier](https://github.com/julienXX/terminal-notifier)
if installed, `osascript` otherwise) and optionally [ntfy](https://ntfy.sh) for your phone.

**1. Install.**

```bash
git clone https://github.com/bondie/incident-scout && cd incident-scout
uv sync
brew install terminal-notifier        # optional: grouped notifications that open a link
```

**2. Point it at your telemetry and write rules.**

```bash
mkdir -p ~/.config/incident-scout
cp config.example.yaml ~/.config/incident-scout/config.yaml
```

The telemetry comes either from the standard HTTP APIs (`type: http`) or from an MCP server
that wraps them (`type: mcp`). If that MCP server is already registered in Claude Code,
`claude_mcp_server: <name>` reuses its URL and credentials, so no token is copied into
another file.

**3. Try the rules before trusting them.**

```bash
uv run scout check --dry-run          # what is wrong right now; no state, no notifications
uv run scout backtest --since 7d      # how often each rule would have fired
uv run scout notify-test              # does a notification reach you?
```

**4. Run it every five minutes.**

```bash
uv run scout install                  # macOS LaunchAgent; `scout uninstall` removes it
uv run scout status                   # open incidents, pending findings, health
tail -f ~/Library/Logs/incident-scout.log
```

launchd, unlike cron, runs a missed check as soon as the Mac wakes up and never starts a
second check while one is still running. With `quiet_hours` (for example 22:00-06:00, every
60 minutes) checks inside the window are skipped until the interval has passed. Rules then
see only their own query window once an hour, so keep sustained problems covered by
range-based rules or Alertmanager. `scout check --force` ignores the window.

## Rules

A rule is a query that returns only what is wrong, the same convention as Prometheus alerting
rules. Every returned series is one problem.

```yaml
rules:
  - name: http-5xx
    kind: logql                         # promql | logql | alertmanager
    severity: critical                  # info | warning | critical (critical plays a sound)
    query: 'sum by (app) (count_over_time({job="nginx"} | json | status >= 500 [5m])) >= 10'
    summary: '{app}: {value:.0f}x HTTP 5xx in 5 min'
    key_labels: [app]                   # what identifies one problem (default: all labels)
    for_runs: 1                         # consecutive checks before notifying
```

| Kind | Evaluates | Notes |
|---|---|---|
| `promql` | instant query | Range-based rules (`avg_over_time(...[15m]) < 0.7`) catch flapping that single samples miss |
| `logql` | Loki metric query, latest point | Aggregate in the query; raw log lines are not supported |
| `alertmanager` | active, unsilenced alerts | `match` filters labels by regex, severity comes from the alert's label |

`vars` defines `$name` placeholders, so a label selector shared by many rules is written once.

## How it behaves

- **One notification per change.** An incident is opened when a rule has returned a problem
  for `for_runs` consecutive checks. It is resolved after `resolve_after` clean checks. In
  between, nothing repeats. The resolution replaces the original notification in
  Notification Center.
- **Blind is not healthy.** When no rule can be evaluated (VPN down, server unreachable),
  open incidents are frozen instead of resolved. After `blind_after` checks one *"monitoring
  is blind"* notification goes out, and another when telemetry is back. A single broken rule
  is reported the same way, without affecting the others.
- **No storms.** More events than `max_per_run` in one check collapse into a single summary.
- **Read-only.** incident-scout only queries telemetry. State lives in one SQLite file
  (`~/.local/share/incident-scout/state.db`).

## Backtesting

`scout backtest` replays `promql` rules through range queries in daily chunks and groups the
moments a rule fired into episodes. It counts only episodes long enough to pass `for_runs`.
Some MCP servers let log queries look back only from "now", without setting a step. For
those, `logql` rules are replayed in 12-hour chunks reached with LogQL `offset`, so the
server's automatic step stays below the rule's window and short spikes are not stepped over.

The same replay is the basis of the evaluation on the roadmap: known incidents with known
start times, scored for detection latency and false alarms.

## Development

```bash
uv sync
uv run pytest --cov          # no network needed: telemetry, MCP and notifiers are faked
uv run ruff check . && uv run ruff format --check .
uv run mypy                  # strict mode
uvx pre-commit install       # ruff, mypy and gitleaks on every commit
```

## Roadmap

- **Investigator on a local LLM.** For a new incident, deterministic code collects an
  evidence pack: metrics around the start, the most frequent error lines, recent deploys,
  and similar past tickets from [ticket-precedent](https://github.com/bondie/ticket-precedent).
  A local model (Ollama) then writes a short hypothesis into the notification. Logs never
  leave the machine.
- **Evaluation.** A docker-compose demo stack with fault injection (database killed, 5xx
  burst, full disk, expiring certificate). It would measure detection and false alarms, and
  compare a local model's diagnoses with Claude's on the same evidence.
- Reminders for long-open critical incidents, a systemd timer for Linux.

## License

[MIT](LICENSE)
