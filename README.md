# incident-scout

[![CI](https://github.com/bondie/incident-scout/actions/workflows/ci.yml/badge.svg)](https://github.com/bondie/incident-scout/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A second pair of eyes on your production, running on your laptop.** incident-scout checks
Prometheus (or VictoriaMetrics), Loki, Alertmanager and Amazon CloudWatch every five minutes
with deterministic rules. It sends one notification when a problem starts and one when it is gone. It also tells
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
if installed, `osascript` otherwise), optionally [ntfy](https://ntfy.sh) for your phone and
a Microsoft Teams channel (see [below](#how-it-behaves)).

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

The telemetry comes from the standard HTTP APIs (`type: http`), from an MCP server that
wraps them (`type: mcp`), from Amazon CloudWatch (`type: cloudwatch`, see
[below](#amazon-cloudwatch)), from Elasticsearch (`type: elasticsearch`, see
[below](#elasticsearch)), or from Cloudflare's analytics
(`type: cloudflare`, see [below](#cloudflare)). If the MCP server is already registered in Claude Code,
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
| `alertmanager` | active, unsilenced alerts | `match` filters labels by regex, severity comes from the alert's label; on a CloudWatch source, alarms in the ALARM state |
| `cloudwatch` | Metrics Insights query or metric math, last complete period | `since` is the period; `above` or `below` keeps only the problems |
| `logs_insights` | Logs Insights query over the last `since` | Name the number `value`; `filter` after `stats` keeps only the problems |
| `elasticsearch` | documents matching a query over the last `since`, in total or per `group_by` | Needs an `elasticsearch` source; `above` or `below` keeps only the problems |
| `cloudflare` | requests of a zone matching a filter over the last `since`, in total or per `group_by` dimensions | Needs a `cloudflare` source; counts are sampled estimates; `above` or `below` keeps only the problems |
| `tls` | days until the certificate of each `host:port` expires | Works on any source; `below` keeps only the problems |

`vars` defines `$name` placeholders, so a label selector shared by many rules is written once.

With `key_labels`, series that share a key are **one problem**: they are merged into one
finding whose value is their sum, `{count}` is how many series were merged, and every other
label that differs between them becomes a list of its distinct values (five shown, then
`+N`). `rewrite` cleans label values with `[regex, replacement]` pairs, in order, before the
key and the summary are built, so a log rule that returns one series per record and error
text still opens one incident per bug:

```yaml
  - name: connector-import-failed
    kind: logs_insights
    log_groups: ['$logs']
    query: 'filter level = "error" | stats count(*) as value by type, code, reason'
    key_labels: [type, reason]
    record_labels: [code]                                  # one record: a customer
    rewrite:
      reason:
        - ['\s*\([^)]*\)\.?$', '']                        # trailing "(x)." / "(EB2-1.5-125-60x104)."
        - ['\s*\[(entityType|externalCode): [^\]]*\]', '']
        - ['(externalCode: )[^)\s]+', '\1…']
        - ['(?:[A-Za-z]+\\\\)+([A-Za-z]+)', '\1']         # App\\Entity\\Customer -> Customer
    summary: '$shop: KARAT {type} se nepropsal na e-shop ({count}×: {code}) – {reason}'
```

Fourteen customers whose first name is too short are then one incident,
`KARAT customer se nepropsal na e-shop (14×: C1, C2, C3, C4, C5 +9) – First name is too short`.
A rule with neither `key_labels` nor `rewrite` keeps every series apart. Alertmanager rules
are not rewritten. `record_labels` name what one merged series stands for, here a customer:
ticket cards then count the distinct records the problem hit. Without them, as for metric
rules whose other labels are only an instance or a job, cards count incidents.
`resolve_after` on a rule overrides the global one, so a failure that recurs every hour stays
one incident instead of a notification every hour.

Failures that arrive in bursts, such as records an ERP import keeps rejecting, can be
**gathered before they are told**. With `hold`, a new incident is opened quietly and
announced once the hold is over, with everything it gathered meanwhile; a one-off failure is
still announced, only later, and is never resolved before it was told. `problem_labels` tell
apart the problems one incident gathers when its key is broader than one bug:

```yaml
  - name: connector-import-failed
    kind: logs_insights
    log_groups: ['$logs']
    query: 'filter level = "error" | stats count(*) as value by type, code, reason'
    key_labels: [type]                 # one incident per record type...
    problem_labels: [reason]           # ...that lists every reason it met
    record_labels: [code]
    hold: 2h
    summary: '$shop: {type} import failed ({count}x: {code}) - {reason}'
```

The summary then covers the whole incident, not only the latest check: `{count}` is the
number of records, `{code}` and `{reason}` list every record and reason seen so far. A reason
that first appears after the announcement is told on its own (*new: ...*). Keep a separate
rule without `hold` for failures that must not wait.

## Amazon CloudWatch

Each AWS account is one named source. A rule or an evidence query with `sources: [a, b]` runs
once per account, as `rule@a` and `rule@b`, and the source's `vars` fill its placeholders,
so one rule covers several accounts with the same layout:

```yaml
sources:
  shop-a: {type: cloudwatch, profile: monitoring-shop-a, region: eu-central-1,
           vars: {shop: shop-a, logs: /ecs/shop-a}}
  shop-b: {type: cloudwatch, profile: monitoring-shop-b, region: eu-central-1,
           vars: {shop: shop-b, logs: /ecs/shop-b}}

rules:
  - name: lb-5xx
    kind: cloudwatch
    sources: [shop-a, shop-b]
    query: SELECT SUM(HTTPCode_Target_5XX_Count) FROM SCHEMA("AWS/ApplicationELB", LoadBalancer) GROUP BY LoadBalancer
    above: 9
    summary: '$shop: {value:.0f}x HTTP 5xx in 5 min'
```

Credentials come from an ordinary AWS profile. A monitor that runs unattended needs keys that
do not expire after a few hours, so give it its own read-only IAM user:
[docs/aws-readonly-policy.json](docs/aws-readonly-policy.json) allows reading metrics and
alarms, Logs Insights queries on the log groups you name, and the ECS service list for
deployments, nothing else. Metric rules are cheap; a Logs Insights rule scans its whole
window on every check, so keep log rules few and windows short.

## Elasticsearch

An `elasticsearch` source counts log documents, for example errors of an integration that
writes its logs to Elasticsearch. The rule's `query` is an Elasticsearch query clause, written
as YAML or as JSON text; it is combined with a range filter on `time_field` (default
`timestamp`) over the last `since` (default `5m`). With `group_by`, a terms aggregation (up to
50 buckets) yields one series per value, labelled by the field without `.keyword`
(`node.keyword` becomes `{node}`). Without it, the rule sees one series with the total, zero
included, so `below: 1` can also say that logs stopped arriving. `index` on the rule overrides
the source's.

```yaml
sources:
  orchesty-logs: {type: elasticsearch, url: 'http://elasticsearch:9200', index: 'orchesty-*',
                  vars: {shop: shop-a}}   # headers: {Authorization: ...} and timeout as for http

rules:
  - name: erp-link-errors
    kind: elasticsearch
    source: orchesty-logs
    query:
      bool:
        filter:
          - term: {level.keyword: error}
          - terms: {message.keyword: ['Download data from ERP', 'Save data to erp [response]']}
    group_by: node.keyword
    since: 30m
    above: 2
    summary: '$shop: {node} failed to talk to the ERP {value:.0f}x in 30 min'
```

## Cloudflare

A `cloudflare` source counts the requests of one zone from the GraphQL Analytics API
(`httpRequestsAdaptiveGroups`), for example partner bots that the WAF challenged, which never
reach the origin and so never show in its logs. It needs the zone ID and an API token with
only *Zone > Analytics > Read* on that zone. The rule's `query` is the dataset's filter object,
written as YAML or as JSON text; it is combined with the window of the last `since` (default
`5m`). `group_by` lists dimensions (`clientRequestHTTPHost`, `clientRequestPath`, `userAgent`,
`securityAction`, ...); each combination is one series labelled by the dimension names, up to
50 per check, most requests first. Without it, the rule sees the total, zero included.

Adaptive analytics are sampled, so a rare request can be missed in a short window and counts
are estimates; a window of hours suits events that happen a few times a day. A query may span
at most the zone's retention (about a month on the Pro plan). Count only what a person must
act on: a busy zone blocks scanners all day, so filter on the paths or user agents of known
partners rather than on every 403.

```yaml
sources:
  edge: {type: cloudflare, zone: '<zone id>', token: '${CLOUDFLARE_API_TOKEN}'}

rules:
  - name: partner-bot-blocked
    kind: cloudflare
    source: edge
    query:
      edgeResponseStatus: 403
      OR:
        - clientRequestPath_like: '/feed/%'
        - userAgent_like: '%Zbozi%'
    group_by: [clientRequestHTTPHost, userAgent]
    since: 24h
    above: 0
    summary: '{clientRequestHTTPHost}: {userAgent} blocked {value:.0f}x in 24 h'
```

## TLS certificates

A `tls` rule reads the certificate of every `host:port` in its `query` (a list, or a comma or
space separated string) straight from a TLS handshake, so it also covers ports no HTTP probe
sees, such as a message broker. It does not verify the certificate, so an expired or
self-signed one is still read. Each target is one series valued in days until `notAfter`,
negative once it has expired, with the labels `target`, `subject` and `issuer` (common names),
`not_after` and `error`. A target that cannot be reached within 10 s is valued -9999 and its
`error` says why, so a `below` rule fires for it too; the other labels are then empty, so one
summary fits both. Incidents are keyed by `target` unless `key_labels` says otherwise. The rule
ignores its source's telemetry, but still runs inside that source's connection, so pick a
source that opens without a network call (http or elasticsearch) or one you rely on anyway.

```yaml
  - name: erp-certificate
    kind: tls
    source: orchesty-logs
    query: ['erp.example.com:9093', 'shop.example.com:443']
    below: 14
    summary: '{target}: valid until {not_after}{error} ({value:.1f} days)'
```

Both kinds need `above` or `below`; without a threshold every series would be a problem.

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
- **Incidents in Teams.** With `notify.teams_url`, a Workflows webhook ("Post to a channel
  when a webhook request is received", triggered by *anyone*), every incident posts an
  Adaptive Card when it opens and a short one when it resolves (`notify.teams_kinds`, by
  default `[opened, resolved]`). The card is one row, like an issue in Sentry's list: the
  rule's `title` as a link to the telemetry, the summary without its leading `shop: ` behind a
  marker in the severity's colour, and a meta line `SCOUT-47 | Critical | Shop | rule` after
  the shop's logo, only the severity coloured (green *Resolved* once it ends). At the right
  stand when it started and, for rules with `record_labels` or a summary counting `N×`, the
  number of records; a resolved card shows how long it lasted and when it ended. Teams writes
  the dates with its `DATE` and `TIME` functions, in the reader's language and time zone. It
  waits until the check's investigation is done, so a diagnosis made in the same check
  arrives as a *Cause* line under the row; a diagnosis made in a later check is not posted
  on its own. Labels follow `investigator.language` (English without an investigator). Long
  texts are clipped, a card over 27 KB drops its logo, and a failing webhook is logged
  without stopping the check. Use a different channel than the ticket proposals.
- **Read-only.** incident-scout only queries telemetry. State, history and evidence live in
  one SQLite file (`~/.local/share/incident-scout/state.db`).
- **A file for viewers.** Every check and decision rewrites `status.json` next to the
  database: health, failing rules, open and pending incidents, undecided ticket proposals
  with their decision page, and the last resolved ones. A desktop viewer reads it instead of
  the database; `scout status --json` prints the same. It holds the proposals' tokens, so
  only its owner can read it.

## Backtesting

`scout backtest` replays `promql` rules through range queries in daily chunks and groups the
moments a rule fired into episodes. `cloudwatch` rules are replayed the same way, with their
own period as the step and their threshold applied to every point; `logs_insights`,
`elasticsearch`, `cloudflare` and `tls` rules cannot be replayed yet. It counts only episodes long enough to pass `for_runs`.
Some MCP servers let log queries look back only from "now", without setting a step. For
those, `logql` rules are replayed in 12-hour chunks reached with LogQL `offset`, so the
server's automatic step stays below the rule's window and short spikes are not stepped over.

The same replay is the basis of the evaluation on the roadmap: known incidents with known
start times, scored for detection latency and false alarms.

## Investigator

The alert says *what* is wrong. A few seconds later a second notification says *why*, written
by a local model through [Ollama](https://ollama.com), so logs never leave the machine:

```text
🔴 http-5xx       prod-shop-a: 1530x HTTP 5xx in 5 min
🔎 http-5xx       Every product and cart request calls PriceResolver::resolveForChannel(),
                  which no longer exists; the last release probably removed it [high]
```

1. **Evidence pack.** Deterministic queries from the config run over a window around the
   start (30 minutes before, 10 after): 5xx and request timelines, the most frequent error
   messages, paths, user agents and clients, probe results of the whole fleet, services that
   are down, CPU, memory and disk. On AWS the same questions are answered by CloudWatch
   metrics and Logs Insights, plus the ECS deployments and service events in the window.
   Without the deployments, a short burst of 5xx during a rollout was blamed on the one
   unrelated exception that happened to be logged; with them, the model tied it to the
   deployment. Similar past tickets come from
   [ticket-precedent](https://github.com/bondie/ticket-precedent), searched with the top
   line of the first `precedents_from` section that has data (the top error message, else
   e.g. the web server's error when PHP logged none), else with the alert summary.
2. **One model call.** The model gets the pack and must answer in a JSON schema: summary,
   scope (one shop or several), category, likely cause, confidence, key evidence and next
   steps. There are no tool calls and no agent loop, because small local models handle those
   poorly. A fixed pack makes every diagnosis reproducible and testable.
3. **Follow-up.** The diagnosis replaces the alert in Notification Center and is stored with
   the incident, together with the pack it was made from. The pack is kept even when the
   model fails. `max_per_hour` caps the model's work during an incident storm.

```bash
uv run scout investigate --incident 12                  # diagnose the stored pack again
uv run scout investigate --rule http-5xx --label shop=b --at 2026-03-12T14:05 --show-pack
uv run scout investigate --pack pack.json --model gemma4:12b
```

### Was the diagnosis right?

Every incident keeps a timeline of what happened to it (opened, diagnosed, resolved, and
whether monitoring went blind meanwhile), the evidence pack and the diagnosis. A short
review records whether the diagnosis was right, and a reviewed incident becomes an eval case,
so the model choice is checked against your own incidents, not only synthetic ones:

```bash
uv run scout history --since 30d                     # incidents with diagnosis and review state
uv run scout show 12 --pack                          # timeline, diagnosis, review, evidence
uv run scout review 12 --verdict correct --keywords "scan,bot"
uv run scout review 13 --verdict wrong --cause "Disk full of logs" --category resources \
    --keywords "disk" --keywords "log"
uv run scout export-case 12 --out ~/incident-cases    # then: scout eval ~/incident-cases ...
```

A review takes over the category and scope of the diagnosis unless you correct them, and
its cause when the verdict is `correct`.
`--keywords` gives the terms a right cause has to name: each option is one group of
synonyms, and every group must match, the same as in the case files.

### Should this become a ticket?

Some incidents need a developer's work and a ticket for the project manager; most do not.
With a `tickets` section, an incident that lasts (seen for 30 minutes by default, from its
first to its latest sighting, so a one-off failure that stays open until `resolve_after` does
not count) or keeps coming back (the third time in 7 days) gets a **ticket proposal**: the model reads the incident, how often
the same problem happened, the diagnosis and the evidence, and recommends one of
*create a ticket*, *no ticket needed*, or *already in ticket X* (only for a similar ticket of
the same shop). It also drafts the ticket for the PM in JIRA markup: what happens and since
when, how often, the impact on customers, the evidence and what to check first.
A review that marks the diagnosis `wrong` replaces it in the model's input with the reviewed
cause, and a `partial` one is put next to it, so a proposal drafted after the review does not
repeat a cause a person has already rejected.

The proposal arrives as a card in a Microsoft Teams channel, through a Workflows webhook
("Send webhook alerts to a channel", triggered by *anyone*, since the monitor does not sign
in). The card has the same row as the incident card: the proposed ticket title as a link to
the detail page, the reason, and a meta line with the id, the status (*ongoing*, *recurs*,
*growing*, *resolved*), the shop, the priority and the rule; at the right how many records
(with `record_labels`) or incidents the problem had in `recurring_days` and when it was last
seen. Under the row come the likely cause, the affected records and the recommendation.
**Approve the ticket** and **Reject with a reason** open a small page served on your
machine (`scout serve`, installed next to the checks by `scout install`): it records the
decision, with a reason and the ticket that already covers the problem when you reject, and
shows the ticket text to copy for the PM. Nothing reaches the PM without a person approving
it, and every link carries a random token, so the buttons do nothing for anyone else in the
channel.

A proposal card also carries a collapsed block for a chat bot in the channel (*For the bot*):
the text for the PM in the element with id `handoff.pm_message`, the same text the detail page
copies, and the ticket draft in the fact set `handoff.ticket` with the JIRA project of the shop
(`jira_projects: {shop-a: SHOPA}`) and the title. The ids stay when the labels change. The bot
takes the text as content only; what happens with it is decided by a person's command.

Only proposals that need a decision reach Teams. *No ticket needed* stays on the console and
the page and is marked rejected with the model's reason. *Already in ticket X* posts a short
card with only a link to the detail, and the ticket covers the next incidents of the problem.

Every incident has an id such as `SCOUT-47`, in the card's meta line, the page, `scout show`
and `scout history`; every command takes it as well as the plain number.

The shop is named on every card, from the rule's `shop_title`, else `shop_titles:
{shop-a: Shop A}` by the shop var or label, else the shop capitalised.
A source shared by several shops (one Orchesty cluster for all of them) can name the shop
an incident hit from one of its labels: `vars: {shop: orchesty, shop_label: namespace,
shop_pattern: '^orchesty-(?P<shop>[a-z0-9]+)-prod$'}` takes the `shop` group of the pattern
from the `namespace` label (the label must be in the rule's `key_labels`; without a pattern
the whole label is the shop). `shop_aliases: {albra: prod-hetzner-albra}` turns the name
found into the key of `logos` and `shop_titles`. The card then shows that shop's logo and
name with the source as context (`Albra | Orchesty`); a label that does not match leaves
the source's own shop.
A logo per shop goes in front of the shop name: `logos: {shop-a: ~/logos/shop-a.png}`. A
local png or jpg of at most 18 KB is embedded in the card, an `https://` URL is used as it is.
Embedding makes a file a third bigger and Teams refuses a card of about 28 KB, so a card that
would pass 27 KB goes out without its logo, with a warning in the log.
Teams cannot load `.ico` files or `localhost` URLs, so those are left out.

```bash
uv run scout propose 12                 # a proposal now, whatever its age; --no-send prints it
uv run scout propose SCOUT-12 --card    # preview the Teams card of the stored proposal
uv run scout decide 12 approve          # the same decision without Teams
uv run scout decide 12 reject --ticket SHOP-123 --reason "known, fixed in the next release"
uv run scout show 12                    # timeline, diagnosis, proposal and decision
```

`--no-send` still stores the proposal, and one that needs no ticket or names an existing one
is decided at once, as in a check. `--card` only prints the card of the stored proposal: it
calls no model, stores nothing and sends nothing.

A decision with `--ticket` or `--reason` covers the problem: while it is among the incidents
of the last `recurring_days`, a new incident of the same problem is still opened and notified,
but instead of a new proposal it gets a *covered by SHOP-123* line in the log and timeline,
nothing in Teams. Without a ticket or reason, any earlier proposal of the problem in that
window blocks a new one, as before. A decision without them keeps the ones recorded earlier.
For a rule with `problem_labels`, both count per problem: a decision covers an incident only
when it was about every problem the incident has, and only incidents that share a problem
add up to *keeps coming back*. A held incident gets no proposal before it is announced.

### Choosing a model

`scout eval` replays frozen evidence packs with known causes against any number of models.
`eval/cases/` holds twelve synthetic incidents: a database or Redis outage, a full disk,
memory exhaustion, a bad deploy, a payment gateway timeout, a fleet-wide network problem,
bot traffic, a search engine outage, harmless noise, an expiring certificate, and one case
without enough evidence.

```bash
uv run scout eval eval/cases --models gemma4:12b,gpt-oss:20b --out results.json
uv run scout report results.json --cases eval/cases      # combine runs, per-case matrix
```

Each diagnosis is scored on four checks, and the score is their mean:

- **Category** and **Scope** are compared with the expected values.
- **Cause** passes when the stated cause contains the expected key terms. Czech and English
  wording both count, and accents are ignored.
- **Grounded** fails when the answer names a class, method, error code or host that is not
  in the evidence pack, which catches invented details.

### Results

Seven local models ran on an Apple M1 Pro with 32 GB of RAM, in November 2026, with
answers in Czech. Each model saw the same packs and answered once, at temperature 0, with
thinking switched off (`gpt-oss` cannot switch it off and ran at `low`). Besides the
twelve public cases, every model also saw **eight real incidents** from the e-commerce fleet
the tool was built for. Those packs contain production logs and stay private; only the
aggregate scores are published.

| Model | Size | Synthetic (12) | Real incidents (8) | All (20) | p50 latency |
|---|---:|---:|---:|---:|---:|
| **`gemma4:12b`** | 8 GB | 0.96 | **1.00** | **0.97** | 39 s |
| `gemma4:26b` | 18 GB | 0.96 | 0.97 | 0.96 | **20 s** |
| `qwen3.8:27b` | 18 GB | **1.00** | 0.88 | 0.95 | 81 s |
| `gpt-oss:20b` | 13 GB | 0.92 | 0.78 | 0.86 | 15 s |
| `granite4.2:8b` | 5 GB | 0.90 | 0.75 | 0.84 | 31 s |
| `qwen2.5:14b` | 9 GB | 0.94 | 0.69 | 0.84 | 54 s |
| `nemotron-3.5-lightning:30b-a3b` | 19 GB | 0.73 | 0.69 | 0.71 | 15 s |

What the numbers say:

- **Real incidents separate the models; synthetic ones barely do.** Six of the seven models
  score 0.90 or more on the synthetic cases, but only three reach 0.88 on real incidents.
  The typical miss is a vulnerability scan (a burst of requests for `/.env` and
  `wp-config.php` from one address) reported as an application bug, a connector failure or
  an overloaded CPU, even when the pack shows a CPU load below 0.5.
- **Size is not the deciding factor.** The 8 GB `gemma4:12b` matched or beat the 18-19 GB
  models. The 30B mixture-of-experts `nemotron` is fast, but 15% of its answers were not
  valid JSON.
- **The pack matters as much as the model.** In the first run, the internal frontend was the
  busiest client in the scan incidents, and even the best models named it as the attacker.
  The keyword check cannot catch a wrong culprit described in the right words; reading the
  answers did. The fix belonged to the evidence: client and user-agent sections now leave out
  internal traffic, so the pack shows what normal traffic looks like.
- **Runtimes have quirks.** One model kept generating until a timeout, so answers are now
  capped at `max_tokens`. One runtime rejects schema-constrained output (HTTP 501), so the
  investigator retries with the schema described in the prompt and reads the JSON leniently.
- **Caveats.** Twenty cases with one run each means a difference of 0.05 is a single case.
  The synthetic cases were written by the same author as the scoring rules.

**Thinking does not pay off here.** The winner with thinking switched on scored 0.86
instead of 0.97, and its median latency rose from 39 s to 99 s. Two answers exceeded the
five-minute timeout, and on three cases the cause got vaguer. Thinking fixed one case, the
scope of the fleet-wide network problem. For a pack that already holds the decisive
evidence, careful reading beats long deliberation, so the recommended setting is
`think: false`.

## Development

```bash
uv sync
uv run pytest --cov          # no network needed: telemetry, MCP, Ollama and notifiers are faked
uv run ruff check . && uv run ruff format --check .
uv run mypy                  # strict mode
uvx pre-commit install       # ruff, mypy and gitleaks on every commit
```

## Roadmap

- **Fault-injection demo stack.** docker-compose with a shop, a database, Prometheus and
  Loki, where faults are injected on purpose (database killed, 5xx burst, full disk,
  expiring certificate). It would measure detection latency and false alarms end to end.
- Comparing local models with a hosted model (Claude) on the same evidence packs.
- Reminders for long-open critical incidents, a systemd timer for Linux.
- Approved proposals straight into JIRA, with the PM as reporter, once the drafts prove
  reliable.

## License

[MIT](LICENSE)
