from __future__ import annotations

import inspect
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from pathlib import Path
from string import Template
from typing import Any, cast, get_args

import yaml

from .evidence import EvidenceKind, EvidenceQuery
from .models import SEVERITIES
from .rules import Rule, RuleKind
from .sources.cloudwatch import CloudWatchTelemetry
from .sources.http import HttpTelemetry
from .sources.mcp import McpTelemetry, McpTools

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
CLOUDWATCH_KINDS = ("cloudwatch", "logs_insights")
DEFAULT = "default"


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class NotifyConfig:
    desktop: bool = True
    ntfy_url: str | None = None
    ntfy_topic: str | None = None
    ntfy_token: str | None = None
    max_per_run: int = 5


@dataclass(frozen=True)
class InvestigatorConfig:
    model: str
    url: str = "http://localhost:11434"
    language: str = "English"
    think: bool | str | None = None
    before_minutes: int = 30
    after_minutes: int = 10
    max_per_hour: int = 4
    timeout_seconds: int = 300
    precedents_command: tuple[str, ...] = ()
    precedents_from: str | None = None
    evidence: tuple[EvidenceQuery, ...] = ()


@dataclass(frozen=True)
class TicketsConfig:
    """When to propose a ticket for the PM, and where to send the proposal."""

    teams_url: str | None = None
    after_minutes: int = 30
    recurring: int = 3
    recurring_days: int = 7
    max_per_hour: int = 4
    port: int = 8765


@dataclass(frozen=True)
class QuietHours:
    """A daily window, possibly across midnight, in which checks run less often."""

    start: time
    end: time
    interval_minutes: int = 60

    def active(self, moment: datetime) -> bool:
        clock = moment.astimezone().time()
        if self.start <= self.end:
            return self.start <= clock < self.end
        return clock >= self.start or clock < self.end

    def resting(self, now: datetime, last_run: datetime | None) -> bool:
        """True when this check should be skipped; a minute of slack absorbs launchd jitter."""
        if last_run is None or not self.active(now):
            return False
        return now - last_run < timedelta(minutes=self.interval_minutes - 1)


@dataclass(frozen=True)
class Config:
    source: Mapping[str, Any]
    rules: list[Rule]
    sources: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    state_path: Path = field(default_factory=lambda: data_dir() / "state.db")
    interval_minutes: int = 5
    blind_after: int = 3
    resolve_after: int = 2
    timeout_seconds: int = 120
    quiet_hours: QuietHours | None = None
    investigator: InvestigatorConfig | None = None
    tickets: TicketsConfig | None = None
    logos: Mapping[str, str] = field(default_factory=dict)

    def rule(self, name: str) -> Rule:
        for rule in self.rules:
            if rule.name == name:
                return rule
        raise ConfigError(f"Unknown rule {name!r}; known: {', '.join(r.name for r in self.rules)}")

    def source_options(self, name: str = DEFAULT) -> Mapping[str, Any]:
        if name == DEFAULT:
            return self.source
        if name not in self.sources:
            raise ConfigError(f"Unknown source {name!r}")
        return self.sources[name]


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "incident-scout"


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "incident-scout"


def default_config_path() -> Path:
    override = os.environ.get("INCIDENT_SCOUT_CONFIG")
    return Path(override) if override else config_dir() / "config.yaml"


def load_config(path: Path | None = None) -> Config:
    path = path or default_config_path()
    if not path.exists():
        raise ConfigError(f"No config at {path}; start from config.example.yaml")
    raw = yaml.safe_load(path.read_text()) or {}
    env = _environment(path.parent, raw.get("env_files") or [])
    raw = _expand(raw, env)
    variables = {str(k): str(v) for k, v in (raw.get("vars") or {}).items()}
    sources = _sources(raw)
    rules = [rule for item in raw.get("rules") or [] for rule in _rules(item, variables, sources)]
    names = [rule.name for rule in rules]
    if len(names) != len(set(names)):
        raise ConfigError("Rule names must be unique")
    notify = _build(NotifyConfig, raw.get("notify") or {}, "notify")
    options: dict[str, Any] = {
        key: int(raw[key])
        for key in ("interval_minutes", "blind_after", "resolve_after", "timeout_seconds")
        if key in raw
    }
    if raw.get("state_path"):
        options["state_path"] = Path(raw["state_path"]).expanduser()
    if raw.get("quiet_hours"):
        options["quiet_hours"] = _quiet_hours(raw["quiet_hours"])
    if raw.get("investigator"):
        options["investigator"] = _investigator(raw["investigator"], variables, sources)
    if raw.get("tickets"):
        if "investigator" not in options:
            raise ConfigError("tickets need the investigator section, which runs the model")
        options["tickets"] = _build(TicketsConfig, raw["tickets"], "tickets")
    if raw.get("logos"):
        if not isinstance(raw["logos"], Mapping):
            raise ConfigError("logos must map a shop to a png/jpg file or an https URL")
        options["logos"] = {str(shop): str(logo) for shop, logo in raw["logos"].items()}
    named = {name: value for name, value in sources.items() if name != DEFAULT}
    return Config(source=sources[DEFAULT], rules=rules, sources=named, notify=notify, **options)


def _sources(raw: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    sources: dict[str, Mapping[str, Any]] = {DEFAULT: raw.get("source") or {}}
    for name, options in (raw.get("sources") or {}).items():
        if name == DEFAULT:
            raise ConfigError("`default` is reserved for the `source` section")
        sources[str(name)] = dict(options or {})
    return sources


def _targets(item: dict[str, Any], where: str) -> list[str | None]:
    """`sources: [a, b]` repeats an item for every source; None keeps a single item as it is."""
    targets = item.pop("sources", None)
    if targets is None:
        return [None]
    if isinstance(targets, str) or not targets:
        raise ConfigError(f"{where}.sources must be a list of source names")
    return [str(target) for target in targets]


def _variables(
    variables: Mapping[str, str], sources: Mapping[str, Mapping[str, Any]], name: str
) -> dict[str, str]:
    if name not in sources:
        raise ConfigError(f"Unknown source {name!r}; known: {', '.join(sources)}")
    own = {
        str(key): Template(str(value)).safe_substitute(variables)
        for key, value in (sources[name].get("vars") or {}).items()
    }
    return {**variables, "source": name, **own}


def _rules(
    item: Mapping[str, Any],
    variables: Mapping[str, str],
    sources: Mapping[str, Mapping[str, Any]],
) -> list[Rule]:
    data = dict(item)
    rules = []
    for target in _targets(data, f"rules.{data.get('name') or '?'}"):
        copy = dict(data)
        if target is not None:
            copy |= {"name": f"{data.get('name')}@{target}", "source": target}
        rules.append(_rule(copy, _variables(variables, sources, copy.get("source", DEFAULT))))
    return rules


def _investigator(
    value: Mapping[str, Any],
    variables: Mapping[str, str],
    sources: Mapping[str, Mapping[str, Any]],
) -> InvestigatorConfig:
    data = dict(value)
    if not data.get("model"):
        raise ConfigError("investigator.model is required, e.g. qwen3.8:27b")
    queries = []
    for item in data.pop("evidence", None) or []:
        query = dict(item)
        if query.get("kind") not in get_args(EvidenceKind):
            raise ConfigError(f"investigator.evidence kind must be one of {get_args(EvidenceKind)}")
        for target in _targets(query, "investigator.evidence"):
            copy = dict(query) | ({"source": target} if target else {})
            known = _variables(variables, sources, copy.get("source", DEFAULT))
            copy["query"] = Template(str(copy.get("query", ""))).safe_substitute(known)
            copy["log_groups"] = _substituted(copy.get("log_groups") or (), known)
            queries.append(
                cast(EvidenceQuery, _build(EvidenceQuery, copy, "investigator.evidence"))
            )
    data["evidence"] = tuple(queries)
    command = data.get("precedents_command") or ()
    data["precedents_command"] = tuple(
        str(Path(part).expanduser()) if part.startswith("~") else str(part) for part in command
    )
    return cast(InvestigatorConfig, _build(InvestigatorConfig, data, "investigator"))


def _quiet_hours(value: Mapping[str, Any]) -> QuietHours:
    quiet = dict(value)
    for key in ("start", "end"):
        if key not in quiet:
            raise ConfigError(f"quiet_hours.{key} is required, e.g. '22:00'")
        quiet[key] = _clock(quiet[key], f"quiet_hours.{key}")
    return cast(QuietHours, _build(QuietHours, quiet, "quiet_hours"))


def _clock(value: Any, where: str) -> time:
    if isinstance(value, int):  # YAML 1.1 reads an unquoted 22:00 as sexagesimal 1320
        return time(value // 60 % 24, value % 60)
    try:
        hours, minutes = str(value).split(":")
        return time(int(hours), int(minutes))
    except ValueError as error:
        raise ConfigError(f"{where} must look like '22:00', got {value!r}") from error


def build_telemetry(
    source: Mapping[str, Any],
) -> McpTelemetry | HttpTelemetry | CloudWatchTelemetry:
    options = dict(source)
    options.pop("vars", None)
    kind = options.pop("type", "mcp")
    if kind == "http":
        return cast(HttpTelemetry, _build(HttpTelemetry, options, "source"))
    if kind == "cloudwatch":
        allowed = {
            key: options[key] for key in ("profile", "region", "query_timeout") if key in options
        }
        if set(options) - set(allowed):
            raise ConfigError(
                f"source: unknown option(s) {', '.join(sorted(set(options) - set(allowed)))}"
            )
        return CloudWatchTelemetry(**allowed)
    if kind != "mcp":
        raise ConfigError(f"Unknown source type {kind!r}, expected mcp, http or cloudwatch")
    tools = _build(McpTools, options.pop("tools", None) or {}, "source.tools")
    server = options.pop("claude_mcp_server", None)
    if server:
        options = {**claude_mcp_server(str(server), options.pop("claude_config", None)), **options}
    if not options.get("url"):
        raise ConfigError("source.url or source.claude_mcp_server is required")
    return McpTelemetry(
        url=str(options["url"]),
        headers=dict(options.get("headers") or {}),
        tools=tools,
        timeout=float(options.get("timeout", 60)),
    )


def claude_mcp_server(name: str, claude_config: str | None = None) -> dict[str, Any]:
    """URL and headers of an MCP server registered in Claude Code (user scope), so the
    credentials stay where they already are instead of being copied into this config."""
    path = Path(claude_config).expanduser() if claude_config else Path.home() / ".claude.json"
    try:
        servers = json.loads(path.read_text()).get("mcpServers") or {}
    except (OSError, ValueError) as error:
        raise ConfigError(f"Cannot read {path}: {error}") from error
    server = servers.get(name)
    if not server or not server.get("url"):
        raise ConfigError(f"No HTTP MCP server {name!r} in {path}")
    headers = _expand(dict(server.get("headers") or {}), dict(os.environ))
    return {"url": server["url"], "headers": headers}


def _rule(item: Mapping[str, Any], variables: Mapping[str, str]) -> Rule:
    data = dict(item)
    name = data.get("name") or "?"
    if data.get("kind") not in get_args(RuleKind):
        raise ConfigError(f"rules.{name}.kind must be one of {get_args(RuleKind)}")
    if data.get("severity", "warning") not in SEVERITIES:
        raise ConfigError(f"rules.{name}.severity must be one of {SEVERITIES}")
    for key in ("query", "summary", "url", "title"):
        if isinstance(data.get(key), str):
            data[key] = Template(data[key]).safe_substitute(variables)
    for key in ("shop", "shop_title"):
        data.setdefault(key, variables.get(key, ""))
    if "key_labels" in data:
        data["key_labels"] = tuple(data["key_labels"])
    if "log_groups" in data:
        data["log_groups"] = _substituted(data["log_groups"], variables)
    if "rewrite" in data:
        data["rewrite"] = _rewrite(data["rewrite"], f"rules.{name}.rewrite")
    if data["kind"] != "alertmanager" and not data.get("query"):
        raise ConfigError(f"rules.{name}.query is required")
    if data["kind"] in CLOUDWATCH_KINDS:
        data.setdefault("since", "5m")
    if data["kind"] == "logs_insights" and not data.get("log_groups"):
        raise ConfigError(f"rules.{name}.log_groups is required for logs_insights")
    return cast(Rule, _build(Rule, data, f"rules.{name}"))


def _rewrite(value: Any, where: str) -> dict[str, tuple[tuple[str, str], ...]]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where} must map a label to a list of [regex, replacement] pairs")
    return {str(label): _rewrite_steps(steps, f"{where}.{label}") for label, steps in value.items()}


def _rewrite_steps(steps: Any, where: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(steps, list) or not all(
        isinstance(step, list) and len(step) == 2 for step in steps
    ):
        raise ConfigError(f"{where} must be a list of [regex, replacement] pairs")
    pairs = tuple((str(pattern), str(replacement or "")) for pattern, replacement in steps)
    for pattern, replacement in pairs:
        try:
            re.compile(pattern).sub(replacement, "")  # also checks group references
        except (re.error, IndexError) as error:
            raise ConfigError(f"{where}: invalid regex {pattern!r}: {error}") from error
    return pairs


def _substituted(values: Any, variables: Mapping[str, str]) -> tuple[str, ...]:
    items = [values] if isinstance(values, str) else list(values)
    return tuple(Template(str(item)).safe_substitute(variables) for item in items)


def _build(cls: Any, values: Mapping[str, Any], where: str) -> Any:
    known = set(inspect.signature(cls).parameters)
    unknown = set(values) - known
    if unknown:
        raise ConfigError(f"{where}: unknown option(s) {', '.join(sorted(unknown))}")
    return cls(**values)


def _environment(config_dir: Path, env_files: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for name in env_files:
        env.update(read_dotenv(Path(name).expanduser()))
    env.update(read_dotenv(config_dir / ".env"))
    env.update(os.environ)
    return env


def read_dotenv(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _expand(value: Any, env: Mapping[str, str]) -> Any:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            if match.group(1) not in env:
                raise ConfigError(f"Environment variable {match.group(1)} is not set")
            return env[match.group(1)]

        return _ENV.sub(replace, value)
    if isinstance(value, Mapping):
        return {key: _expand(item, env) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand(item, env) for item in value]
    return value
