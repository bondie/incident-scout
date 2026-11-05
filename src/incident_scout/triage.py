"""Collect evidence for an incident and ask the investigator model about it."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping, Sequence
from datetime import datetime

from .config import Config, ConfigError, InvestigatorConfig, build_telemetry
from .evidence import EvidencePack, PrecedentFinder, collect
from .investigator import OllamaInvestigator


def investigator_config(config: Config) -> InvestigatorConfig:
    if config.investigator is None:
        raise ConfigError("No `investigator` section in the config")
    return config.investigator


def investigator(config: Config, model: str | None = None) -> OllamaInvestigator:
    settings = investigator_config(config)
    return OllamaInvestigator(
        model=model or settings.model,
        url=settings.url,
        language=settings.language,
        think=settings.think,
        timeout=settings.timeout_seconds,
    )


async def gather(
    config: Config,
    rule: str,
    severity: str,
    summary: str,
    labels: Mapping[str, str],
    started_at: float,
) -> EvidencePack:
    settings = investigator_config(config)
    finder = (
        command_precedents(settings.precedents_command) if settings.precedents_command else None
    )
    source = next((r.source for r in config.rules if r.name == rule), "default")
    async with build_telemetry(config.source_options(source)) as telemetry:
        return await collect(
            telemetry,
            [query for query in settings.evidence if query.source == source],
            rule,
            severity,
            summary,
            labels,
            started_at,
            before=settings.before_minutes * 60,
            after=settings.after_minutes * 60,
            precedents=finder,
            precedents_from=settings.precedents_from,
        )


def command_precedents(command: Sequence[str]) -> PrecedentFinder:
    """Search past tickets with an external command that prints a JSON list, such as
    ticket-precedent's `tp search --json`."""

    def find(text: str) -> list[str]:
        completed = subprocess.run(  # noqa: S603 - the command comes from the user's own config
            [*command, text[:500]], capture_output=True, text=True, timeout=120, check=True
        )
        lines = []
        for item in json.loads(completed.stdout or "[]"):
            spent = f", {item['time_spent_hours']} h" if item.get("time_spent_hours") else ""
            status = " ".join(filter(None, [item.get("status"), item.get("resolution")]))
            snippet = " ".join(str(item.get("snippet") or "").split())[:200]
            lines.append(f"{item.get('key')}: {item.get('title')} [{status}{spent}] {snippet}")
        return lines or ["(no similar tickets)"]

    return find


def started_at(opened_at: str) -> float:
    return datetime.fromisoformat(opened_at).timestamp()
