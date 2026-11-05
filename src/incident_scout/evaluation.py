"""Score investigator models on frozen evidence packs with known causes."""

from __future__ import annotations

import re
import statistics
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from .evidence import EvidencePack, Section
from .investigator import Diagnosis, InvestigationError

# Tokens a model could only know from the evidence: PHP class paths, Class::method, error
# codes, CamelCase identifiers and hyphenated host or shop names.
_IDENTIFIER = re.compile(
    r"[A-Za-z_][\w\\]*\\[\w\\]+"
    r"|\b\w+::\w+"
    r"|\b[A-Z]{2,}\[?[A-Z]*\d[0-9A-Z]*\]?"
    r"|\b[A-Z][a-z]+(?:[A-Z][a-z0-9]+){2,}\b"
    r"|\b(?:prod|test|stage|dev)-[a-z0-9-]+\b"
)


@dataclass(frozen=True)
class Case:
    id: str
    pack: EvidencePack
    categories: tuple[str, ...]
    scope: str
    cause: tuple[tuple[str, ...], ...]
    note: str = ""


@dataclass(frozen=True)
class Score:
    case: str
    model: str
    valid: bool
    category: bool = False
    scope: bool = False
    cause: bool = False
    ungrounded: tuple[str, ...] = ()
    seconds: float = 0.0
    diagnosis: Diagnosis | None = None
    error: str | None = None

    @property
    def grounded(self) -> bool:
        return self.valid and not self.ungrounded

    @property
    def total(self) -> float:
        if not self.valid:
            return 0.0
        return (self.category + self.scope + self.cause + self.grounded) / 4


@dataclass
class ModelReport:
    model: str
    scores: list[Score] = field(default_factory=list)

    def rate(self, attribute: str) -> float:
        return statistics.fmean(float(getattr(s, attribute)) for s in self.scores)

    @property
    def latency(self) -> float:
        times = [s.seconds for s in self.scores if s.valid]
        return statistics.median(times) if times else 0.0


def load_cases(paths: Sequence[Path]) -> list[Case]:
    files = sorted(
        file
        for path in paths
        for file in ([path] if path.is_file() else [*path.glob("*.yaml"), *path.glob("*.yml")])
    )
    return [_case(yaml.safe_load(file.read_text()), file.stem) for file in files]


def _case(data: dict[str, Any], default_id: str) -> Case:
    raw = dict(data["pack"])
    started = _timestamp(raw["started_at"])
    pack = EvidencePack(
        rule=raw["rule"],
        severity=raw.get("severity", "warning"),
        summary=raw["summary"],
        labels={str(k): str(v) for k, v in (raw.get("labels") or {}).items()},
        started_at=started,
        window_start=_timestamp(raw.get("window_start", started - 1800)),
        window_end=_timestamp(raw.get("window_end", started + 600)),
        sections=[Section(s["name"], [str(line) for line in s["lines"]]) for s in raw["sections"]],
    )
    expect = data["expect"]
    categories = expect["category"]
    return Case(
        id=str(data.get("id", default_id)),
        pack=pack,
        categories=tuple([categories] if isinstance(categories, str) else categories),
        scope=expect["scope"],
        cause=tuple(tuple(group) for group in expect["cause"]),
        note=str(data.get("note", "")),
    )


def score(case: Case, diagnosis: Diagnosis) -> Score:
    stated = fold(f"{diagnosis.summary} {diagnosis.likely_cause}")
    cause = all(any(fold(word) in stated for word in group) for group in case.cause)
    return Score(
        case=case.id,
        model=diagnosis.model,
        valid=True,
        category=diagnosis.category in case.categories,
        scope=diagnosis.scope == case.scope,
        cause=cause,
        ungrounded=ungrounded(diagnosis, case.pack.render()),
        seconds=diagnosis.seconds,
        diagnosis=diagnosis,
    )


def ungrounded(diagnosis: Diagnosis, evidence: str) -> tuple[str, ...]:
    """Identifiers the diagnosis mentions that the evidence never contained."""
    said = " ".join(
        [diagnosis.summary, diagnosis.likely_cause, *diagnosis.key_evidence, *diagnosis.next_steps]
    )
    source = fold(evidence)
    missing = {
        token for token in _IDENTIFIER.findall(said) if fold(token).strip("\\:") not in source
    }
    return tuple(sorted(missing))


def fold(text: str) -> str:
    """Case- and accent-insensitive form, so Czech answers match plain keywords."""
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def evaluate(
    cases: Sequence[Case],
    diagnose: Callable[[EvidencePack], Diagnosis],
    model: str,
    progress: Callable[[Score], None] | None = None,
) -> ModelReport:
    report = ModelReport(model)
    for case in cases:
        try:
            result = score(case, diagnose(case.pack))
        except InvestigationError as error:
            result = Score(case=case.id, model=model, valid=False, error=str(error)[:300])
        report.scores.append(result)
        if progress:
            progress(result)
    return report


def rescore(rows: Sequence[dict[str, Any]], cases: Sequence[Case]) -> list[ModelReport]:
    """Score saved diagnoses again, e.g. after an expectation was corrected."""
    by_id = {case.id: case for case in cases}
    reports: dict[str, ModelReport] = {}
    for row in rows:
        case = by_id.get(row["case"])
        if case is None:
            continue
        report = reports.setdefault(row["model"], ModelReport(row["model"]))
        if row.get("diagnosis"):
            report.scores.append(score(case, Diagnosis(**row["diagnosis"])))
            continue
        report.scores.append(Score(case.id, row["model"], valid=False, error=row.get("error")))
    return list(reports.values())


def case_matrix(reports: Sequence[ModelReport]) -> str:
    """Per-case scores: C category, S scope, K cause, G grounded; '-' marks a miss."""
    models = sorted(reports, key=lambda r: -r.rate("total"))
    cases = list(dict.fromkeys(s.case for r in models for s in r.scores))
    header = "| Case | " + " | ".join(f"`{r.model}`" for r in models) + " |"
    lines = [header, "|---|" + "---|" * len(models)]
    for case in cases:
        cells = []
        for report in models:
            found = next((s for s in report.scores if s.case == case), None)
            if found is None or not found.valid:
                cells.append("invalid")
                continue
            marks = zip(
                "CSKG", (found.category, found.scope, found.cause, found.grounded), strict=True
            )
            cells.append("".join(mark if ok else "-" for mark, ok in marks))
        lines.append(f"| {case} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def markdown_table(reports: Sequence[ModelReport]) -> str:
    lines = [
        "| Model | Score | Category | Scope | Cause | Grounded | Valid JSON | p50 latency |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for report in sorted(reports, key=lambda r: -r.rate("total")):
        lines.append(
            f"| `{report.model}` | {report.rate('total'):.2f} | {report.rate('category'):.0%} | "
            f"{report.rate('scope'):.0%} | {report.rate('cause'):.0%} | "
            f"{report.rate('grounded'):.0%} | {report.rate('valid'):.0%} | {report.latency:.0f} s |"
        )
    return "\n".join(lines)


def _timestamp(value: Any) -> float:
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        return datetime.fromisoformat(value).timestamp()
    return float(value)
