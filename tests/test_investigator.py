from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from incident_scout.evaluation import (
    case_matrix,
    evaluate,
    fold,
    load_cases,
    markdown_table,
    rescore,
    score,
    ungrounded,
)
from incident_scout.evidence import EvidencePack, EvidenceQuery, Section, collect, labels_from_key
from incident_scout.investigator import (
    Diagnosis,
    InvestigationError,
    OllamaInvestigator,
    parse_diagnosis,
)
from incident_scout.models import Series

from .conftest import T0, FakeTelemetry

CASES = Path(__file__).parents[1] / "eval" / "cases"
START = T0.timestamp()
ANSWER: dict[str, Any] = {
    "summary": "Shop A answers 500 since 14:05.",
    "scope": "single_shop",
    "category": "dependency",
    "likely_cause": "MySQL refuses connections: SQLSTATE[HY000] [2002] Connection refused.",
    "confidence": "high",
    "key_evidence": ["1268x SQLSTATE[HY000] [2002] Connection refused"],
    "next_steps": ["Restart MySQL on prod-shop-a", "Check the MySQL error log"],
}


def pack(*sections: Section) -> EvidencePack:
    return EvidencePack(
        "http-5xx",
        "critical",
        "prod-shop-a: 412x HTTP 5xx in 5 min",
        {"shop": "prod-shop-a"},
        START,
        START - 1800,
        START + 600,
        list(sections),
    )


def test_collect_builds_timelines_totals_and_precedents():
    queries = [
        EvidenceQuery("Up", "promql", 'up{shop="$shop"}'),
        EvidenceQuery("5xx", "logql", 'sum(count_over_time({shop="$shop"} [5m]))'),
        EvidenceQuery(
            "Top errors", "logql_top", 'topk(3, sum by (message) ({shop="$shop"} [$window]))'
        ),
        EvidenceQuery("Broken", "promql", "broken"),
    ]
    now = START + 3600
    errors = [
        Series({"message": "SQLSTATE[HY000] Connection refused"}, [(now, 120.0)]),
        Series({"message": "minor"}, [(now, 3.0)]),
    ]
    telemetry = FakeTelemetry(
        ranges={'up{shop="prod-shop-a"}': [Series({"job": "mysql"}, [(START, 0.0)])]},
        logs={
            'sum(count_over_time({shop="prod-shop-a"} [5m] offset 3000s))': [
                Series({}, [(now - 300, 55.0)])
            ],
            'topk(3, sum by (message) ({shop="prod-shop-a"} [2400s] offset 3000s))': errors,
        },
    )
    telemetry.ranges["broken"] = []  # an empty range is not an error, a missing series is
    seen: list[str] = []

    def find(text: str) -> list[str]:
        seen.append(text)
        return ["DB-1: MySQL down [Done, 2 h]"]

    result = asyncio.run(
        collect(
            telemetry,
            queries,
            "http-5xx",
            "critical",
            "prod-shop-a: 412x HTTP 5xx",
            {"shop": "prod-shop-a"},
            START,
            precedents=find,
            precedents_from="Top errors",
            now=now,
        )
    )
    sections = {s.name: s.lines for s in result.sections}
    assert sections["Up"][1].split()[:2] == ["job=mysql", "."]
    assert "55" in sections["5xx"][1]
    assert sections["Top errors"][0].strip().startswith("120x")
    assert sections["Broken"] == []
    assert seen == ["SQLSTATE[HY000] Connection refused"]
    assert sections["Similar past tickets"] == ["DB-1: MySQL down [Done, 2 h]"]
    rendered = result.render()
    assert "## Top errors" in rendered
    assert "(no data)" in rendered


def test_collect_reports_failing_queries_and_failing_precedent_search():
    def broken(_text: str) -> list[str]:
        raise RuntimeError("index missing")

    telemetry = FakeTelemetry(logs={"x": RuntimeError("loki down")})
    result = asyncio.run(
        collect(
            telemetry,
            [EvidenceQuery("Logs", "logql_top", "x")],
            "r",
            "warning",
            "s",
            {},
            START,
            precedents=broken,
            now=START + 900,
        )
    )
    assert result.sections[0].lines[0].startswith("(query failed: RuntimeError: loki down")
    assert result.sections[1].lines == ["(search failed: RuntimeError)"]


def test_pack_round_trips_through_json_and_labels_from_key():
    original = pack(Section("A", ["line"]))
    assert EvidencePack.from_json(original.to_json()) == original
    assert labels_from_key("shop=a,job=node") == {"shop": "a", "job": "node"}


def ollama(reply: Any, captured: list[dict[str, Any]], status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append({"path": request.url.path, **json.loads(request.content)})
        return httpx.Response(status, json=reply)

    return httpx.MockTransport(handler)


def test_ollama_investigator_sends_schema_and_parses_the_answer():
    calls: list[dict[str, Any]] = []
    reply = {"message": {"content": json.dumps(ANSWER)}}
    investigator = OllamaInvestigator(
        "tiny", language="Czech", think=False, transport=ollama(reply, calls)
    )
    diagnosis = investigator.diagnose(pack(Section("A", ["x"])))
    assert diagnosis.category == "dependency"
    assert diagnosis.model == "tiny"
    request = calls[0]
    assert request["path"] == "/api/chat"
    assert request["format"]["required"][0] == "summary"
    assert request["think"] is False
    assert request["options"]["temperature"] == 0
    assert "Czech" in request["messages"][0]["content"]
    assert "prod-shop-a" in request["messages"][1]["content"]

    investigator.warm_up()
    investigator.unload()
    assert [c["path"] for c in calls[1:]] == ["/api/generate", "/api/generate"]
    assert calls[2]["keep_alive"] == 0


def test_ollama_errors_become_investigation_errors():
    calls: list[dict[str, Any]] = []
    failing = OllamaInvestigator("tiny", transport=ollama({}, calls, status=500))
    with pytest.raises(InvestigationError, match="tiny"):
        failing.diagnose(pack())


@pytest.mark.parametrize(
    ("content", "message"),
    [("not json", "invalid JSON"), ("[1]", "expected an object"), ('{"summary": "x"}', "left out")],
)
def test_parse_diagnosis_rejects_broken_answers(content: str, message: str):
    with pytest.raises(InvestigationError, match=message):
        parse_diagnosis(content, "m")


def test_parse_diagnosis_normalises_unknown_enums_and_trims_lists():
    data = {**ANSWER, "category": "cosmic rays", "key_evidence": list("abcdef")}
    diagnosis = parse_diagnosis(json.dumps(data), "m", 1.26)
    assert diagnosis.category == "unknown"
    assert diagnosis.key_evidence == ["a", "b", "c", "d"]
    assert diagnosis.seconds == 1.3
    assert diagnosis.headline().endswith("(high)")
    assert json.loads(diagnosis.to_json())["model"] == "m"


def test_synthetic_cases_load_and_a_correct_answer_scores_full_marks():
    cases = {case.id: case for case in load_cases([CASES])}
    assert len(cases) >= 10
    database = cases["database-down"]
    result = score(database, Diagnosis(**ANSWER, model="m"))
    assert (result.category, result.scope, result.cause, result.grounded) == (True,) * 4
    assert result.total == 1.0


def test_invented_identifiers_are_flagged():
    evidence = pack(Section("Errors", ["SQLSTATE[HY000] [2002] Connection refused"])).render()
    invented = Diagnosis(
        **{
            **ANSWER,
            "likely_cause": "Doctrine\\DBAL\\ConnectionLost in OrderRepository::findOpen",
            "next_steps": ["Restart prod-shop-z"],
        }
    )
    assert ungrounded(invented, evidence) == (
        "Doctrine\\DBAL\\ConnectionLost",
        "OrderRepository::findOpen",
        "prod-shop-z",
    )
    assert fold("Databáze NEODPOVÍDÁ") == "databaze neodpovida"


def test_evaluate_rescore_and_tables():
    cases = [c for c in load_cases([CASES]) if c.id in ("database-down", "redis-down")]
    answers = iter([Diagnosis(**ANSWER, model="m", seconds=3.0)])

    def diagnose(_pack: EvidencePack) -> Diagnosis:
        try:
            return next(answers)
        except StopIteration:
            raise InvestigationError("model returned nothing") from None

    report = evaluate(cases, diagnose, "m")
    assert [s.valid for s in report.scores] == [True, False]
    assert report.rate("total") == 0.5
    assert report.latency == 3.0
    assert "| `m` | 0.50 |" in markdown_table([report])

    rows = [
        {"case": s.case, "model": s.model, "diagnosis": s.diagnosis and s.diagnosis.__dict__}
        for s in report.scores
    ]
    (again,) = rescore([*rows, {"case": "gone", "model": "m"}], cases)
    assert [s.total for s in again.scores] == [1.0, 0.0]
    matrix = case_matrix([again])
    assert "| database-down | CSKG |" in matrix
    assert "| redis-down | invalid |" in matrix


def test_runtimes_without_constrained_output_get_the_schema_in_the_prompt():
    calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if "format" in body:
            return httpx.Response(501)
        return httpx.Response(
            200, json={"message": {"content": f"```json\n{json.dumps(ANSWER)}\n```"}}
        )

    investigator = OllamaInvestigator("new-engine", transport=httpx.MockTransport(handler))
    assert investigator.diagnose(pack()).category == "dependency"
    assert "format" not in calls[1]
    assert (
        '"scope": one of: single_shop | multiple_shops | unknown'
        in calls[1]["messages"][0]["content"]
    )
