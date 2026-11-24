from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import ssl
import threading
from collections.abc import Coroutine, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from incident_scout.config import ConfigError, build_telemetry, load_config
from incident_scout.engine import backtest
from incident_scout.rules import Rule, evaluate, render
from incident_scout.sources import tls
from incident_scout.sources.base import SourceError
from incident_scout.sources.elasticsearch import ElasticsearchTelemetry, label_name
from incident_scout.sources.tls import (
    UNREACHABLE,
    certificate,
    certificate_series,
    fetch_certificate,
    parse_targets,
)

from .conftest import FakeTelemetry

T = TypeVar("T")
NOW = datetime(2026, 11, 21, 9, 0, tzinfo=UTC).timestamp()
ERP_ERRORS = {
    "bool": {
        "filter": [
            {"term": {"level.keyword": "error"}},
            {"terms": {"message.keyword": ["Download data from ERP"]}},
        ]
    }
}
SUMMARY = "{target}: {not_after}{error} ({value:.1f} days)"


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coroutine)


def elasticsearch(
    reply: Any, status: int = 200, index: str | None = "logs*"
) -> tuple[ElasticsearchTelemetry, list[httpx.Request]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(status, json=reply)

    transport = httpx.MockTransport(handler)
    return ElasticsearchTelemetry("http://es:9200/", index=index, transport=transport), requests


def test_counts_are_grouped_by_a_field_in_the_window():
    buckets = [{"key": "erp-download", "doc_count": 22}, {"key": "erp-save", "doc_count": 9}]
    telemetry, requests = elasticsearch({"aggregations": {"groups": {"buckets": buckets}}})
    found = run(telemetry.count(None, ERP_ERRORS, 1800, NOW, "node.keyword"))
    assert [(s.labels, s.points) for s in found] == [
        ({"node": "erp-download"}, [(NOW, 22.0)]),
        ({"node": "erp-save"}, [(NOW, 9.0)]),
    ]
    assert str(requests[0].url) == "http://es:9200/logs*/_search"
    window = {"gte": int((NOW - 1800) * 1000), "lte": int(NOW * 1000), "format": "epoch_millis"}
    assert json.loads(requests[0].content) == {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [ERP_ERRORS, {"range": {"timestamp": window}}]}},
        "aggs": {"groups": {"terms": {"field": "node.keyword", "size": 50}}},
    }


def test_without_a_group_the_total_is_one_series_even_when_zero():
    telemetry, requests = elasticsearch({"hits": {"total": {"value": 0, "relation": "eq"}}})
    (total,) = run(telemetry.count("other-*", ERP_ERRORS, 60, NOW, time_field="@timestamp"))
    assert (total.labels, total.last) == ({}, 0.0)
    body = json.loads(requests[0].content)
    assert str(requests[0].url) == "http://es:9200/other-*/_search"
    assert "aggs" not in body
    assert "@timestamp" in body["query"]["bool"]["filter"][1]["range"]


def test_elasticsearch_errors_become_source_errors():
    rejected = {
        "error": {
            "root_cause": [{"type": "illegal_argument_exception", "reason": "Text fields are not"}],
            "type": "search_phase_execution_exception",
        },
        "status": 400,
    }
    telemetry, _ = elasticsearch(rejected, status=400)
    with pytest.raises(SourceError, match="HTTP 400: Text fields are not"):
        run(telemetry.count(None, ERP_ERRORS, 60, NOW, "node"))
    shard_failure = {
        "failed": 1,
        "total": 3,
        "failures": [{"reason": {"reason": "Fielddata is disabled"}}],
    }
    partial, _ = elasticsearch({"_shards": shard_failure, "hits": {"total": {"value": 5}}})
    with pytest.raises(SourceError, match="1 of 3 shards failed Fielddata is disabled"):
        run(partial.count(None, ERP_ERRORS, 60, NOW))
    slow, _ = elasticsearch({"timed_out": True, "hits": {"total": {"value": 5}}})
    with pytest.raises(SourceError, match="timed out"):
        run(slow.count(None, ERP_ERRORS, 60, NOW))
    nowhere, _ = elasticsearch({}, index=None)
    with pytest.raises(SourceError, match="needs an index"):
        run(nowhere.count(None, ERP_ERRORS, 60, NOW))

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    down = ElasticsearchTelemetry("http://es", "logs", transport=httpx.MockTransport(refuse))
    with pytest.raises(SourceError, match="refused"):
        run(down.count(None, ERP_ERRORS, 60, NOW))
    for call in (down.query("x"), down.query_range("x", 0, 1, 1), down.logs("x", "5m")):
        with pytest.raises(SourceError, match=r"no (promql|logql)"):
            run(call)
    with pytest.raises(SourceError, match="no alertmanager"):
        run(down.alerts())


def test_group_fields_become_placeholder_friendly_labels():
    assert label_name("node.keyword") == "node"
    assert label_name("context.objectType") == "context_objectType"


def test_elasticsearch_rules_apply_their_threshold_and_need_their_source():
    rule = Rule(
        "erp",
        "elasticsearch",
        query=json.dumps(ERP_ERRORS),
        since="30m",
        above=2,
        index="kovianprod-orchesty*",
        group_by="node.keyword",
        summary="{node}: {value:.0f}x",
    )
    buckets = [{"key": "a", "doc_count": 3}, {"key": "b", "doc_count": 2}]
    telemetry, requests = elasticsearch({"aggregations": {"groups": {"buckets": buckets}}})
    assert [f.summary for f in run(evaluate(rule, telemetry, now=NOW))] == ["a: 3x"]
    assert requests[0].url.path == "/kovianprod-orchesty*/_search"
    with pytest.raises(SourceError, match="elasticsearch source"):
        run(evaluate(rule, FakeTelemetry(), now=NOW))
    for kind in ("elasticsearch", "tls"):
        with pytest.raises(ValueError, match="cannot be replayed"):
            run(backtest(Rule("x", kind, query="q"), telemetry, 0, 1, 60))


def make_certificate(
    expires: datetime, common_name: str = "erp.example"
) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(expires - timedelta(days=90))
        .not_valid_after(expires)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER), key


def test_a_certificate_is_valued_in_days_left():
    expired, _ = make_certificate(datetime(2026, 11, 20, 23, 59, 59, tzinfo=UTC))
    series = certificate("erp.example:29092", expired, NOW)
    assert series.labels == {
        "target": "erp.example:29092",
        "subject": "erp.example",
        "issuer": "erp.example",
        "not_after": "2026-11-20 23:59:59 UTC",
        "error": "",
    }
    assert series.last == pytest.approx(-(9 * 3600 + 1) / 86400)
    valid, _ = make_certificate(datetime(2027, 1, 1, tzinfo=UTC))
    assert certificate("t:443", valid, NOW).last == pytest.approx(40.625)


def test_unreadable_targets_fire_with_their_reason():
    der, _ = make_certificate(datetime(2027, 1, 1, tzinfo=UTC))

    def fetch(host: str, port: int) -> bytes:
        if host == "down":
            raise ConnectionRefusedError(61, "Connection refused")
        if host == "slow":
            raise TimeoutError
        return der

    found = run(certificate_series(["ok:443", "down:443", "slow:443"], NOW, fetch))
    assert [s.labels["error"] for s in found] == ["", "[Errno 61] Connection refused", "timed out"]
    assert [s.last for s in found][1:] == [UNREACHABLE, UNREACHABLE]
    assert {tuple(s.labels) for s in found} == {
        ("target", "subject", "issuer", "not_after", "error")
    }
    shown = [render(SUMMARY, {**s.labels, "value": s.last}) for s in found]
    assert shown == [
        "ok:443: 2027-01-01 00:00:00 UTC (40.6 days)",
        "down:443: [Errno 61] Connection refused (-9999.0 days)",
        "slow:443: timed out (-9999.0 days)",
    ]


def test_tls_rules_ignore_their_source(monkeypatch: pytest.MonkeyPatch):
    der, _ = make_certificate(datetime(2026, 11, 20, 23, 59, 59, tzinfo=UTC))
    monkeypatch.setattr(tls, "fetch_certificate", lambda host, port: der)
    rule = Rule("cert", "tls", query="a:1, b:2", below=14, key_labels=("target",))
    found = run(evaluate(rule, FakeTelemetry(), now=NOW))
    assert [f.key for f in found] == ["target=a:1", "target=b:2"]
    assert not run(evaluate(Rule("old", "tls", query="a:1", below=-1), FakeTelemetry(), now=NOW))


def test_targets_are_parsed_from_lists_and_strings():
    assert parse_targets("a:1, b:2 c:3") == ["a:1", "b:2", "c:3"]
    assert parse_targets(["a:1", "[::1]:443"]) == ["a:1", "[::1]:443"]
    assert tls.split_target("[::1]:443") == ("::1", 443)
    for bad in ("a", "a:", ":1", "a:http", "a:70000"):
        with pytest.raises(ValueError, match="host:port"):
            parse_targets(bad)


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[int, bytes]]:
    der, key = make_certificate(datetime(2026, 11, 20, 23, 59, 59, tzinfo=UTC), "localhost")
    (tmp_path / "cert.pem").write_text(ssl.DER_cert_to_PEM_cert(der))
    (tmp_path / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    listener = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        connection, _ = listener.accept()
        with (
            contextlib.suppress(OSError),
            context.wrap_socket(connection, server_side=True) as tls_connection,
        ):
            tls_connection.recv(1)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1], der
    listener.close()
    thread.join(5)


def test_the_certificate_is_read_even_when_it_fails_verification(tls_server: tuple[int, bytes]):
    port, der = tls_server
    assert fetch_certificate("127.0.0.1", port, timeout=5) == der
    closed = socket.create_server(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    (series,) = run(certificate_series([f"127.0.0.1:{free}"], NOW))
    assert series.last == UNREACHABLE
    assert series.labels["error"]


CONFIG = """
state_path: {state}
source: {{type: http, prometheus_url: "http://prom"}}
vars: {{level: error}}
sources:
  orchesty-logs:
    type: elasticsearch
    url: http://es:9207
    index: 'orchesty*'
    vars: {{shop: kovian, erp: erp.example}}
rules:
  - name: erp-link
    kind: elasticsearch
    source: orchesty-logs
    query:
      bool:
        filter:
          - term: {{level.keyword: $level}}
          - terms: {{message.keyword: ['Download "data" from ERP']}}
    group_by: node.keyword
    since: 30m
    above: 2
    summary: '$shop: {{node}} {{value:.0f}}x'
  - name: erp-json
    kind: elasticsearch
    source: orchesty-logs
    index: 'other-$shop'
    query: '{{"term": {{"level.keyword": "$level"}}}}'
    below: 1
  - name: erp-cert
    kind: tls
    source: orchesty-logs
    query: ['$erp:29092', 'shop.example:443']
    below: 14
"""


def test_config_reads_elasticsearch_sources_and_both_rule_kinds(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG.format(state=tmp_path / "state.db"))
    config = load_config(path)
    rules = {rule.name: rule for rule in config.rules}
    link = rules["erp-link"]
    assert json.loads(link.query)["bool"]["filter"] == [
        {"term": {"level.keyword": "error"}},
        {"terms": {"message.keyword": ['Download "data" from ERP']}},
    ]
    assert (link.group_by, link.since, link.above, link.index) == ("node.keyword", "30m", 2, None)
    assert link.summary == "kovian: {node} {value:.0f}x"
    assert json.loads(rules["erp-json"].query) == {"term": {"level.keyword": "error"}}
    assert (rules["erp-json"].index, rules["erp-json"].since) == ("other-kovian", "5m")
    cert = rules["erp-cert"]
    assert (cert.query, cert.key_labels) == ("erp.example:29092, shop.example:443", ("target",))
    telemetry = build_telemetry(config.source_options("orchesty-logs"))
    assert isinstance(telemetry, ElasticsearchTelemetry)
    assert (telemetry.url, telemetry.index) == ("http://es:9207", "orchesty*")


@pytest.mark.parametrize(
    ("snippet", "message"),
    [
        ("rules: [{name: x, kind: elasticsearch, query: {term: {a: b}}}]", "above or below"),
        ("rules: [{name: x, kind: tls, query: [a:1]}]", "above or below"),
        ("rules: [{name: x, kind: elasticsearch, query: '[1]', above: 1}]", "query object"),
        ("rules: [{name: x, kind: elasticsearch, query: '{bad', above: 1}]", "not valid JSON"),
        ("rules: [{name: x, kind: elasticsearch, query: {a: b}, since: soon, above: 1}]", "since"),
        ("rules: [{name: x, kind: tls, query: 'host', below: 1}]", "host:port"),
        ("rules: [{name: x, kind: tls, query: {a: 1}, below: 1}]", "list of host:port"),
        ("rules: [{name: x, kind: tls, query: ' , ', below: 1}]", "at least one"),
        ("rules: [{name: x, kind: promql, query: q, group_by: node}]", "only appl"),
        ("rules: [{name: x, kind: elasticsearch, query: {a: b}, above: 1, size: 9}]", "unknown"),
    ],
)
def test_elasticsearch_and_tls_config_errors(tmp_path: Path, snippet: str, message: str):
    path = tmp_path / "config.yaml"
    path.write_text(snippet)
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_elasticsearch_source_options_are_checked():
    with pytest.raises(ConfigError, match="url is required"):
        build_telemetry({"type": "elasticsearch"})
    with pytest.raises(ConfigError, match="unknown option"):
        build_telemetry({"type": "elasticsearch", "url": "http://es", "user": "x"})
    with pytest.raises(ConfigError, match="elasticsearch"):
        build_telemetry({"type": "opensearch"})
