"""Days until the TLS certificate of a host:port expires, read straight from the handshake."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from collections.abc import Callable, Sequence

from cryptography import x509
from cryptography.x509.oid import NameOID

from ..models import Series

TIMEOUT = 10
UNREACHABLE = -9999.0
_SEPARATORS = re.compile(r"[\s,]+")

Fetch = Callable[[str, int], bytes]


def parse_targets(value: str | Sequence[str]) -> list[str]:
    """`host:port` targets from a list or a comma or space separated string."""
    items = [value] if isinstance(value, str) else [str(item) for item in value]
    targets = [part for item in items for part in _SEPARATORS.split(item.strip()) if part]
    for target in targets:
        split_target(target)
    return targets


def split_target(target: str) -> tuple[str, int]:
    host, colon, port = target.rpartition(":")
    if not colon or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"TLS target {target!r} must be host:port, e.g. example.com:443")
    return host.strip("[]"), int(port)


def fetch_certificate(host: str, port: int, timeout: float = TIMEOUT) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    # Unverified on purpose: an expired or self-signed certificate must still be read.
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as connection,
        context.wrap_socket(connection, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("the server sent no certificate")
    return der


async def certificate_series(
    targets: Sequence[str], now: float, fetch: Fetch | None = None
) -> list[Series]:
    """One series per target valued in days until expiry (negative once expired). A target
    that cannot be read is valued UNREACHABLE with the reason in `error`."""
    read = fetch or fetch_certificate
    return list(await asyncio.gather(*(_series(target, now, read) for target in targets)))


async def _series(target: str, now: float, fetch: Fetch) -> Series:
    try:
        host, port = split_target(target)
        der = await asyncio.to_thread(fetch, host, port)
        return certificate(target, der, now)
    except (OSError, ValueError) as error:
        return Series(_labels(target, error=_short(error)), [(now, UNREACHABLE)])


def certificate(target: str, der: bytes, now: float) -> Series:
    cert = x509.load_der_x509_certificate(der)
    expires = cert.not_valid_after_utc
    labels = _labels(
        target,
        subject=_common_name(cert.subject),
        issuer=_common_name(cert.issuer),
        not_after=expires.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    return Series(labels, [(now, (expires.timestamp() - now) / 86400)])


def _labels(
    target: str, subject: str = "", issuer: str = "", not_after: str = "", error: str = ""
) -> dict[str, str]:
    """The same label names on every series, so one summary template fits readable and
    unreachable targets alike."""
    return {
        "target": target,
        "subject": subject,
        "issuer": issuer,
        "not_after": not_after,
        "error": error,
    }


def _common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not values:
        return ""
    value = values[0].value
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _short(error: BaseException) -> str:
    text = str(error) or type(error).__name__
    if isinstance(error, TimeoutError):
        text = "timed out"
    return " ".join(text.split())[:160]
