"""Live TLS connection inspection (networking layer)."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import certinfo

# Probe order, newest first in reporting but attempted individually.
_TLS_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


@dataclass
class CertSummary:
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_left: int | None = None
    key_type: str | None = None
    key_bits: int | None = None
    key_curve: str | None = None


@dataclass
class InspectResult:
    host: str
    port: int
    ok: bool
    error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    chain: list[CertSummary] = field(default_factory=list)
    supported_versions: dict[str, bool | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _permissive_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _summarize(cert_der: bytes, now: datetime) -> CertSummary:
    s = CertSummary()
    try:
        s.subject = certinfo.subject_cn(cert_der)
        s.issuer = certinfo.issuer_cn(cert_der)
    except Exception:  # noqa: BLE001 - best-effort field extraction
        pass
    try:
        s.sans = certinfo.san_dns_names(cert_der)
    except Exception:  # noqa: BLE001
        s.sans = []
    try:
        nb, na = certinfo.validity(cert_der)
        s.not_before, s.not_after = nb, na
        s.days_left = certinfo.days_until(na, now)
    except Exception:  # noqa: BLE001
        pass
    try:
        info = certinfo.public_key_info(cert_der)
        s.key_type = info.get("type")
        s.key_bits = info.get("bits")
        s.key_curve = info.get("curve")
    except Exception:  # noqa: BLE001
        pass
    return s


def _get_chain_ders(tls_sock: ssl.SSLSocket) -> list[bytes]:
    """Return DER bytes for every cert the server presented, leaf first."""
    getter = getattr(tls_sock, "get_unverified_chain", None)
    if getter is not None:
        try:
            chain = getter()
            ders = []
            for cert in chain or []:
                if isinstance(cert, (bytes, bytearray)):
                    ders.append(bytes(cert))
                elif hasattr(cert, "public_bytes"):
                    ders.append(cert.public_bytes(ssl.ENCODING_DER))
            if ders:
                return ders
        except (ssl.SSLError, ValueError, AttributeError):
            pass
    leaf = tls_sock.getpeercert(binary_form=True)
    return [leaf] if leaf else []


def probe_version(host: str, port: int, version: ssl.TLSVersion, timeout: float):
    """Return True/False if a specific TLS version handshakes, None if unusable."""
    ctx = _permissive_context()
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return None  # version not available in this OpenSSL build
    try:
        with socket.create_connection((host, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def inspect_host(
    host: str,
    port: int = 443,
    timeout: float = 7.0,
    warn_days: int = 30,
    probe_versions: bool = True,
    now: datetime | None = None,
) -> InspectResult:
    """Connect to host:port and gather certificate and protocol details."""
    if now is None:
        now = datetime.now(timezone.utc)
    result = InspectResult(host=host, port=port, ok=False)

    ctx = _permissive_context()
    try:
        with socket.create_connection((host, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                result.ok = True
                result.protocol = tls.version()
                cipher = tls.cipher()
                if cipher:
                    result.cipher = cipher[0]
                    result.cipher_bits = cipher[2]
                for der_bytes in _get_chain_ders(tls):
                    result.chain.append(_summarize(der_bytes, now))
    except (ssl.SSLError, OSError) as exc:
        result.error = str(exc)
        return result

    if result.chain:
        leaf = result.chain[0]
        if leaf.days_left is not None:
            if leaf.days_left < 0:
                result.warnings.append(f"certificate EXPIRED {-leaf.days_left} day(s) ago")
            elif leaf.days_left < warn_days:
                result.warnings.append(
                    f"certificate expires in {leaf.days_left} day(s) (< {warn_days})"
                )
        if leaf.key_type == "RSA" and leaf.key_bits and leaf.key_bits < 2048:
            result.warnings.append(f"weak RSA key: {leaf.key_bits} bits (< 2048)")

    if probe_versions:
        for label, ver in _TLS_VERSIONS:
            result.supported_versions[label] = probe_version(host, port, ver, timeout)
        for weak in ("TLSv1.0", "TLSv1.1"):
            if result.supported_versions.get(weak):
                result.warnings.append(f"deprecated {weak} is accepted")

    return result
