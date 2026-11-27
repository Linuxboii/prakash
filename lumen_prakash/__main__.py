"""Command-line interface for lumen-prakash."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .inspect import CertSummary, InspectResult, inspect_host


def _use_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _c(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _parse_target(target: str, default_port: int) -> tuple[str, int]:
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        return host, int(port)
    return target, default_port


def _iso(dt) -> str | None:
    return dt.isoformat() if dt else None


def _cert_to_dict(c: CertSummary) -> dict:
    return {
        "subject": c.subject,
        "issuer": c.issuer,
        "sans": c.sans,
        "not_before": _iso(c.not_before),
        "not_after": _iso(c.not_after),
        "days_left": c.days_left,
        "key_type": c.key_type,
        "key_bits": c.key_bits,
        "key_curve": c.key_curve,
    }


def _result_to_dict(r: InspectResult) -> dict:
    return {
        "host": r.host,
        "port": r.port,
        "ok": r.ok,
        "error": r.error,
        "protocol": r.protocol,
        "cipher": r.cipher,
        "cipher_bits": r.cipher_bits,
        "chain": [_cert_to_dict(c) for c in r.chain],
        "supported_versions": r.supported_versions,
        "warnings": r.warnings,
    }


def _print_result(r: InspectResult, color: bool) -> None:
    head = _c(f"{r.host}:{r.port}", "1", color)
    if not r.ok:
        print(f"\n{head}  {_c('CONNECT FAILED', '31', color)}: {r.error}")
        return

    print(f"\n{head}")
    print(f"  negotiated : {r.protocol}  {r.cipher} ({r.cipher_bits}-bit)")

    for i, cert in enumerate(r.chain):
        label = "leaf" if i == 0 else f"ca[{i}]"
        print(f"  {label:<6} subject: {cert.subject}")
        print(f"         issuer : {cert.issuer}")
        if cert.key_type:
            bits = f" {cert.key_bits}-bit" if cert.key_bits else ""
            curve = f" ({cert.key_curve})" if cert.key_curve else ""
            print(f"         key    : {cert.key_type}{bits}{curve}")
        if i == 0:
            if cert.not_after:
                days = cert.days_left
                dcol = "31" if days is not None and days < 30 else "32"
                print(f"         valid  : {_iso(cert.not_before)}  ->  {_iso(cert.not_after)}")
                print(f"         expiry : {_c(str(days) + ' day(s)', dcol, color)}")
            if cert.sans:
                shown = ", ".join(cert.sans[:8])
                extra = "" if len(cert.sans) <= 8 else f" (+{len(cert.sans) - 8} more)"
                print(f"         SANs   : {shown}{extra}")

    if r.supported_versions:
        parts = []
        for ver, ok in r.supported_versions.items():
            if ok is True:
                parts.append(_c(ver + " yes", "32", color))
            elif ok is False:
                parts.append(_c(ver + " no", "90", color))
            else:
                parts.append(_c(ver + " n/a", "90", color))
        print(f"  versions   : {'  '.join(parts)}")

    for w in r.warnings:
        print(f"  {_c('WARN', '33', color)}: {w}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="lumen-prakash",
        description="Inspect TLS certificates, protocols, and expiry for a host.",
        epilog="Use only against hosts you own or are authorized to assess.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("targets", nargs="*", help="host or host:port")
    p.add_argument("-f", "--file", help="file of hosts (one per line) for batch mode")
    p.add_argument("-p", "--port", type=int, default=443, help="default port (443)")
    p.add_argument("-t", "--timeout", type=float, default=7.0, help="timeout seconds")
    p.add_argument("-w", "--warn-days", type=int, default=30,
                   help="warn if expiry is under N days (default 30)")
    p.add_argument("--no-probe", action="store_true",
                   help="skip the per-version TLS handshake probes")
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    args = p.parse_args(argv)

    targets: list[str] = list(args.targets)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            targets.extend(
                ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")
            )
    if not targets:
        p.error("provide at least one target or --file")

    results = []
    for target in targets:
        host, port = _parse_target(target, args.port)
        results.append(inspect_host(
            host, port,
            timeout=args.timeout,
            warn_days=args.warn_days,
            probe_versions=not args.no_probe,
        ))

    if args.json:
        payload = [_result_to_dict(r) for r in results]
        json.dump(payload if len(payload) > 1 else payload[0], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        color = _use_color(args.no_color)
        for r in results:
            _print_result(r, color)
        print()

    # Exit 1 if any connection failed or any warning fired.
    if any((not r.ok) or r.warnings for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
