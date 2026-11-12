"""Command-line interface for rimscan-cli."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from rimscan_cli import __version__
from rimscan_cli.banner import render_banner
from rimscan_cli.recon.enumeration import DEFAULT_SOURCES
from rimscan_cli.scanner import SEVERITY_RANK, InvalidArguments, scan_domain, severity_counts


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if not number > 0 or number == float("inf"):
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a whole number") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _csv(value: str) -> List[str]:
    """Split a comma-separated list, dropping blanks and repeats (order is kept)."""
    return list(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rimscan-cli",
        description="External attack-surface reconnaissance for domains you own or are authorized to test.",
        epilog=(
            "The target's domain is sent to public passive-DNS and certificate-transparency services "
            "(crt.sh, Cert Spotter, AlienVault OTX, RapidDNS, Wayback Machine, Anubis). A default scan "
            "also opens TLS connections to discovered hosts and sends at most one HTTP GET to hosts that "
            "CNAME to a known third-party service. --secrets, --nuclei and --zone-transfer send further "
            "probes to the target and require --authorized. Results go to stdout as JSON; progress goes "
            "to stderr. Exit status: 0 ok, 1 findings reached --fail-on, 2 usage or output error, "
            "3 scan incomplete (with --fail-on), 130 interrupted."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="enumerate and audit a domain")
    scan.add_argument("domain", help="domain to scan, e.g. example.com")
    scan.add_argument("--authorized", action="store_true", help="confirm you own or may test this target")
    scan.add_argument("--secrets", action="store_true", help="fetch well-known paths and look for exposed secrets (requires --authorized)")
    scan.add_argument("--zone-transfer", action="store_true", help="attempt AXFR against the domain's nameservers (requires --authorized)")
    scan.add_argument("--nuclei", action="store_true", help="run Nuclei with dos, fuzz and intrusive templates excluded (requires --authorized)")
    scan.add_argument("--nuclei-rate-limit", type=_positive_int, default=75, metavar="N", help="Nuclei requests per second (default: 75)")
    scan.add_argument("--include-third-party", action="store_true",
                      help="let --secrets and --nuclei also probe hosts that CNAME to third-party services (skipped by default)")
    scan.add_argument("--bruteforce", action="store_true", help="also resolve a short list of common subdomain names")
    scan.add_argument("--no-certs", action="store_true", help="skip the TLS certificate audit")
    scan.add_argument("--sources", type=_csv, metavar="LIST",
                      help=f"comma-separated enumeration sources (default: {','.join(DEFAULT_SOURCES)})")
    scan.add_argument("--resolver", type=_csv, metavar="IPS",
                      help="comma-separated DNS resolver addresses for DNS lookups (TLS and HTTP probes always use the system resolver)")
    scan.add_argument("--timeout", type=_positive_float, default=10.0, metavar="SECONDS", help="network timeout (default: 10)")
    scan.add_argument("-o", "--output", type=Path, help="write JSON results to this file instead of stdout")
    scan.add_argument("--fail-on", choices=[*SEVERITY_RANK, "none"], default="none",
                      help="exit with status 1 if any finding is at or above this severity (3 if the scan was incomplete)")
    scan.add_argument("-q", "--quiet", action="store_true", help="no banner, progress or summary on stderr")
    scan.add_argument("--no-banner", action="store_true", help="do not print the banner")
    scan.add_argument("--verbose", action="store_true", help="enable debug logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # --quiet silences stderr completely, including log warnings (--verbose still wins).
    log_level = logging.DEBUG if args.verbose else (logging.CRITICAL + 1 if args.quiet else logging.WARNING)
    logging.basicConfig(
        force=True,
        level=log_level,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    if not (args.quiet or args.no_banner):
        render_banner()  # prints to stderr

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"[*] {message}", file=sys.stderr)

    try:
        result = scan_domain(
            args.domain,
            authorized=args.authorized,
            include_zone_transfer=args.zone_transfer,
            include_secrets=args.secrets,
            include_certs=not args.no_certs,
            include_nuclei=args.nuclei,
            include_third_party=args.include_third_party,
            bruteforce=args.bruteforce,
            sources=args.sources,
            timeout=args.timeout,
            nameservers=args.resolver,
            nuclei_rate_limit=args.nuclei_rate_limit,
            progress=progress,
        )
    except InvalidArguments as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    rendered = json.dumps(result, indent=2, sort_keys=True)
    exit_code = 0
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            # The scan may have taken a long time; never lose its results over a bad path.
            print(f"error: cannot write {args.output}: {exc.strerror}; printing results to stdout", file=sys.stderr)
            print(rendered)
            exit_code = 2
        else:
            progress(f"results written to {args.output}")
    else:
        print(rendered)

    for warning in result.get("warnings", []):
        progress(f"warning: {warning}")
    counts = severity_counts(result)
    if counts:
        summary = ", ".join(f"{n} {level}" for level, n in sorted(counts.items(), key=lambda kv: -SEVERITY_RANK[kv[0]]))
        progress(f"findings: {summary}")
    else:
        progress("no findings" + (" (scan incomplete)" if result.get("incomplete") else ""))

    if exit_code:
        return exit_code
    if args.fail_on != "none":
        if any(SEVERITY_RANK[level] >= SEVERITY_RANK[args.fail_on] for level in counts):
            return 1
        if result.get("incomplete"):
            return 3
    return 0
