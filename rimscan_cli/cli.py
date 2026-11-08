"""Command-line interface for rimscan-cli."""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from rimscan_cli import __version__
from rimscan_cli.banner import render_banner
from rimscan_cli.recon.cert_audit import CertAuditor
from rimscan_cli.recon.dns_audit import DNSAuditor
from rimscan_cli.recon.enumeration import DEFAULT_SOURCES, SubdomainEnumerator
from rimscan_cli.recon.resolver import DNSResolver
from rimscan_cli.recon.secrets import SecretScanner
from rimscan_cli.recon.takeover import FingerprintDatabase, TakeoverDetector, TakeoverVerdict

logger = logging.getLogger(__name__)

NUCLEI_EXCLUDED_TAGS = ("dos", "fuzz", "intrusive")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TAKEOVER_SEVERITY = {
    TakeoverVerdict.VULNERABLE.value: "high",
    TakeoverVerdict.LIKELY.value: "medium",
    TakeoverVerdict.UNKNOWN_SERVICE.value: "info",
}
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

Progress = Callable[[str], None]


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII hostname, or raise ValueError if `value` is not a domain name."""
    domain = value.strip().lower().rstrip(".")
    if not domain or any(char in domain for char in "/:@ ?#"):
        raise ValueError("domain must be a bare hostname such as example.com (no scheme, path, port or user)")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported; pass a domain name")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"{value!r} is not a valid domain name") from None
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"{value!r} is not a valid domain name")
    return domain


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_jsonable(item) for key, item in value.items()}
    return value


def _parse_nuclei_output(text: str) -> List[Dict[str, Any]]:
    findings = []
    for line in text.splitlines():
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        info = raw.get("info", {})
        findings.append({
            "template_id": raw.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity", "info"),
            "host": raw.get("host"),
            "matched_at": raw.get("matched-at"),
            "tags": info.get("tags", []),
            "cve": (info.get("classification") or {}).get("cve-id") or [],
        })
    return findings


def run_nuclei(hosts: Iterable[str], *, rate_limit: int = 75, timeout: float = 1800.0) -> Dict[str, Any]:
    """Run Nuclei against `hosts` with dos, fuzz and intrusive templates excluded."""
    binary = shutil.which("nuclei")
    if not binary:
        return {"status": "skipped", "reason": "nuclei executable not found in PATH"}
    host_list = list(dict.fromkeys(hosts))
    if not host_list:
        return {"status": "skipped", "reason": "no live hosts"}

    with tempfile.TemporaryDirectory(prefix="rimscan-cli-") as temp_dir:
        targets = Path(temp_dir) / "targets.txt"
        targets.write_text("\n".join(host_list) + "\n", encoding="utf-8")
        command = [
            binary, "-list", str(targets),
            "-etags", ",".join(NUCLEI_EXCLUDED_TAGS),
            "-rate-limit", str(rate_limit),
            "-jsonl", "-silent", "-no-color", "-disable-update-check",
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return {"status": "timeout", "timeout_seconds": timeout, "findings": _parse_nuclei_output(partial)}

    result: Dict[str, Any] = {
        "status": "completed" if completed.returncode == 0 else "failed",
        "returncode": completed.returncode,
        "findings": _parse_nuclei_output(completed.stdout),
    }
    if completed.returncode != 0:
        result["stderr"] = completed.stderr[-500:]
    return result


def _validate(
    domain: str,
    *,
    authorized: bool,
    include_zone_transfer: bool,
    include_secrets: bool,
    include_nuclei: bool,
    sources: Optional[Sequence[str]],
    nameservers: Optional[Sequence[str]],
) -> str:
    domain = normalize_domain(domain)
    for flag, enabled in (
        ("--secrets", include_secrets),
        ("--nuclei", include_nuclei),
        ("--zone-transfer", include_zone_transfer),
    ):
        if enabled and not authorized:
            raise PermissionError(f"{flag} sends probes to the target's own servers and requires --authorized")
    unknown = [name for name in sources or () if name not in DEFAULT_SOURCES]
    if unknown:
        raise ValueError(f"unknown source(s): {', '.join(unknown)} (choose from {', '.join(DEFAULT_SOURCES)})")
    for address in nameservers or ():
        ipaddress.ip_address(address)
    return domain


def scan_domain(
    domain: str,
    *,
    authorized: bool = False,
    include_zone_transfer: bool = False,
    include_secrets: bool = False,
    include_certs: bool = True,
    include_nuclei: bool = False,
    bruteforce: bool = False,
    sources: Optional[Sequence[str]] = None,
    timeout: float = 10.0,
    nameservers: Optional[Sequence[str]] = None,
    nuclei_rate_limit: int = 75,
    progress: Progress = lambda message: None,
) -> Dict[str, Any]:
    """Run a standalone scan and return a JSON-serializable result."""
    domain = _validate(
        domain,
        authorized=authorized,
        include_zone_transfer=include_zone_transfer,
        include_secrets=include_secrets,
        include_nuclei=include_nuclei,
        sources=sources,
        nameservers=nameservers,
    )

    progress(f"enumerating subdomains of {domain}")
    enumerator = SubdomainEnumerator(domain, timeout=timeout)
    subdomains = enumerator.run(
        list(sources) if sources else None,
        on_source_done=lambda name, count, status: progress(f"  {name}: {count} found ({status})"),
    )

    resolver = DNSResolver(timeout=min(timeout, 5.0), nameservers=nameservers)
    wildcard = resolver.detect_wildcard(domain)
    if wildcard:
        progress("wildcard DNS detected; wildcard answers are filtered out")
    if bruteforce:
        progress("brute-forcing common subdomain names")
        subdomains |= enumerator.from_bruteforce(resolver)

    hosts = sorted({domain, *subdomains})
    progress(f"resolving {len(hosts)} hosts")
    resolutions = resolver.resolve_many(hosts)
    live_hosts = [r.hostname for r in resolutions if r.is_live]

    progress("checking for subdomain takeovers")
    detector = TakeoverDetector(FingerprintDatabase(), timeout=timeout)
    takeovers = [detector.check(r) for r in resolutions]
    takeovers = [f for f in takeovers if f is not None and f.verdict is not TakeoverVerdict.NOT_VULNERABLE]

    progress("auditing DNS records")
    result: Dict[str, Any] = {
        "domain": domain,
        "wildcard_dns": wildcard,
        "sources": dict(enumerator.source_status),
        "subdomains": sorted(subdomains),
        "resolutions": resolutions,
        "takeover_findings": takeovers,
        "dns_findings": DNSAuditor().audit(domain, include_zone_transfer=include_zone_transfer),
    }
    if include_certs:
        progress(f"auditing TLS certificates on {len(live_hosts)} live hosts")
        result["certificate_findings"] = CertAuditor().audit_many(live_hosts)
    if include_secrets:
        progress("scanning well-known paths for exposed secrets")
        result["secret_findings"] = SecretScanner().scan_domain(live_hosts)
    if include_nuclei:
        progress("running nuclei")
        result["nuclei"] = run_nuclei(live_hosts, rate_limit=nuclei_rate_limit)
    return _to_jsonable(result)


def severity_counts(result: Dict[str, Any]) -> Dict[str, int]:
    counts: Dict[str, int] = {}

    def add(level: str) -> None:
        counts[level] = counts.get(level, 0) + 1

    for finding in result.get("takeover_findings", []):
        add(_TAKEOVER_SEVERITY.get(finding["verdict"], "info"))
    for key in ("dns_findings", "certificate_findings"):
        for finding in result.get(key, []):
            add(finding["severity"])
    for _ in result.get("secret_findings", []):
        add("high")
    for finding in result.get("nuclei", {}).get("findings", []):
        add(finding["severity"] if finding["severity"] in SEVERITY_RANK else "info")
    return counts


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
            "to stderr."
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
    scan.add_argument("--nuclei-rate-limit", type=int, default=75, metavar="N", help="Nuclei requests per second (default: 75)")
    scan.add_argument("--bruteforce", action="store_true", help="also resolve a short list of common subdomain names")
    scan.add_argument("--no-certs", action="store_true", help="skip the TLS certificate audit")
    scan.add_argument("--sources", type=lambda s: [p.strip() for p in s.split(",") if p.strip()], metavar="LIST",
                      help=f"comma-separated enumeration sources (default: {','.join(DEFAULT_SOURCES)})")
    scan.add_argument("--resolver", type=lambda s: [p.strip() for p in s.split(",") if p.strip()], metavar="IPS",
                      help="comma-separated DNS resolver addresses (default: system resolver)")
    scan.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS", help="network timeout (default: 10)")
    scan.add_argument("-o", "--output", type=Path, help="write JSON results to this file instead of stdout")
    scan.add_argument("--fail-on", choices=[*SEVERITY_RANK, "none"], default="none",
                      help="exit with status 1 if any finding is at or above this severity")
    scan.add_argument("-q", "--quiet", action="store_true", help="no banner, progress or summary on stderr")
    scan.add_argument("--no-banner", action="store_true", help="do not print the banner")
    scan.add_argument("--verbose", action="store_true", help="enable debug logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    if not (args.quiet or args.no_banner):
        with contextlib.redirect_stdout(sys.stderr):
            render_banner()

    def progress(message: str) -> None:
        if not args.quiet:
            print(f"[*] {message}", file=sys.stderr)

    options = dict(
        authorized=args.authorized,
        include_zone_transfer=args.zone_transfer,
        include_secrets=args.secrets,
        include_nuclei=args.nuclei,
        sources=args.sources,
        nameservers=args.resolver,
    )
    try:
        _validate(args.domain, **options)
        result = scan_domain(
            args.domain,
            include_certs=not args.no_certs,
            bruteforce=args.bruteforce,
            timeout=args.timeout,
            nuclei_rate_limit=args.nuclei_rate_limit,
            progress=progress,
            **options,
        )
    except (PermissionError, ValueError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc.strerror}", file=sys.stderr)
            return 2
        progress(f"results written to {args.output}")
    else:
        print(rendered)

    counts = severity_counts(result)
    if counts:
        summary = ", ".join(f"{n} {level}" for level, n in sorted(counts.items(), key=lambda kv: -SEVERITY_RANK[kv[0]]))
        progress(f"findings: {summary}")
    else:
        progress("no findings")
    if args.fail_on != "none" and any(SEVERITY_RANK[level] >= SEVERITY_RANK[args.fail_on] for level in counts):
        return 1
    return 0
