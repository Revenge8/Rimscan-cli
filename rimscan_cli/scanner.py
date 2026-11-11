"""Scan orchestration: enumerate, resolve and audit a domain. The CLI is a thin layer over this."""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from rimscan_cli import __version__
from rimscan_cli.recon._common import all_public, normalize_domain
from rimscan_cli.recon.cert_audit import CertAuditor
from rimscan_cli.recon.dns_audit import DNSAuditor
from rimscan_cli.recon.enumeration import DEFAULT_SOURCES, SubdomainEnumerator
from rimscan_cli.recon.resolver import DNSResolver, ResolutionStatus
from rimscan_cli.recon.secret_scan import SecretScanner
from rimscan_cli.recon.takeover import FingerprintDatabase, TakeoverDetector, TakeoverVerdict

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
NUCLEI_EXCLUDED_TAGS = ("dos", "fuzz", "intrusive")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TAKEOVER_SEVERITY = {
    TakeoverVerdict.VULNERABLE.value: "high",
    TakeoverVerdict.LIKELY.value: "medium",
    TakeoverVerdict.UNKNOWN_SERVICE.value: "info",
}

Progress = Callable[[str], None]


class InvalidArguments(Exception):
    """The caller passed arguments that cannot be used (reported as a usage error)."""


class AuthorizationError(InvalidArguments):
    """An option that probes the target was requested without --authorized."""


def to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
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
    """Return the normalized domain, or raise InvalidArguments / AuthorizationError."""
    try:
        domain = normalize_domain(domain)
    except ValueError as exc:
        raise InvalidArguments(str(exc)) from None
    for flag, enabled in (
        ("--secrets", include_secrets),
        ("--nuclei", include_nuclei),
        ("--zone-transfer", include_zone_transfer),
    ):
        if enabled and not authorized:
            raise AuthorizationError(f"{flag} sends probes to the target's own servers and requires --authorized")
    unknown = [name for name in sources or () if name not in DEFAULT_SOURCES]
    if unknown:
        raise InvalidArguments(f"unknown source(s): {', '.join(unknown)} (choose from {', '.join(DEFAULT_SOURCES)})")
    for address in nameservers or ():
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise InvalidArguments(str(exc)) from None
    return domain


def scan_domain(
    domain: str,
    *,
    authorized: bool = False,
    include_zone_transfer: bool = False,
    include_secrets: bool = False,
    include_certs: bool = True,
    include_nuclei: bool = False,
    include_third_party: bool = False,
    bruteforce: bool = False,
    sources: Optional[Sequence[str]] = None,
    timeout: float = 10.0,
    nameservers: Optional[Sequence[str]] = None,
    nuclei_rate_limit: int = 75,
    progress: Progress = lambda message: None,
) -> Dict[str, Any]:
    """Run a standalone scan and return a JSON-serializable result.

    Raises InvalidArguments (AuthorizationError for a missing --authorized) before any
    network activity if the arguments are unusable.

    `nameservers` applies to DNS lookups only; TLS and HTTP probes use the system resolver.
    Hosts that resolve to a non-public address are never probed. With `include_secrets` or
    `include_nuclei`, hosts that CNAME to a known third-party service are skipped unless
    `include_third_party` is set, because those servers belong to someone else.
    """
    domain = _validate(
        domain,
        authorized=authorized,
        include_zone_transfer=include_zone_transfer,
        include_secrets=include_secrets,
        include_nuclei=include_nuclei,
        sources=sources,
        nameservers=nameservers,
    )
    warnings: List[str] = []
    incomplete = False

    progress(f"enumerating subdomains of {domain}")
    chosen_sources = list(sources) if sources else list(DEFAULT_SOURCES)
    enumerator = SubdomainEnumerator(domain, timeout=timeout)
    subdomains = enumerator.run(
        chosen_sources,
        on_source_done=lambda name, count, status: progress(f"  {name}: {count} found ({status})"),
    )
    failed_sources = [name for name in chosen_sources if enumerator.source_status.get(name) != "ok"]
    if failed_sources and len(failed_sources) == len(chosen_sources):
        warnings.append("every enumeration source failed or timed out; the subdomain list is not reliable")
        incomplete = not bruteforce
    elif failed_sources:
        warnings.append(f"enumeration sources failed or timed out: {', '.join(failed_sources)}")

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
    live = [r for r in resolutions if r.is_live]
    public_hosts = [r.hostname for r in live if all_public(r.a_records)]
    non_public = [r.hostname for r in live if not all_public(r.a_records)]
    if non_public:
        progress(f"{len(non_public)} host(s) resolve to non-public addresses and will not be probed")

    progress("checking for subdomain takeovers")
    database = FingerprintDatabase()
    detector = TakeoverDetector(database, timeout=timeout)
    takeovers = [f for f in detector.check_many(resolutions) if f is not None and f.verdict is not TakeoverVerdict.NOT_VULNERABLE]

    progress("auditing DNS records")
    auditor = DNSAuditor(timeout=min(timeout, 5.0), nameservers=nameservers)
    dns_findings = auditor.audit(domain, include_zone_transfer=include_zone_transfer)
    if auditor.errors:
        warnings.append(f"DNS audit incomplete: {'; '.join(auditor.errors)}")
        incomplete = True

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "rimscan-cli", "version": __version__},
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "domain": domain,
        "wildcard_dns": wildcard,
        "wildcard_filtered": sum(1 for r in resolutions if r.status is ResolutionStatus.WILDCARD),
        "sources": dict(enumerator.source_status),
        "subdomains": sorted(subdomains),
        "resolutions": resolutions,
        "takeover_findings": takeovers,
        "dns_findings": dns_findings,
    }
    if include_certs:
        progress(f"auditing TLS certificates on {len(public_hosts)} live hosts")
        result["certificate_findings"] = CertAuditor(timeout=timeout).audit_many(public_hosts)

    if include_secrets or include_nuclei:
        third_party = {
            r.hostname for r in resolutions if any(database.match(hop) for hop in r.cname_chain)
        }
        active_hosts = public_hosts if include_third_party else [h for h in public_hosts if h not in third_party]
        skipped_third_party = [h for h in public_hosts if h not in active_hosts]
        if skipped_third_party:
            progress(
                f"skipping {len(skipped_third_party)} host(s) that CNAME to third-party services "
                "(use --include-third-party to probe them)"
            )
        result["active_targets"] = active_hosts
        result["skipped_hosts"] = {"non_public": non_public, "third_party": skipped_third_party}
        if include_secrets:
            progress(f"scanning well-known paths on {len(active_hosts)} hosts for exposed secrets")
            result["secret_findings"] = SecretScanner(timeout=(min(timeout, 5.0), timeout)).scan_domain(active_hosts)
        if include_nuclei:
            progress("running nuclei")
            result["nuclei"] = run_nuclei(active_hosts, rate_limit=nuclei_rate_limit)

    result["warnings"] = warnings
    result["incomplete"] = incomplete
    return to_jsonable(result)


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
