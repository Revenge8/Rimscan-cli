"""Command-line orchestration for passive, authorized reconnaissance."""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from recon.cert_audit import CertAuditor
from recon.dns_audit import DNSAuditor
from recon.enumeration import SubdomainEnumerator
from recon.resolver import DNSResolver
from recon.secrets import SecretScanner
from recon.takeover import FingerprintDatabase, TakeoverDetector

logger = logging.getLogger(__name__)
PASSIVE_NUCLEI_EXCLUDED_TAGS = ("dos", "fuzz", "intrusive")


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _json_value(item) for key, item in asdict(value).items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    return value


def run_standard_nuclei(hosts: Iterable[str], *, output_file: Path | None = None) -> dict[str, Any]:
    """Run Nuclei with active/intrusive template tags structurally excluded."""
    binary = shutil.which("nuclei")
    if not binary:
        return {"status": "skipped", "reason": "nuclei executable was not found"}

    host_list = list(dict.fromkeys(hosts))
    if not host_list:
        return {"status": "skipped", "reason": "no resolved hosts"}

    with tempfile.TemporaryDirectory(prefix="rimscan-cli-") as temp_dir:
        targets = Path(temp_dir) / "targets.txt"
        targets.write_text("\n".join(host_list) + "\n", encoding="utf-8")
        command = [
            binary,
            "-list",
            str(targets),
            "-etags",
            ",".join(PASSIVE_NUCLEI_EXCLUDED_TAGS),
            "-jsonl",
        ]
        if output_file:
            command.extend(["-o", str(output_file)])
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        return {
            "status": "completed" if completed.returncode == 0 else "failed",
            "returncode": completed.returncode,
            "command": command,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }


def scan_domain(
    domain: str,
    *,
    authorized: bool = False,
    include_zone_transfer: bool = False,
    include_secrets: bool = False,
    include_certs: bool = True,
    include_nuclei: bool = False,
) -> dict[str, Any]:
    """Run the standalone passive scan without persistence or SaaS dependencies."""
    domain = domain.lower().strip().strip(".")
    if not domain or any(char in domain for char in "/:@ "):
        raise ValueError("domain must be a hostname, not a URL, email address, or IP-style target")
    if include_secrets and not authorized:
        raise PermissionError("--secrets requires --authorized because it sends requests to target endpoints")

    enumerator = SubdomainEnumerator(domain)
    subdomains = sorted(enumerator.run())
    hosts = sorted(set([domain, *subdomains]))
    resolver = DNSResolver()
    resolutions = resolver.resolve_many(hosts)
    detector = TakeoverDetector(FingerprintDatabase())
    takeover_findings = [detector.check(result) for result in resolutions]
    takeover_findings = [finding for finding in takeover_findings if finding is not None]

    result: dict[str, Any] = {
        "domain": domain,
        "subdomains": subdomains,
        "resolutions": resolutions,
        "takeover_findings": takeover_findings,
        "dns_findings": DNSAuditor().audit(domain, include_zone_transfer=include_zone_transfer),
    }
    if include_certs:
        result["certificate_findings"] = CertAuditor().audit_many(hosts)
    if include_secrets:
        result["secret_findings"] = SecretScanner(authorized=True).scan_domain(domain, hosts=hosts)
    if include_nuclei:
        result["nuclei"] = run_standard_nuclei(hosts)
    return _json_value(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rimscan-cli",
        description="Passive reconnaissance for domains you own or are explicitly authorized to test.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="enumerate and audit an authorized domain")
    scan.add_argument("domain", help="hostname to scan; do not include https:// or a path")
    scan.add_argument("--authorized", action="store_true", help="confirm you own or have permission to test this target")
    scan.add_argument("--secrets", action="store_true", help="fetch common public paths for exposed-secret checks (requires --authorized)")
    scan.add_argument("--zone-transfer", action="store_true", help="check DNS servers for AXFR exposure")
    scan.add_argument("--no-certs", action="store_true", help="skip the standard TLS certificate audit")
    scan.add_argument("--nuclei", action="store_true", help="run standard Nuclei with dos,fuzz,intrusive templates excluded")
    scan.add_argument("--output", type=Path, help="write JSON results to this file")
    scan.add_argument("--verbose", action="store_true", help="enable diagnostic logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.error("a command is required")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")
    try:
        result = scan_domain(
            args.domain,
            authorized=args.authorized,
            include_zone_transfer=args.zone_transfer,
            include_secrets=args.secrets,
            include_certs=not args.no_certs,
            include_nuclei=args.nuclei,
        )
    except (PermissionError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0

