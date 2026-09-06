"""DNS misconfiguration auditor — SPF, DMARC, zone transfers, wildcards."""

from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass
from enum import Enum
from typing import List

import dns.exception
import dns.query
import dns.resolver
import dns.zone

__all__ = ["DNSAuditFinding", "DNSAuditor", "AuditSeverity"]


class AuditSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DNSAuditFinding:
    check: str
    severity: AuditSeverity
    domain: str
    detail: str
    record: str = ""


class DNSAuditor:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def audit(
        self,
        domain: str,
        include_zone_transfer: bool = False,
    ) -> List[DNSAuditFinding]:
        domain = domain.lower().strip(".")
        findings: List[DNSAuditFinding] = []
        findings.extend(self.check_spf(domain))
        findings.extend(self.check_dmarc(domain))
        findings.extend(self.check_wildcard(domain))
        if include_zone_transfer:
            findings.extend(self.check_zone_transfer(domain))
        findings.extend(self.check_cname_chaining(domain))
        return findings

    def run(
        self,
        domain: str,
        include_zone_transfer: bool | None = None,
    ) -> List[DNSAuditFinding]:
        """Alias for audit() — used by CLI and API."""
        if include_zone_transfer is None:
            return self.audit(domain)
        return self.audit(domain, include_zone_transfer=include_zone_transfer)

    def check_spf(self, domain: str) -> List[DNSAuditFinding]:
        findings: List[DNSAuditFinding] = []
        try:
            answers = self.resolver.resolve(domain, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return findings

        spf_records = [
            str(r).strip('"')
            for r in answers
            if str(r).strip('"').lower().startswith("v=spf1")
        ]
        if not spf_records:
            findings.append(
                DNSAuditFinding("spf", AuditSeverity.MEDIUM, domain, "No SPF record found")
            )
            return findings

        spf = spf_records[0]
        if "+all" in spf or "?all" in spf:
            findings.append(
                DNSAuditFinding(
                    "spf", AuditSeverity.HIGH, domain,
                    "Permissive SPF policy (+all or ?all)", spf,
                )
            )
        elif "~all" in spf:
            findings.append(
                DNSAuditFinding(
                    "spf", AuditSeverity.MEDIUM, domain,
                    "Soft-fail SPF policy (~all)", spf,
                )
            )
        elif "-all" in spf:
            findings.append(
                DNSAuditFinding(
                    "spf", AuditSeverity.INFO, domain,
                    "Strict SPF policy (-all)", spf,
                )
            )
        return findings

    def check_dmarc(self, domain: str) -> List[DNSAuditFinding]:
        findings: List[DNSAuditFinding] = []
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            findings.append(
                DNSAuditFinding("dmarc", AuditSeverity.HIGH, domain, "No DMARC record found")
            )
            return findings

        for r in answers:
            record = str(r).strip('"')
            if not record.lower().startswith("v=dmarc1"):
                continue
            policy_match = re.search(r"\bp=(\w+)", record, re.I)
            policy = policy_match.group(1).lower() if policy_match else "none"
            severity_map = {
                "none": AuditSeverity.HIGH,
                "quarantine": AuditSeverity.MEDIUM,
                "reject": AuditSeverity.INFO,
            }
            findings.append(
                DNSAuditFinding(
                    "dmarc", severity_map.get(policy, AuditSeverity.MEDIUM), domain,
                    f"DMARC policy p={policy}", record,
                )
            )
        return findings

    def check_wildcard(self, domain: str) -> List[DNSAuditFinding]:
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        probe = f"{label}.{domain}"
        try:
            self.resolver.resolve(probe, "A")
            return [
                DNSAuditFinding(
                    "wildcard", AuditSeverity.MEDIUM, domain,
                    f"Wildcard DNS detected (probe {probe} resolved)",
                )
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.Timeout:
            return []

    def check_cname_chaining(self, domain: str) -> List[DNSAuditFinding]:
        """Flag hostnames with deep CNAME chains that may indicate misconfiguration."""
        findings: List[DNSAuditFinding] = []
        probes = [domain, f"www.{domain}", f"mail.{domain}"]
        max_depth = 5

        for hostname in probes:
            chain: List[str] = []
            current = hostname
            visited = {current}
            depth = 0

            while depth < max_depth + 2:
                try:
                    answer = self.resolver.resolve(current, "CNAME")
                    target = str(answer[0].target).rstrip(".").lower()
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    break
                except Exception:
                    break

                if target in visited:
                    findings.append(
                        DNSAuditFinding(
                            "cname_chain", AuditSeverity.HIGH, domain,
                            f"CNAME loop detected starting at {hostname}: {' -> '.join(chain + [target])}",
                            hostname,
                        )
                    )
                    break

                visited.add(target)
                chain.append(target)
                current = target
                depth += 1

            if depth > max_depth:
                findings.append(
                    DNSAuditFinding(
                        "cname_chain", AuditSeverity.MEDIUM, domain,
                        f"Deep CNAME chain ({depth} hops) for {hostname}: {' -> '.join(chain)}",
                        hostname,
                    )
                )

        return findings

    def check_zone_transfer(self, domain: str) -> List[DNSAuditFinding]:
        findings: List[DNSAuditFinding] = []
        try:
            ns_answers = self.resolver.resolve(domain, "NS")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return findings

        for ns in ns_answers:
            ns_host = str(ns.target).rstrip(".")
            try:
                ns_ips = self.resolver.resolve(ns_host, "A")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue
            for ip in ns_ips:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(str(ip), domain, lifetime=self.timeout)
                    )
                    if zone:
                        findings.append(
                            DNSAuditFinding(
                                "zone_transfer", AuditSeverity.CRITICAL, domain,
                                f"Zone transfer (AXFR) allowed on {ns_host} ({ip})",
                                ns_host,
                            )
                        )
                        return findings
                except Exception:
                    continue
        return findings
