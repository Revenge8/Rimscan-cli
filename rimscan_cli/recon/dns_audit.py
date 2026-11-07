"""DNS misconfiguration checks: SPF, DMARC and zone-transfer exposure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

import dns.exception
import dns.query
import dns.rcode
import dns.resolver

__all__ = ["DNSAuditFinding", "DNSAuditor", "AuditSeverity"]

_SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


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

    def audit(self, domain: str, include_zone_transfer: bool = False) -> List[DNSAuditFinding]:
        domain = domain.lower().strip(".")
        findings = self.check_spf(domain) + self.check_dmarc(domain)
        if include_zone_transfer:
            findings += self.check_zone_transfer(domain)
        return findings

    def _txt_records(self, name: str) -> Optional[List[str]]:
        """TXT strings at `name`; [] if none exist, None if the lookup itself failed."""
        try:
            answers = self.resolver.resolve(name, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.exception.DNSException:
            return None
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answers]

    def check_spf(self, domain: str) -> List[DNSAuditFinding]:
        records = self._txt_records(domain)
        if records is None:
            return []
        spf_records = [r for r in records if r.lower().startswith("v=spf1")]
        if not spf_records:
            return [DNSAuditFinding("spf", AuditSeverity.MEDIUM, domain, "No SPF record found")]
        if len(spf_records) > 1:
            return [DNSAuditFinding(
                "spf", AuditSeverity.HIGH, domain,
                "Multiple SPF records; receivers treat this as a permanent error", spf_records[0],
            )]

        spf = spf_records[0]
        for token in spf.split():
            match = _SPF_ALL.match(token)
            if not match:
                continue
            qualifier = match.group(1) or "+"
            if qualifier in "+?":
                return [DNSAuditFinding(
                    "spf", AuditSeverity.HIGH, domain,
                    f"SPF allows any sender ({token.lower()})", spf,
                )]
            if qualifier == "~":
                return [DNSAuditFinding(
                    "spf", AuditSeverity.MEDIUM, domain, "SPF soft-fail policy (~all)", spf
                )]
            return []
        return [DNSAuditFinding(
            "spf", AuditSeverity.MEDIUM, domain, "SPF record has no terminating 'all' mechanism", spf
        )]

    def check_dmarc(self, domain: str) -> List[DNSAuditFinding]:
        records = self._txt_records(f"_dmarc.{domain}")
        if records is None:
            return []
        dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
        if not dmarc:
            return [DNSAuditFinding("dmarc", AuditSeverity.HIGH, domain, "No DMARC record found")]

        record = dmarc[0]
        match = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
        policy = match.group(1).lower() if match else "none"
        if policy == "none":
            return [DNSAuditFinding(
                "dmarc", AuditSeverity.HIGH, domain, "DMARC policy is p=none (monitoring only)", record
            )]
        if policy == "quarantine":
            return [DNSAuditFinding(
                "dmarc", AuditSeverity.MEDIUM, domain, "DMARC policy is p=quarantine", record
            )]
        return []

    def check_zone_transfer(self, domain: str) -> List[DNSAuditFinding]:
        """Ask each nameserver for an AXFR and stop reading after the first reply message."""
        try:
            nameservers = self.resolver.resolve(domain, "NS")
        except dns.exception.DNSException:
            return []

        findings: List[DNSAuditFinding] = []
        for ns in nameservers:
            ns_host = str(ns.target).rstrip(".")
            try:
                addresses = [str(a) for a in self.resolver.resolve(ns_host, "A")]
            except dns.exception.DNSException:
                continue
            for address in addresses:
                if self._axfr_allowed(address, domain):
                    findings.append(DNSAuditFinding(
                        "zone_transfer", AuditSeverity.CRITICAL, domain,
                        f"Zone transfer (AXFR) allowed on {ns_host} ({address})", ns_host,
                    ))
                    break
        return findings

    def _axfr_allowed(self, address: str, domain: str) -> bool:
        try:
            for message in dns.query.xfr(address, domain, lifetime=self.timeout):
                return message.rcode() == dns.rcode.NOERROR and bool(message.answer)
        except (dns.exception.DNSException, OSError, EOFError):
            return False
        return False
