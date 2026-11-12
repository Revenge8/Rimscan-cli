"""DNS misconfiguration checks: SPF, DMARC and zone-transfer exposure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence

import dns.exception
import dns.query
import dns.rcode
import dns.resolver

from rimscan_cli.recon._common import is_public_address, normalize_name
from rimscan_cli.recon.severity import Severity

__all__ = ["DNSAuditFinding", "DNSAuditor", "AuditSeverity"]

# Kept so existing imports keep working; there is a single Severity enum.
AuditSeverity = Severity

_SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)
_DMARC_START = re.compile(r"^v=dmarc1\s*(?:;|$)", re.IGNORECASE)


def _is_spf(record: str) -> bool:
    text = record.strip().lower()
    return text == "v=spf1" or text.startswith("v=spf1 ")


def _dmarc_tag(record: str, tag: str) -> Optional[str]:
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}\s*=\s*(\w+)", record, re.IGNORECASE)
    return match.group(1).lower() if match else None


@dataclass
class DNSAuditFinding:
    check: str
    severity: Severity
    domain: str
    detail: str
    record: str = ""


class DNSAuditor:
    def __init__(self, timeout: float = 5.0, nameservers: Optional[Sequence[str]] = None):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        if nameservers:
            self.resolver.nameservers = list(nameservers)
        # Lookups that failed (timeout, SERVFAIL, ...). A failed lookup produces no finding,
        # so callers use this to tell "clean" apart from "could not check".
        self.errors: List[str] = []

    def audit(self, domain: str, include_zone_transfer: bool = False) -> List[DNSAuditFinding]:
        domain = normalize_name(domain)
        self.errors = []
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
            self.errors.append(f"TXT lookup for {name} failed")
            return None
        return [b"".join(rdata.strings).decode("utf-8", "replace") for rdata in answers]

    def check_spf(self, domain: str) -> List[DNSAuditFinding]:
        records = self._txt_records(domain)
        if records is None:
            return []
        spf_records = [r for r in records if _is_spf(r)]
        if not spf_records:
            return [DNSAuditFinding("spf", Severity.MEDIUM, domain, "No SPF record found")]
        if len(spf_records) > 1:
            return [DNSAuditFinding(
                "spf", Severity.HIGH, domain,
                "Multiple SPF records; receivers treat this as a permanent error", spf_records[0],
            )]

        spf = spf_records[0]
        tokens = spf.split()[1:]
        for token in tokens:
            match = _SPF_ALL.match(token)
            if not match:
                continue
            qualifier = match.group(1) or "+"
            if qualifier in "+?":
                return [DNSAuditFinding(
                    "spf", Severity.HIGH, domain,
                    f"SPF allows any sender ({token.lower()})", spf,
                )]
            if qualifier == "~":
                return [DNSAuditFinding(
                    "spf", Severity.MEDIUM, domain, "SPF soft-fail policy (~all)", spf
                )]
            return []
        # RFC 7208: without an "all" mechanism, redirect= supplies the policy instead.
        if any(token.lower().startswith("redirect=") for token in tokens):
            return []
        return [DNSAuditFinding(
            "spf", Severity.MEDIUM, domain, "SPF record has no terminating 'all' mechanism", spf
        )]

    def check_dmarc(self, domain: str) -> List[DNSAuditFinding]:
        """Look for DMARC at the domain, then at each parent (subdomains inherit the policy).

        Parents are walked down to two labels because there is no public-suffix list here.
        """
        labels = domain.split(".")
        candidates = [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]

        record = ""
        found_at = domain
        for name in candidates:
            records = self._txt_records(f"_dmarc.{name}")
            if records is None:
                return []
            matching = [r for r in records if _DMARC_START.match(r.strip())]
            if matching:
                record, found_at = matching[0], name
                break
        else:
            return [DNSAuditFinding("dmarc", Severity.HIGH, domain, "No DMARC record found")]

        policy = _dmarc_tag(record, "p") or "none"
        suffix = ""
        if found_at != domain:
            policy = _dmarc_tag(record, "sp") or policy
            suffix = f" (inherited from {found_at})"
        if policy == "none":
            return [DNSAuditFinding(
                "dmarc", Severity.HIGH, domain, f"DMARC policy is p=none (monitoring only){suffix}", record
            )]
        if policy == "quarantine":
            return [DNSAuditFinding(
                "dmarc", Severity.MEDIUM, domain, f"DMARC policy is p=quarantine{suffix}", record
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
                if not is_public_address(address):
                    continue  # never send a transfer request to an internal address
                if self._axfr_allowed(address, domain):
                    findings.append(DNSAuditFinding(
                        "zone_transfer", Severity.CRITICAL, domain,
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
