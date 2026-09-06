"""Certificate and TLS auditor."""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

__all__ = ["CertAuditFinding", "CertAuditor", "CertSeverity"]

logger = logging.getLogger(__name__)


class CertSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CertAuditFinding:
    check: str
    severity: CertSeverity
    hostname: str
    detail: str
    expires: Optional[str] = None


class CertAuditor:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def audit_host(self, hostname: str, port: int = 443) -> List[CertAuditFinding]:
        findings: List[CertAuditFinding] = []
        hostname = hostname.lower().strip(".")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
        except ssl.SSLError as e:
            findings.append(
                CertAuditFinding("tls", CertSeverity.HIGH, hostname, f"TLS error: {e}")
            )
            return findings
        except socket.gaierror:
            # DNS resolution failed entirely — this hostname doesn't exist.
            # Not a certificate/TLS finding, just a nonexistent name (very
            # common for unresolved brute-force candidates). Skip silently
            # instead of reporting it as a "connection failed" finding.
            return findings
        except (socket.timeout, OSError) as e:
            findings.append(
                CertAuditFinding("connect", CertSeverity.MEDIUM, hostname, f"Connection failed: {e}")
            )
            return findings

        if protocol in ("TLSv1", "TLSv1.1"):
            findings.append(
                CertAuditFinding(
                    "protocol", CertSeverity.HIGH, hostname,
                    f"Weak TLS protocol in use: {protocol}",
                )
            )

        if cert:
            findings.extend(self._check_expiry(hostname, cert))

        return findings

    def _check_expiry(self, hostname: str, cert: dict) -> List[CertAuditFinding]:
        findings: List[CertAuditFinding] = []
        not_after = cert.get("notAfter")
        if not not_after:
            return findings

        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expires - now).days
        expires_str = expires.isoformat()

        if days_left < 0:
            findings.append(
                CertAuditFinding(
                    "expired", CertSeverity.CRITICAL, hostname,
                    f"Certificate expired {abs(days_left)} days ago", expires_str,
                )
            )
        elif days_left <= 14:
            findings.append(
                CertAuditFinding(
                    "expiring", CertSeverity.HIGH, hostname,
                    f"Certificate expires in {days_left} days", expires_str,
                )
            )
        elif days_left <= 30:
            findings.append(
                CertAuditFinding(
                    "expiring", CertSeverity.MEDIUM, hostname,
                    f"Certificate expires in {days_left} days", expires_str,
                )
            )
        else:
            findings.append(
                CertAuditFinding(
                    "valid", CertSeverity.INFO, hostname,
                    f"Certificate valid for {days_left} days", expires_str,
                )
            )
        return findings

    def audit_many(self, hostnames: List[str], max_hosts: int = 50) -> List[CertAuditFinding]:
        if len(hostnames) > max_hosts:
            logger.debug(
                "Capping cert audit at %d of %d hosts to avoid unbounded live TLS scanning",
                max_hosts,
                len(hostnames),
            )
        all_findings: List[CertAuditFinding] = []
        for host in hostnames[:max_hosts]:
            all_findings.extend(self.audit_host(host))
        return all_findings

    def check(self, domain: str) -> List[CertAuditFinding]:
        """Audit apex and www TLS certificates for a domain."""
        domain = domain.lower().strip(".")
        targets = [domain]
        www = f"www.{domain}"
        if www not in targets:
            targets.append(www)
        return self.audit_many(targets)