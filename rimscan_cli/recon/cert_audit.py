"""TLS certificate checks: validity, expiry and protocol support."""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Sequence

__all__ = ["CertAuditFinding", "CertAuditor", "CertSeverity"]

logger = logging.getLogger(__name__)

# OpenSSL X509_V_ERR_* codes reported by ssl.SSLCertVerificationError.verify_code.
_VERIFY_FINDINGS = {
    10: ("expired", "critical", "Certificate has expired"),
    9: ("not_yet_valid", "high", "Certificate is not yet valid"),
    18: ("self_signed", "high", "Certificate is self-signed"),
    19: ("self_signed", "high", "Certificate chain ends in an untrusted self-signed root"),
    20: ("untrusted_chain", "high", "Certificate issuer is not trusted (missing intermediate or unknown CA)"),
    21: ("untrusted_chain", "high", "Certificate chain is incomplete"),
    62: ("hostname_mismatch", "high", "Certificate does not match the hostname"),
}


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
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers

    def _handshake(self, hostname: str, port: int) -> dict:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.getpeercert() or {}

    def audit_host(self, hostname: str, port: int = 443) -> List[CertAuditFinding]:
        hostname = hostname.lower().strip(".")
        try:
            cert = self._handshake(hostname, port)
        except ssl.SSLCertVerificationError as exc:
            check, severity, detail = _VERIFY_FINDINGS.get(
                exc.verify_code, ("invalid", "high", f"Certificate failed verification: {exc.verify_message}")
            )
            return [CertAuditFinding(check, CertSeverity(severity), hostname, detail)]
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", "") or ""
            if "UNSUPPORTED_PROTOCOL" in reason or "NO_PROTOCOLS_AVAILABLE" in reason:
                return [CertAuditFinding(
                    "protocol", CertSeverity.HIGH, hostname, "Server does not support TLS 1.2 or newer"
                )]
            logger.debug("%s: TLS handshake failed (%s)", hostname, reason)
            return []
        except OSError as exc:
            # No listener on 443, filtered port, DNS failure: the host simply has no HTTPS.
            logger.debug("%s: connection failed (%s)", hostname, type(exc).__name__)
            return []
        return self._check_expiry(hostname, cert)

    @staticmethod
    def _check_expiry(hostname: str, cert: dict) -> List[CertAuditFinding]:
        not_after = cert.get("notAfter")
        if not not_after:
            return []
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left <= 14:
            severity = CertSeverity.HIGH
        elif days_left <= 30:
            severity = CertSeverity.MEDIUM
        else:
            return []
        return [CertAuditFinding(
            "expiring", severity, hostname, f"Certificate expires in {days_left} days", expires.isoformat()
        )]

    def audit_many(self, hostnames: Sequence[str], max_hosts: int = 100) -> List[CertAuditFinding]:
        hosts = list(dict.fromkeys(hostnames))
        if len(hosts) > max_hosts:
            logger.warning("Certificate audit limited to %d of %d hosts", max_hosts, len(hosts))
            hosts = hosts[:max_hosts]
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            results = pool.map(self.audit_host, hosts)
        return [finding for host_findings in results for finding in host_findings]
