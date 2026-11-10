"""TLS certificate checks: validity, expiry and protocol support."""

from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence

import certifi

from rimscan_cli.recon._common import normalize_name
from rimscan_cli.recon.severity import Severity

__all__ = ["CertAuditFinding", "CertAuditor", "CertSeverity"]

# Kept so existing imports keep working; there is a single Severity enum.
CertSeverity = Severity

logger = logging.getLogger(__name__)

# OpenSSL X509_V_ERR_* codes reported by ssl.SSLCertVerificationError.verify_code.
_VERIFY_FINDINGS = {
    10: ("expired", Severity.CRITICAL, "Certificate has expired"),
    9: ("not_yet_valid", Severity.HIGH, "Certificate is not yet valid"),
    18: ("self_signed", Severity.HIGH, "Certificate is self-signed"),
    19: ("self_signed", Severity.HIGH, "Certificate chain ends in an untrusted self-signed root"),
    20: ("untrusted_chain", Severity.HIGH, "Certificate issuer is not trusted (missing intermediate or unknown CA)"),
    21: ("untrusted_chain", Severity.HIGH, "Certificate chain is incomplete"),
    62: ("hostname_mismatch", Severity.HIGH, "Certificate does not match the hostname"),
}

_PROTOCOL_REASONS = ("UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE", "PROTOCOL_VERSION")


@dataclass
class CertAuditFinding:
    check: str
    severity: Severity
    hostname: str
    detail: str
    expires: Optional[str] = None


def _context() -> ssl.SSLContext:
    """A client context whose results do not depend on the Python version or the OS.

    - the CA bundle is certifi's, so a slim image without ca-certificates does not
      report every host as untrusted;
    - TLS 1.2 is the floor on every Python version, so the "protocol" check is stable;
    - strict X.509 checking (default since Python 3.13) is off, so the same certificate
      gives the same verdict on 3.10 and 3.13.
    """
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


class CertAuditor:
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        self.timeout = timeout
        self.max_workers = max_workers

    def _handshake(self, hostname: str, port: int) -> dict:
        context = _context()
        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.getpeercert() or {}

    def audit_host(self, hostname: str, port: int = 443) -> List[CertAuditFinding]:
        hostname = normalize_name(hostname)
        try:
            cert = self._handshake(hostname, port)
        except ssl.SSLCertVerificationError as exc:
            check, severity, detail = _VERIFY_FINDINGS.get(
                exc.verify_code, ("invalid", Severity.HIGH, f"Certificate failed verification: {exc.verify_message}")
            )
            return [CertAuditFinding(check, severity, hostname, detail)]
        except ssl.SSLError as exc:
            reason = getattr(exc, "reason", "") or ""
            if any(marker in reason for marker in _PROTOCOL_REASONS):
                return [CertAuditFinding(
                    "protocol", Severity.HIGH, hostname, "Server does not support TLS 1.2 or newer"
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
            severity = Severity.HIGH
        elif days_left <= 30:
            severity = Severity.MEDIUM
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
