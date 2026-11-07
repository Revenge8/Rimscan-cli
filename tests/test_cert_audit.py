import socket
import ssl
import time

import pytest

from rimscan_cli.recon.cert_audit import CertAuditor, CertSeverity


def verification_error(code, message="x"):
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_code, exc.verify_message = code, message
    return exc


def raising(exc):
    def handshake(hostname, port):
        raise exc
    return handshake


def not_after(days):
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + days * 86400 + 3600))


@pytest.mark.parametrize("code,check,severity", [
    (10, "expired", CertSeverity.CRITICAL),
    (62, "hostname_mismatch", CertSeverity.HIGH),
    (18, "self_signed", CertSeverity.HIGH),
    (20, "untrusted_chain", CertSeverity.HIGH),
])
def test_verification_failures_get_specific_findings(code, check, severity):
    a = CertAuditor()
    a._handshake = raising(verification_error(code))
    (finding,) = a.audit_host("example.com")
    assert (finding.check, finding.severity) == (check, severity)


def test_unknown_verify_code_still_reported():
    a = CertAuditor()
    a._handshake = raising(verification_error(99, "weird failure"))
    (finding,) = a.audit_host("example.com")
    assert finding.check == "invalid" and "weird failure" in finding.detail


@pytest.mark.parametrize("exc", [ConnectionRefusedError(), socket.timeout(), socket.gaierror(), OSError("net")])
def test_hosts_without_https_are_not_findings(exc):
    a = CertAuditor()
    a._handshake = raising(exc)
    assert a.audit_host("example.com") == []


def test_unsupported_protocol_is_reported():
    err = ssl.SSLError(1, "[SSL: UNSUPPORTED_PROTOCOL] unsupported protocol")
    err.reason = "UNSUPPORTED_PROTOCOL"
    a = CertAuditor()
    a._handshake = raising(err)
    assert a.audit_host("example.com")[0].check == "protocol"


def test_non_tls_service_on_443_is_not_a_finding():
    err = ssl.SSLError(1, "wrong version")
    err.reason = "WRONG_VERSION_NUMBER"
    a = CertAuditor()
    a._handshake = raising(err)
    assert a.audit_host("example.com") == []


@pytest.mark.parametrize("days,severity", [(5, CertSeverity.HIGH), (20, CertSeverity.MEDIUM), (90, None)])
def test_expiry_windows(days, severity):
    a = CertAuditor()
    a._handshake = lambda hostname, port: {"notAfter": not_after(days)}
    found = a.audit_host("example.com")
    assert [f.severity for f in found] == ([severity] if severity else [])


def test_audit_many_dedupes_and_caps(caplog):
    seen = []
    a = CertAuditor()
    a.audit_host = lambda host: seen.append(host) or []
    a.audit_many(["a.example.com", "a.example.com", "b.example.com", "c.example.com"], max_hosts=2)
    assert sorted(seen) == ["a.example.com", "b.example.com"]
    assert "limited to 2 of 3" in caplog.text
