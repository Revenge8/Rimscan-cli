"""Regression tests for the second round of review fixes."""

import json
from types import SimpleNamespace

import dns.rcode
import dns.resolver
import pytest

from rimscan_cli import cli, scanner
from rimscan_cli.recon import dns_audit, enumeration
from rimscan_cli.recon.dns_audit import AuditSeverity as Sev, DNSAuditor
from rimscan_cli.recon.enumeration import SubdomainEnumerator
from rimscan_cli.recon.secret_scan import SecretScanner
from tests.test_scanner import fakes  # noqa: F401  (fixture)

HEADER = "-----BEGIN PRIVATE KEY-----"


class Streamed:
    """A streamed 200 response carrying `payload` as its JSON body."""

    status_code = 200
    headers = {}
    encoding = "utf-8"

    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size=0):
        yield self._body

    def close(self):
        pass


def test_crtsh_response_is_read_with_a_size_cap(monkeypatch):
    data = [{"name_value": "a.example.com"}]
    e = SubdomainEnumerator("example.com")
    e.session = SimpleNamespace(get=lambda url, **kw: Streamed(data))
    assert e.from_crtsh() == {"a.example.com"}
    # Past the cap the body is cut off, no longer parses, and the source fails cleanly.
    monkeypatch.setattr(enumeration, "_CRTSH_MAX_BYTES", 10)
    with pytest.raises(ValueError):
        e.from_crtsh()


def test_crtsh_request_is_streamed():
    seen = {}

    def get(url, **kw):
        seen.update(kw)
        return Streamed([])

    e = SubdomainEnumerator("example.com")
    e.session = SimpleNamespace(get=get)
    e.from_crtsh()
    assert seen["stream"] is True


def test_repeated_cli_list_values_are_dropped_in_order():
    assert cli._csv("otx, crt.sh,otx,,crt.sh") == ["otx", "crt.sh"]


def test_repeated_sources_are_queried_once(fakes, monkeypatch):  # noqa: F811
    seen = []
    base = scanner.SubdomainEnumerator  # the fake installed by the fixture

    class Spy(base):
        def run(self, sources, on_source_done=None):
            seen.append(list(sources))
            return super().run(sources, on_source_done)

    monkeypatch.setattr(scanner, "SubdomainEnumerator", Spy)
    scanner.scan_domain("example.com", sources=["otx", "crt.sh", "otx"])
    assert seen == [["otx", "crt.sh"]]


def test_zone_transfer_tries_aaaa_when_a_nameserver_has_no_a_record(monkeypatch):
    auditor = DNSAuditor()
    asked = []

    def resolve(name, rdtype):
        asked.append((name, rdtype))
        if rdtype == "NS":
            return [SimpleNamespace(target="ns1.example.com.")]
        if rdtype == "A":
            raise dns.resolver.NoAnswer()
        return ["2606:4700::1111"]

    auditor.resolver = SimpleNamespace(resolve=resolve)
    monkeypatch.setattr(
        dns_audit.dns.query, "xfr",
        lambda address, domain, lifetime: iter([SimpleNamespace(rcode=lambda: dns.rcode.NOERROR, answer=[object()])]),
    )
    (finding,) = auditor.check_zone_transfer("example.com")
    assert finding.severity is Sev.CRITICAL and "2606:4700::1111" in finding.detail
    assert ("ns1.example.com", "AAAA") in asked and auditor.errors == []


def test_aaaa_is_not_asked_when_the_nameserver_has_an_a_record(monkeypatch):
    auditor = DNSAuditor()
    asked = []

    def resolve(name, rdtype):
        asked.append(rdtype)
        return [SimpleNamespace(target="ns1.example.com.")] if rdtype == "NS" else ["1.1.1.1"]

    def refused(*args, **kwargs):
        raise dns_audit.dns.exception.FormError()
        yield

    auditor.resolver = SimpleNamespace(resolve=resolve)
    monkeypatch.setattr(dns_audit.dns.query, "xfr", refused)
    assert auditor.check_zone_transfer("example.com") == []
    assert "AAAA" not in asked


def test_private_key_header_is_shown_and_key_material_on_the_same_line_is_masked():
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
    line = f'var k="{HEADER}\\n{body}\\n-----END PRIVATE KEY-----";'
    (finding,) = SecretScanner().scan_text(line)
    assert finding.secret_type == "private_key"
    assert finding.context == f'var k="{HEADER}[...]'
    exported = finding.to_dict()
    assert exported["match"] == HEADER
    assert exported["context"] == f'var k="{HEADER}[...]'
    assert body[:8] not in str(exported)


def test_private_key_header_on_its_own_line_is_reported_whole():
    (finding,) = SecretScanner().scan_text("-----BEGIN OPENSSH PRIVATE KEY-----")
    exported = finding.to_dict()
    assert exported["match"] == exported["context"] == "-----BEGIN OPENSSH PRIVATE KEY-----"
