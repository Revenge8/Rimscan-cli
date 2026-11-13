"""Regression tests for the bugs found in the code review."""

from pathlib import Path
from types import SimpleNamespace

import dns.exception
import dns.resolver
import requests

from rimscan_cli.recon._http import make_session
from rimscan_cli.recon.dns_audit import DNSAuditor
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus as S
from rimscan_cli.recon.secret_scan import COMMON_PATHS, SecretScanner
from rimscan_cli.recon.takeover import FingerprintDatabase, TakeoverDetector, TakeoverVerdict as V

FIXTURE = Path(__file__).with_name("fixtures_fingerprints.json")


class BrokenBody:
    """A 200 response whose connection dies while the body is being read."""

    status_code = 200
    headers = {"Content-Type": "text/plain"}
    encoding = "utf-8"

    def __init__(self):
        self.closed = False

    def iter_content(self, chunk_size=0):
        raise requests.ConnectionError("connection reset")
        yield b""  # pragma: no cover - makes this a generator

    def close(self):
        self.closed = True


def test_mid_body_failure_skips_the_path_instead_of_aborting_the_scan():
    urls, responses = [], []

    def get(url, **kw):
        urls.append(url)
        responses.append(BrokenBody())
        return responses[-1]

    scanner = SecretScanner()
    scanner._session = SimpleNamespace(get=get)
    assert scanner.scan_domain(["example.com"]) == []
    # One request per path: the host answered, so there is no HTTP fallback.
    assert len(urls) == len(COMMON_PATHS) and all(u.startswith("https://") for u in urls)
    assert all(r.closed for r in responses)


def test_retry_after_header_is_not_honored():
    for retries in (1, 2):
        retry = make_session(retries=retries).get_adapter("https://a.example").max_retries
        assert retry.respect_retry_after_header is False


def test_entities_in_the_served_page_still_match_the_fingerprint():
    detector = TakeoverDetector(FingerprintDatabase(FIXTURE))
    detector._fetch = lambda hostname: (
        200, "<p>Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.</p>"
    )
    result = ResolutionResult(
        "a.example.com", S.CNAME, a_records=["1.2.3.4"], cname_chain=["x.worksites.net"], cname_target="x.worksites.net"
    )
    assert detector.check(result).verdict is V.VULNERABLE


def test_zone_transfer_ns_lookup_failure_is_recorded():
    auditor = DNSAuditor()

    def resolve(name, rdtype):
        raise dns.exception.Timeout()

    auditor.resolver = SimpleNamespace(resolve=resolve)
    assert auditor.check_zone_transfer("example.com") == []
    assert any("NS lookup" in error for error in auditor.errors)


def test_zone_transfer_nameserver_address_failure_is_recorded():
    auditor = DNSAuditor()

    def resolve(name, rdtype):
        if rdtype == "NS":
            return [SimpleNamespace(target="ns1.example.com.")]
        raise dns.exception.Timeout()

    auditor.resolver = SimpleNamespace(resolve=resolve)
    assert auditor.check_zone_transfer("example.com") == []
    assert any("ns1.example.com" in error for error in auditor.errors)


def test_domain_without_ns_records_is_not_an_error():
    auditor = DNSAuditor()

    def resolve(name, rdtype):
        raise dns.resolver.NoAnswer()

    auditor.resolver = SimpleNamespace(resolve=resolve)
    assert auditor.check_zone_transfer("sub.example.com") == [] and auditor.errors == []
