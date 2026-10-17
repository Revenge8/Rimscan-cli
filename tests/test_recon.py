from unittest.mock import MagicMock, patch

from recon.dns_audit import AuditSeverity, DNSAuditor
from recon.enumeration import SubdomainEnumerator
from recon.resolver import DNSResolver, ResolutionResult, ResolutionStatus


class StreamingResponse:
    def __init__(self, chunks, headers=None):
        self.chunks = iter(chunks)
        self.headers = headers or {}
        self.closed = False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        yield from self.chunks

    def close(self):
        self.closed = True


def test_wildcard_detection_uses_majority_matching_ips():
    resolver = DNSResolver()
    probes = iter(
        [
            ResolutionResult("one.example.com", ResolutionStatus.A_RECORD, a_records=["192.0.2.1"]),
            ResolutionResult("two.example.com", ResolutionStatus.A_RECORD, a_records=["192.0.2.1"]),
            ResolutionResult("three.example.com", ResolutionStatus.A_RECORD, a_records=["192.0.2.2"]),
        ]
    )

    with patch.object(resolver, "_resolve_uncached", side_effect=lambda _: next(probes)):
        assert resolver.detect_wildcard("example.com")

    assert resolver._is_wildcard_match("random.example.com", ["192.0.2.1"])


def test_bruteforce_includes_dangling_cname_candidates():
    result = ResolutionResult(
        "orphan.example.com",
        ResolutionStatus.DANGLING_CNAME,
        cname_chain=["missing.provider.example"],
    )
    enumerator = SubdomainEnumerator("example.com")

    with patch("recon.enumeration.DNSResolver.resolve_many", return_value=[result]):
        assert enumerator.from_bruteforce(["orphan"]) == {"orphan.example.com"}


def test_dmarc_without_a_dmarc_txt_record_is_reported():
    auditor = DNSAuditor()
    auditor.resolver = MagicMock()
    auditor.resolver.resolve.return_value = ['"v=spf1 -all"']

    findings = auditor.check_dmarc("example.com")

    assert len(findings) == 1
    assert findings[0].severity is AuditSeverity.HIGH
    assert findings[0].detail == "No DMARC record found"


def test_wayback_reads_json_from_bounded_stream():
    response = StreamingResponse(
        [b'[["original"],["https://www.example.com/path"]]', b""]
    )
    enumerator = SubdomainEnumerator("example.com")

    with patch.object(enumerator, "_wayback_get", return_value=response):
        assert enumerator.from_wayback() == {"www.example.com"}

    assert response.closed


def test_wayback_stops_reading_when_response_exceeds_limit():
    response = StreamingResponse([b"1234", b"5678"])
    enumerator = SubdomainEnumerator("example.com")
    enumerator._WAYBACK_MAX_BYTES = 3

    with patch.object(enumerator, "_wayback_get", return_value=response):
        assert enumerator.from_wayback() == set()

    assert enumerator.source_status["wayback"] == "response too large, skipped"
    assert response.closed
