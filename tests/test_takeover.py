from pathlib import Path

import pytest

from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus as S
from rimscan_cli.recon.takeover import FingerprintDatabase, TakeoverDetector, TakeoverVerdict as V

FIXTURE = Path(__file__).with_name("fixtures_fingerprints.json")


@pytest.fixture()
def detector():
    return TakeoverDetector(FingerprintDatabase(FIXTURE))


def cname(host, chain, status=S.CNAME):
    return ResolutionResult(host, status, a_records=["1.2.3.4"] if status is S.CNAME else [],
                            cname_chain=chain, cname_target=chain[-1])


def serve(detector, status, body):
    calls = []

    def fetch(hostname):
        calls.append(hostname)
        return status, body

    detector._fetch = fetch
    return calls


def test_database_ignores_urls_and_ip_cnames():
    db = FingerprintDatabase(FIXTURE)
    assert db.match("52.16.160.97") is None
    assert db.match("x.vercel.com") is None
    assert db.match("foo.ghost.io").service == "Ghost"


def test_nxdomain_service_that_still_resolves_is_not_flagged(detector):
    finding = detector.check(cname("a.example.com", ["x.elasticbeanstalk.com"]))
    assert finding.verdict is V.NOT_VULNERABLE


def test_nxdomain_service_dangling_is_vulnerable(detector):
    finding = detector.check(cname("a.example.com", ["x.elasticbeanstalk.com"], S.DANGLING_CNAME))
    assert finding.verdict is V.VULNERABLE


def test_pipe_alternation_fingerprint(detector):
    serve(detector, 200, "<h1>Failed to resolve DNS path for this host</h1>")
    assert detector.check(cname("a.example.com", ["x.ghost.io"])).verdict is V.VULNERABLE


def test_markdown_split_fingerprint_matches_either_phrase(detector):
    serve(detector, 404, "There is no such company. Did you enter the right URL?")
    assert detector.check(cname("a.example.com", ["x.canny.io"])).verdict is V.VULNERABLE


def test_regex_fingerprint(detector):
    serve(detector, 404, "Tunnel abc123.ngrok.io not found")
    assert detector.check(cname("a.example.com", ["abc123.ngrok.io"])).verdict is V.VULNERABLE


def test_html_entity_fingerprint(detector):
    serve(detector, 200, "Hello! Sorry, but the website you’re looking for doesn’t exist.")
    assert detector.check(cname("a.example.com", ["x.worksites.net"])).verdict is V.VULNERABLE


def test_status_only_fingerprint_is_likely_not_vulnerable(detector):
    serve(detector, 301, "")
    assert detector.check(cname("a.example.com", ["x.helprace.com"])).verdict is V.LIKELY
    serve(detector, 200, "")
    assert detector.check(cname("a.example.com", ["x.helprace.com"])).verdict is V.NOT_VULNERABLE


def test_unreachable_host(detector):
    detector._fetch = lambda hostname: None
    assert detector.check(cname("a.example.com", ["x.ghost.io"])).verdict is V.UNKNOWN_SERVICE


def test_plain_a_records_are_never_probed(detector):
    calls = serve(detector, 200, "Repository not found")
    res = ResolutionResult("a.example.com", S.A_RECORD, a_records=["1.2.3.4"])
    assert detector.check(res) is None and calls == []


def test_unknown_cname_target_is_ignored_unless_dangling(detector):
    calls = serve(detector, 200, "")
    assert detector.check(cname("a.example.com", ["lb.unknown.net"])) is None
    assert calls == []
    assert detector.check(cname("a.example.com", ["lb.unknown.net"], S.DANGLING_CNAME)).verdict is V.LIKELY


def test_non_vulnerable_service_does_not_make_requests(detector):
    calls = serve(detector, 200, "There isn't a GitHub Pages site here.")
    assert detector.check(cname("a.example.com", ["user.github.io"])).verdict is V.NOT_VULNERABLE
    assert calls == []


def test_wildcard_results_skipped(detector):
    res = ResolutionResult("a.example.com", S.WILDCARD, a_records=["1.1.1.1"], cname_chain=["x.ghost.io"])
    assert detector.check(res) is None
