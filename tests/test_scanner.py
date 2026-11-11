"""End-to-end tests of scan_domain with every network component replaced by a fake."""

from pathlib import Path

import pytest

from rimscan_cli import __version__, scanner
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus as S
from rimscan_cli.recon.takeover import FingerprintDatabase

FIXTURE = Path(__file__).with_name("fixtures_fingerprints.json")


def enumerator_class(status):
    class FakeEnumerator:
        def __init__(self, domain, timeout=10.0):
            self.source_status = {}

        def run(self, sources, on_source_done=None):
            for name in sources:
                self.source_status[name] = status
            return {"a.example.com", "c.example.com", "internal.example.com"} if status == "ok" else set()

        def from_bruteforce(self, resolver):
            return set()

    return FakeEnumerator


class FakeResolver:
    table = {
        "a.example.com": ResolutionResult("a.example.com", S.A_RECORD, a_records=["1.1.1.1"]),
        "c.example.com": ResolutionResult(
            "c.example.com", S.CNAME, a_records=["2.2.2.2"], cname_chain=["x.ghost.io"], cname_target="x.ghost.io"
        ),
        "example.com": ResolutionResult("example.com", S.A_RECORD, a_records=["1.1.1.1"]),
        "internal.example.com": ResolutionResult("internal.example.com", S.A_RECORD, a_records=["10.0.0.5"]),
    }

    def __init__(self, timeout=5.0, nameservers=None):
        self.nameservers = nameservers

    def detect_wildcard(self, domain):
        return False

    def resolve_many(self, hosts):
        return [self.table.get(h, ResolutionResult(h, S.NXDOMAIN)) for h in hosts]


class FakeDetector:
    def __init__(self, database, timeout=10.0):
        pass

    def check_many(self, results):
        return [None for _ in results]


class FakeAuditor:
    errors = []
    created = []

    def __init__(self, timeout=5.0, nameservers=None):
        self.created.append((timeout, nameservers))

    def audit(self, domain, include_zone_transfer=False):
        return []


class Recorder:
    calls = {}

    @classmethod
    def record(cls, name, hosts):
        cls.calls[name] = list(hosts)


class FakeCerts:
    def __init__(self, timeout=5.0):
        self.timeout = timeout

    def audit_many(self, hosts):
        Recorder.record("certs", hosts)
        return []


class FakeSecrets:
    def __init__(self, timeout=(5.0, 10.0)):
        Recorder.calls["secret_timeout"] = timeout

    def scan_domain(self, hosts):
        Recorder.record("secrets", hosts)
        return []


@pytest.fixture()
def fakes(monkeypatch):
    Recorder.calls = {}
    FakeAuditor.errors = []
    FakeAuditor.created = []
    monkeypatch.setattr(scanner, "SubdomainEnumerator", enumerator_class("ok"))
    monkeypatch.setattr(scanner, "DNSResolver", FakeResolver)
    monkeypatch.setattr(scanner, "FingerprintDatabase", lambda: FingerprintDatabase(FIXTURE))
    monkeypatch.setattr(scanner, "TakeoverDetector", FakeDetector)
    monkeypatch.setattr(scanner, "DNSAuditor", FakeAuditor)
    monkeypatch.setattr(scanner, "CertAuditor", FakeCerts)
    monkeypatch.setattr(scanner, "SecretScanner", FakeSecrets)
    monkeypatch.setattr(scanner, "run_nuclei", lambda hosts, **kw: Recorder.record("nuclei", hosts) or {"status": "completed", "findings": []})


def test_result_carries_schema_version_tool_and_timestamp(fakes):
    result = scanner.scan_domain("Example.COM")
    assert result["schema_version"] == scanner.SCHEMA_VERSION
    assert result["tool"] == {"name": "rimscan-cli", "version": __version__}
    assert result["scanned_at"].endswith("+00:00")
    assert result["domain"] == "example.com"
    assert result["incomplete"] is False and result["warnings"] == []
    assert "secret_findings" not in result and "active_targets" not in result


def test_non_public_hosts_are_never_probed(fakes):
    result = scanner.scan_domain("example.com", authorized=True, include_secrets=True, include_nuclei=True)
    assert "internal.example.com" not in Recorder.calls["certs"]
    assert "internal.example.com" not in Recorder.calls["secrets"]
    assert "internal.example.com" not in Recorder.calls["nuclei"]
    assert result["skipped_hosts"]["non_public"] == ["internal.example.com"]


def test_third_party_hosts_are_skipped_by_active_steps_by_default(fakes):
    result = scanner.scan_domain("example.com", authorized=True, include_secrets=True, include_nuclei=True)
    assert Recorder.calls["secrets"] == ["a.example.com", "example.com"]
    assert Recorder.calls["nuclei"] == ["a.example.com", "example.com"]
    assert result["active_targets"] == ["a.example.com", "example.com"]
    assert result["skipped_hosts"]["third_party"] == ["c.example.com"]
    # TLS handshakes are part of the default scan and still cover third-party hosts.
    assert Recorder.calls["certs"] == ["a.example.com", "c.example.com", "example.com"]


def test_include_third_party_opts_back_in(fakes):
    result = scanner.scan_domain(
        "example.com", authorized=True, include_secrets=True, include_third_party=True
    )
    assert Recorder.calls["secrets"] == ["a.example.com", "c.example.com", "example.com"]
    assert result["skipped_hosts"]["third_party"] == []


def test_timeout_and_resolver_reach_every_component(fakes):
    scanner.scan_domain("example.com", authorized=True, include_secrets=True, timeout=7.0, nameservers=["9.9.9.9"])
    assert FakeAuditor.created == [(5.0, ["9.9.9.9"])]
    assert Recorder.calls["secret_timeout"] == (5.0, 7.0)


def test_active_steps_are_not_run_unless_requested(fakes):
    scanner.scan_domain("example.com")
    assert set(Recorder.calls) == {"certs"}


def test_all_sources_failing_marks_the_scan_incomplete(fakes, monkeypatch):
    monkeypatch.setattr(scanner, "SubdomainEnumerator", enumerator_class("failed (HTTPError)"))
    result = scanner.scan_domain("example.com")
    assert result["incomplete"] is True
    assert any("every enumeration source" in w for w in result["warnings"])


def test_bruteforce_makes_a_failed_enumeration_still_usable(fakes, monkeypatch):
    monkeypatch.setattr(scanner, "SubdomainEnumerator", enumerator_class("timed out"))
    assert scanner.scan_domain("example.com", bruteforce=True)["incomplete"] is False


def test_partial_source_failure_warns_but_is_not_incomplete(fakes, monkeypatch):
    base = enumerator_class("ok")

    class Partial(base):
        def run(self, sources, on_source_done=None):
            found = super().run(sources, on_source_done)
            self.source_status["crt.sh"] = "timed out"
            return found

    monkeypatch.setattr(scanner, "SubdomainEnumerator", Partial)
    result = scanner.scan_domain("example.com")
    assert result["incomplete"] is False
    assert result["warnings"] == ["enumeration sources failed or timed out: crt.sh"]


def test_dns_audit_failures_mark_the_scan_incomplete(fakes):
    FakeAuditor.errors = ["TXT lookup for example.com failed"]
    result = scanner.scan_domain("example.com")
    assert result["incomplete"] is True
    assert "DNS audit incomplete" in result["warnings"][0]


def test_wildcard_filtered_hosts_are_counted(fakes, monkeypatch):
    monkeypatch.setitem(
        FakeResolver.table, "a.example.com", ResolutionResult("a.example.com", S.WILDCARD, a_records=["1.1.1.1"])
    )
    assert scanner.scan_domain("example.com")["wildcard_filtered"] == 1


def test_validation_happens_before_any_network_activity(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network component constructed")

    monkeypatch.setattr(scanner, "SubdomainEnumerator", boom)
    with pytest.raises(scanner.AuthorizationError):
        scanner.scan_domain("example.com", include_secrets=True)
    with pytest.raises(scanner.InvalidArguments):
        scanner.scan_domain("https://example.com")
    with pytest.raises(scanner.InvalidArguments):
        scanner.scan_domain("example.com", sources=["nope"])
    with pytest.raises(scanner.InvalidArguments):
        scanner.scan_domain("example.com", nameservers=["not-an-ip"])


def test_authorization_error_is_not_a_builtin_permission_error():
    assert not issubclass(scanner.AuthorizationError, PermissionError)
    assert issubclass(scanner.AuthorizationError, scanner.InvalidArguments)
