"""Regression tests for hardening fixes: one test group per reported problem."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from rimscan_cli import cli, scanner
from rimscan_cli.recon import cert_audit, dns_audit
from rimscan_cli.recon.cert_audit import CertAuditor
from rimscan_cli.recon.dns_audit import DNSAuditor
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus as S
from rimscan_cli.recon.secret_scan import SecretScanner
from rimscan_cli.recon.takeover import FingerprintDatabase
from tests.test_scanner import FakeResolver, Recorder, fakes  # noqa: F401  (fixture)

FIXTURE = Path(__file__).with_name("fixtures_fingerprints.json")
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# 1. Third-party detection for platforms whose fingerprint entry has no CNAME suffix.

@pytest.mark.parametrize("host", [
    "user.github.io", "app.herokuapp.com", "site.netlify.app", "shop.myshopify.com", "x.ghost.io", "x.elasticbeanstalk.com",
])
def test_known_hosting_platforms_are_third_party_without_a_fingerprint_cname(host):
    # The fixture has no entry for Heroku, Netlify or Shopify; the built-in list covers them.
    assert FingerprintDatabase(FIXTURE).is_third_party(host)


@pytest.mark.parametrize("host", ["www.example.com", "lb.unknown.net", "notgithub.io", "github.io.example.com"])
def test_own_and_unknown_hosts_are_not_third_party(host):
    assert not FingerprintDatabase(FIXTURE).is_third_party(host)


@pytest.mark.parametrize("host", ["user.github.io", "app.herokuapp.com", "site.netlify.app", "shop.myshopify.com"])
def test_shipped_fingerprints_treat_empty_cname_platforms_as_third_party(host):
    assert FingerprintDatabase().is_third_party(host)


def test_platforms_without_a_fingerprint_cname_are_skipped_by_active_steps(fakes, monkeypatch):  # noqa: F811
    chain = ["x.herokuapp.com"]
    monkeypatch.setitem(
        FakeResolver.table, "c.example.com",
        ResolutionResult("c.example.com", S.CNAME, a_records=["2.2.2.2"], cname_chain=chain, cname_target=chain[-1]),
    )
    result = scanner.scan_domain("example.com", authorized=True, include_secrets=True)
    assert result["skipped_hosts"]["third_party"] == ["c.example.com"]
    assert "c.example.com" not in Recorder.calls["secrets"]


# 2. DNS resolution failures must not look like a clean scan.

def _fail_hosts(monkeypatch, names):
    for name in names:
        monkeypatch.setitem(FakeResolver.table, name, ResolutionResult(name, S.TIMEOUT))


def test_a_few_resolution_failures_warn_but_do_not_mark_the_scan_incomplete(fakes, monkeypatch):  # noqa: F811
    _fail_hosts(monkeypatch, ["a.example.com"])
    result = scanner.scan_domain("example.com")
    assert result["incomplete"] is False
    assert result["warnings"] == ["DNS resolution failed (timeout or error) for 1 of 4 hosts"]


def test_mostly_failed_resolution_marks_the_scan_incomplete(fakes, monkeypatch):  # noqa: F811
    _fail_hosts(monkeypatch, ["a.example.com", "c.example.com", "internal.example.com"])
    result = scanner.scan_domain("example.com")
    assert result["incomplete"] is True
    assert any("3 of 4 hosts" in w for w in result["warnings"])


# 3. Host caps are reported in the JSON, and --quiet silences stderr completely.

def test_host_caps_are_reported_in_the_json_warnings(fakes, monkeypatch):  # noqa: F811
    monkeypatch.setattr(scanner, "MAX_CERT_HOSTS", 2)
    monkeypatch.setattr(scanner, "MAX_SECRET_HOSTS", 1)
    result = scanner.scan_domain("example.com", authorized=True, include_secrets=True)
    assert "TLS audit limited to 2 of 3 live hosts; the rest were not checked" in result["warnings"]
    assert "secret scan limited to 1 of 2 hosts; the rest were not checked" in result["warnings"]


def test_quiet_also_silences_log_warnings(monkeypatch, capsys):
    root = logging.getLogger()
    monkeypatch.setattr(root, "level", root.level)  # main() changes the root level; restore it afterwards

    def noisy(domain, **kw):
        logging.getLogger("rimscan_cli.recon.cert_audit").warning("Certificate audit limited to 100 of 120 hosts")
        return {"domain": domain}

    monkeypatch.setattr(cli, "scan_domain", noisy)
    cli.main(["scan", "example.com", "-q"])
    assert capsys.readouterr().err == ""
    cli.main(["scan", "example.com", "--no-banner"])
    assert "limited to 100 of 120" in capsys.readouterr().err


# 4. Redirect responses are not file content.

def test_redirect_bodies_are_not_scanned_as_files():
    class Redirect:
        status_code = 301
        headers = {"Content-Type": "text/plain"}
        encoding = "utf-8"

        def iter_content(self, chunk_size=0):
            yield f"k={AWS_KEY}".encode()

        def close(self):
            pass

    scanner_ = SecretScanner()
    scanner_._session = SimpleNamespace(get=lambda url, **kw: Redirect())
    assert scanner_.scan_domain(["example.com"]) == []


# 5. Zone transfers are never sent to non-public nameserver addresses.

@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "169.254.169.254"])
def test_zone_transfer_is_never_attempted_against_non_public_nameservers(monkeypatch, address):
    auditor = DNSAuditor()
    answers = {
        ("example.com", "NS"): [SimpleNamespace(target="ns1.example.com.")],
        ("ns1.example.com", "A"): [address],
    }
    auditor.resolver = SimpleNamespace(resolve=lambda name, rdtype: answers[(name, rdtype)])
    called = []
    monkeypatch.setattr(dns_audit.dns.query, "xfr", lambda *args, **kwargs: called.append(args) or iter(()))
    assert auditor.check_zone_transfer("example.com") == [] and called == []


# 6. Certificate audit robustness.

@pytest.mark.parametrize("value", ["not a date", "Foo 99 99:99:99 1999 GMT", "99999999999999999999"])
def test_malformed_not_after_does_not_crash(value):
    auditor = CertAuditor()
    auditor._handshake = lambda hostname, port: {"notAfter": value}
    assert auditor.audit_host("example.com") == []


def test_ca_bundle_is_loaded_once_and_shared():
    assert cert_audit._context() is cert_audit._context()


# 7. Non-positive numeric options are usage errors.

@pytest.mark.parametrize("extra", [
    ["--timeout", "0"], ["--timeout", "-1"], ["--timeout", "nan"], ["--timeout", "inf"],
    ["--nuclei-rate-limit", "0"], ["--nuclei-rate-limit", "-5"], ["--nuclei-rate-limit", "1.5"],
])
def test_non_positive_numeric_options_are_usage_errors(extra):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["scan", "example.com", "-q", *extra])
    assert exit_info.value.code == 2
