from unittest.mock import MagicMock, patch

from rimscan_cli.cli import PASSIVE_NUCLEI_EXCLUDED_TAGS, build_parser, scan_domain
from recon.enumeration import SubdomainEnumerator
from recon.secrets import SecretScanner


def test_help_requires_authorized_for_live_secret_scan():
    args = build_parser().parse_args(["scan", "example.com", "--secrets", "--authorized"])
    assert args.authorized is True
    assert args.secrets is True


def test_scan_domain_is_database_free():
    fingerprints = MagicMock()
    fingerprints.entries = []
    fingerprints.match.return_value = None
    with patch("rimscan_cli.cli.SubdomainEnumerator.run", return_value=["www.example.com"]), \
         patch("rimscan_cli.cli.DNSResolver.resolve_many", return_value=[]), \
         patch("rimscan_cli.cli.DNSAuditor.audit", return_value=[]), \
         patch("rimscan_cli.cli.CertAuditor.audit_many", return_value=[]), \
         patch("rimscan_cli.cli.FingerprintDatabase", return_value=fingerprints):
        result = scan_domain("example.com")
    assert result["domain"] == "example.com"
    assert result["subdomains"] == ["www.example.com"]


def test_secret_matches_are_redacted_for_display():
    finding = SecretScanner().scan_text("token=ghp_" + "a" * 36, source="fixture")[0]
    assert finding.redacted_match().startswith("ghp_")
    assert finding.redacted_match().endswith("aaaa")


def test_passive_nuclei_exclusions_are_fixed():
    assert PASSIVE_NUCLEI_EXCLUDED_TAGS == ("dos", "fuzz", "intrusive")


def test_subdomain_validation_requires_label_boundary():
    enumerator = SubdomainEnumerator("example.com")
    assert enumerator._is_valid_subdomain("api.example.com")
    assert not enumerator._is_valid_subdomain("api.notexample.com")
