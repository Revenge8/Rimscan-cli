from unittest.mock import MagicMock, patch
import requests

from rimscan_cli.cli import PASSIVE_NUCLEI_EXCLUDED_TAGS, build_parser, main, scan_domain
from rimscan_cli.banner import ASCII_BANNER, BANNER, UNICODE_BANNER, render_banner
from recon.enumeration import SubdomainEnumerator
from recon.secrets import SecretScanner


def test_help_requires_authorized_for_live_secret_scan():
    args = build_parser().parse_args(["scan", "example.com", "--secrets", "--authorized"])
    assert args.authorized is True
    assert args.secrets is True


def test_banner_can_be_suppressed_with_both_flags():
    parser = build_parser()
    assert parser.parse_args(["scan", "example.com", "--quiet"]).quiet is True
    assert parser.parse_args(["scan", "example.com", "--no-banner"]).quiet is True
    assert BANNER == UNICODE_BANNER
    assert "RRRR" not in BANNER
    assert max(map(len, BANNER.splitlines())) <= 80


def test_banner_uses_ascii_fallback_for_non_unicode_stream():
    class AsciiStream:
        encoding = "ascii"

        def __init__(self):
            self.value = ""

        def write(self, value):
            self.value += value
            return len(value)

        def flush(self):
            return None

    stream = AsciiStream()
    render_banner(stream)
    assert ASCII_BANNER in stream.value
    assert "┌" not in stream.value


def test_banner_prints_by_default_and_output_suppresses_it(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("rimscan_cli.cli.scan_domain", lambda *args, **kwargs: {"domain": "example.com"})

    assert main(["scan", "example.com"]) == 0
    assert "rimscan-cli v1.0.0" in capsys.readouterr().err

    output_file = tmp_path / "results.json"
    assert main(["scan", "example.com", "--output", str(output_file)]) == 0
    assert capsys.readouterr().err == ""


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


def test_wayback_timeout_is_clean_and_does_not_stop_other_sources(capsys):
    enumerator = SubdomainEnumerator("example.com")
    with patch.object(enumerator, "_wayback_get", side_effect=requests.Timeout("slow")), \
         patch.object(enumerator, "from_crtsh", return_value={"www.example.com"}):
        results = enumerator.run(sources=["wayback", "crt.sh"])

    output = capsys.readouterr().out
    assert "wayback: 0 subdomains (timed out, skipped)" in output
    assert "crt.sh: 1 subdomains" in output
    assert "Retrying" not in output
    assert "www.example.com" in results


def test_wayback_and_otx_timeouts_are_clean_and_continue(capsys):
    enumerator = SubdomainEnumerator("example.com")
    with patch.object(enumerator, "_wayback_get", side_effect=requests.Timeout("wayback slow")), \
         patch.object(enumerator, "_otx_get", side_effect=requests.ConnectionError("otx unavailable")), \
         patch.object(enumerator, "from_crtsh", return_value={"api.example.com"}):
        results = enumerator.run(sources=["wayback", "otx", "crt.sh"])

    output = capsys.readouterr().out
    assert "wayback: 0 subdomains (timed out, skipped)" in output
    assert "otx: 0 subdomains (unavailable, skipped)" in output
    assert "crt.sh: 1 subdomains" in output
    assert "Retrying" not in output
    assert "api.example.com" in results
