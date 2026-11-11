import logging
from types import SimpleNamespace

import requests

from rimscan_cli.recon.secret_scan import SecretFinding, SecretScanner

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GH_TOKEN = "ghp_" + "A" * 36


class Resp:
    def __init__(self, text="", status=200, ctype="text/plain"):
        self.status_code = status
        self.headers = {"Content-Type": ctype}
        self.encoding = "utf-8"
        self._text = text

    def iter_content(self, chunk_size=0):
        yield self._text.encode()

    def close(self):
        pass


def scanner_with(handler):
    s = SecretScanner()
    s._session = SimpleNamespace(get=handler)
    return s


def test_detects_access_key_and_redacts_everywhere():
    (finding,) = SecretScanner().scan_text(f"aws_key = '{AWS_KEY}'", "src")
    assert finding.secret_type == "aws_access_key"
    dumped = str(finding.to_dict()) + repr(finding) + finding.context
    assert AWS_KEY not in dumped
    assert finding.redacted_match() == "AKIA...MPLE"


def test_aws_secret_needs_context_and_entropy():
    s = SecretScanner()
    assert [f.secret_type for f in s.scan_text(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}")] == ["aws_secret_key"]
    assert s.scan_text(f"build_id={AWS_SECRET}") == []
    assert s.scan_text("aws " + "a" * 40) == []


def test_aws_secret_context_must_be_near_the_match():
    assert SecretScanner().scan_text(f"aws {'-' * 200} {AWS_SECRET}") == []


def test_jwt_and_private_key_detected():
    text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig\n-----BEGIN RSA PRIVATE KEY-----"
    assert {f.secret_type for f in SecretScanner().scan_text(text)} == {"jwt", "private_key"}


def test_to_dict_never_contains_raw_context():
    f = SecretFinding("aws_access_key", "u", 1, match=AWS_KEY, context=f"key={AWS_KEY}")
    assert AWS_KEY not in str(f.to_dict())


def test_context_is_taken_around_the_match_on_a_minified_line():
    line = "x" * 500 + f"key='{AWS_KEY}'" + "y" * 500
    (finding,) = SecretScanner().scan_text(line)
    assert "AKIA...MPLE" in finding.context
    assert AWS_KEY not in finding.context
    assert len(finding.context) < 130


def test_other_credentials_near_the_match_are_redacted_whole():
    line = f"a={AWS_KEY} tok={GH_TOKEN}"
    findings = SecretScanner().scan_text(line)
    assert {f.secret_type for f in findings} == {"aws_access_key", "github_token"}
    for finding in findings:
        assert AWS_KEY not in finding.context and "A" * 10 not in finding.context


def test_context_window_never_cuts_through_another_credential():
    # The 40-character window before the AWS key starts inside the token, so it must grow.
    line = "z" * 34 + " " + GH_TOKEN + " " + AWS_KEY
    findings = {f.secret_type: f for f in SecretScanner().scan_text(line)}
    context = findings["aws_access_key"].context
    assert "ghp_...AAAA" in context
    assert "A" * 10 not in context


def test_http_error_does_not_fall_back_to_http():
    urls = []

    def get(url, **kw):
        urls.append(url)
        return Resp(status=404)

    scanner_with(get).scan_domain(["example.com"])
    assert all(u.startswith("https://") for u in urls)
    assert len(urls) == 9


def test_falls_back_to_http_when_https_request_fails():
    def get(url, **kw):
        if url.startswith("https://"):
            raise requests.ConnectionError()
        return Resp(f"k={AWS_KEY}" if url.endswith("/.env") else "", status=200)

    findings = scanner_with(get).scan_domain(["example.com"])
    assert [f.source for f in findings] == ["http://example.com/.env"]


def test_redirects_are_not_followed():
    seen = []

    def get(url, **kw):
        seen.append(kw)
        return Resp(status=404)

    scanner_with(get).scan_domain(["example.com"])
    assert seen and all(kw["allow_redirects"] is False for kw in seen)


def test_soft_404_html_for_env_files_is_ignored():
    def get(url, **kw):
        return Resp(f"<html>{AWS_KEY}</html>", ctype="text/html; charset=utf-8")

    findings = scanner_with(get).scan_domain(["example.com"])
    assert {f.source.rsplit("/", 1)[-1] for f in findings}.isdisjoint({".env", ".env.local", ".env.production"})


def test_identical_bodies_are_reported_once_per_host():
    handler = lambda url, **kw: Resp(f"var k='{AWS_KEY}'", ctype="application/javascript")  # noqa: E731
    findings = scanner_with(handler).scan_domain(["a.example.com", "b.example.com"])
    assert sorted({f.source.split("/")[2] for f in findings}) == ["a.example.com", "b.example.com"]
    assert len(findings) == 2


def test_host_cap_is_logged(caplog):
    caplog.set_level(logging.WARNING)
    hosts = [f"h{i}.example.com" for i in range(51)]
    scanner_with(lambda url, **kw: Resp(status=404)).scan_domain(hosts)
    assert "limited to 50 of 51" in caplog.text
