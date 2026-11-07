from types import SimpleNamespace

import requests

from rimscan_cli.recon.secrets import SecretFinding, SecretScanner

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


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
    dumped = str(finding.to_dict()) + repr(finding)
    assert AWS_KEY not in dumped
    assert finding.redacted_match() == "AKIA...MPLE"


def test_aws_secret_needs_context_and_entropy():
    s = SecretScanner()
    assert [f.secret_type for f in s.scan_text(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}")] == ["aws_secret_key"]
    assert s.scan_text(f"build_id={AWS_SECRET}") == []
    assert s.scan_text("aws " + "a" * 40) == []


def test_jwt_and_private_key_detected():
    text = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig\n-----BEGIN RSA PRIVATE KEY-----"
    assert {f.secret_type for f in SecretScanner().scan_text(text)} == {"jwt", "private_key"}


def test_to_dict_never_contains_raw_context():
    f = SecretFinding("aws_access_key", "u", 1, match=AWS_KEY, context=f"key={AWS_KEY}")
    assert AWS_KEY not in str(f.to_dict())


def test_http_error_does_not_fall_back_to_http():
    urls = []

    def get(url, **kw):
        urls.append(url)
        return Resp(status=404)

    scanner_with(get).scan_domain(["example.com"])
    assert all(u.startswith("https://") for u in urls)
    assert len(urls) == 9


def test_falls_back_to_http_only_on_connection_error():
    def get(url, **kw):
        if url.startswith("https://"):
            raise requests.ConnectionError()
        return Resp(f"k={AWS_KEY}" if url.endswith("/.env") else "", status=200)

    findings = scanner_with(get).scan_domain(["example.com"])
    assert [f.source for f in findings] == ["http://example.com/.env"]


def test_soft_404_html_for_env_files_is_ignored():
    def get(url, **kw):
        return Resp(f"<html>{AWS_KEY}</html>", ctype="text/html; charset=utf-8")

    findings = scanner_with(get).scan_domain(["example.com"])
    assert {f.source.rsplit("/", 1)[-1] for f in findings}.isdisjoint({".env", ".env.local", ".env.production"})


def test_identical_bodies_are_reported_once():
    findings = scanner_with(lambda url, **kw: Resp(f"var k='{AWS_KEY}'", ctype="application/javascript")).scan_domain(
        ["a.example.com", "b.example.com"]
    )
    assert len(findings) == 1
