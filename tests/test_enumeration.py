import json
import threading
from types import SimpleNamespace

import pytest
import requests

from rimscan_cli.recon.enumeration import SubdomainEnumerator
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus


class FakeResponse:
    def __init__(self, payload=None, text="", status=200):
        self._payload, self.text, self.status_code = payload, text, status
        self.encoding = "utf-8"

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self._payload

    def iter_content(self, chunk_size=0):
        yield json.dumps(self._payload).encode()

    def close(self):
        pass


def enumerator(handler):
    e = SubdomainEnumerator("example.com")
    e.session = SimpleNamespace(get=handler)
    return e


def test_crtsh_strips_wildcards_and_rejects_foreign_names():
    data = [{"name_value": "*.a.example.com\nb.example.com\nevil-example.com\nx.other.org\nexample.com"}]
    e = enumerator(lambda url, **kw: FakeResponse(data))
    assert e.from_crtsh() == {"a.example.com", "b.example.com"}


def test_invalid_labels_are_rejected():
    e = SubdomainEnumerator("example.com")
    assert e._accept("-bad.example.com") is None
    assert e._accept("under_score.example.com") is None
    assert e._accept("a" * 64 + ".example.com") is None
    assert e._accept("Good.Example.COM.") == "good.example.com"


def test_certspotter_paginates_until_empty():
    pages = iter([[{"id": "1", "dns_names": ["a.example.com"]}], [{"id": "2", "dns_names": ["b.example.com"]}], []])
    seen = []

    def get(url, params=None, **kw):
        seen.append(params.get("after"))
        return FakeResponse(next(pages))

    assert enumerator(get).from_certspotter() == {"a.example.com", "b.example.com"}
    assert seen == [None, "1", "2"]


def test_wayback_uses_hostname_not_netloc():
    rows = [["original"], ["http://user@sub.example.com:8080/x"], ["other.example.com/path"], []]
    e = enumerator(lambda url, **kw: FakeResponse(rows))
    assert e.from_wayback() == {"sub.example.com", "other.example.com"}


def test_rapiddns_parses_links():
    html = '<a href="x" target="_blank">m.example.com</a><a target="_blank">zzz.other.com</a>'
    e = enumerator(lambda url, **kw: FakeResponse(text=html))
    assert e.from_rapiddns() == {"m.example.com"}


def test_run_isolates_failing_source_and_reports_status():
    e = SubdomainEnumerator("example.com")
    e._sources = {
        "good": lambda: {"a.example.com"},
        "bad": lambda: (_ for _ in ()).throw(requests.ConnectionError("boom")),
    }
    events = []
    found = e.run(["good", "bad"], on_source_done=lambda *a: events.append(a))
    assert found == {"a.example.com"}
    assert e.source_status["good"] == "ok"
    assert e.source_status["bad"] == "failed (ConnectionError)"
    assert len(events) == 2


def test_run_survives_a_malformed_response_from_a_source():
    e = enumerator(lambda url, **kw: FakeResponse({"error": "rate limited"}))
    e._sources = {"crt.sh": e.from_crtsh, "good": lambda: {"a.example.com"}}
    assert e.run(["crt.sh", "good"]) == {"a.example.com"}
    assert e.source_status["crt.sh"] == "failed (AttributeError)"


def test_run_times_out_slow_source_without_leaving_a_blocking_thread():
    import time

    release = threading.Event()
    e = SubdomainEnumerator("example.com")
    e._sources = {"slow": lambda: release.wait(5) or {"x.example.com"}, "fast": lambda: {"a.example.com"}}
    started = time.monotonic()
    found = e.run(["slow", "fast"], source_timeout=0.2)
    assert time.monotonic() - started < 2
    assert found == {"a.example.com"}
    assert e.source_status["slow"] == "timed out"
    stuck = [t for t in threading.enumerate() if t.name == "enum-slow"]
    assert stuck and all(t.daemon for t in stuck)
    release.set()


def test_unknown_source_rejected():
    with pytest.raises(ValueError, match="nope"):
        SubdomainEnumerator("example.com").run(["nope"])


def test_bruteforce_returns_only_live_hosts():
    class R:
        def resolve_many(self, names):
            return [
                ResolutionResult("www.example.com", ResolutionStatus.A_RECORD, a_records=["1.1.1.1"]),
                ResolutionResult("dev.example.com", ResolutionStatus.WILDCARD, a_records=["2.2.2.2"]),
                ResolutionResult("api.example.com", ResolutionStatus.NXDOMAIN),
            ]

    assert SubdomainEnumerator("example.com").from_bruteforce(R(), ["www", "dev", "api"]) == {"www.example.com"}
