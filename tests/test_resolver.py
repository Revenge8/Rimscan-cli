from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest

from rimscan_cli.recon.resolver import DNSResolver, ResolutionStatus as S


class FakeDNS:
    """Scripted answers keyed by (name, rdtype); anything unlisted is NXDOMAIN."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, name, rdtype):
        self.calls.append((name, rdtype))
        entry = self.table.get((name, rdtype), "nxdomain")
        if entry == "nodata":
            raise dns.resolver.NoAnswer()
        if entry == "nxdomain":
            raise dns.resolver.NXDOMAIN()
        if entry == "timeout":
            raise dns.exception.Timeout()
        if rdtype == "CNAME":
            return [SimpleNamespace(target=entry)]
        return [entry] if isinstance(entry, str) else entry


def make(table):
    resolver = DNSResolver()
    fake = FakeDNS(table)
    resolver._resolver = SimpleNamespace(resolve=fake)
    return resolver, fake


def test_plain_a_record():
    r, _ = make({("a.example.com", "CNAME"): "nodata", ("a.example.com", "A"): "1.2.3.4"})
    res = r.resolve_one("a.example.com")
    assert res.status is S.A_RECORD and res.a_records == ["1.2.3.4"] and res.is_live


def test_cname_chain_and_dangling():
    r, _ = make({
        ("x.example.com", "CNAME"): "mid.example.net.",
        ("mid.example.net", "CNAME"): "gone.example.org.",
    })
    res = r.resolve_one("x.example.com")
    assert res.status is S.DANGLING_CNAME
    assert res.cname_chain == ["mid.example.net", "gone.example.org"]


def test_nxdomain_without_chain():
    r, _ = make({})
    assert r.resolve_one("none.example.com").status is S.NXDOMAIN


def test_cname_loop_is_error():
    r, _ = make({("a.example.com", "CNAME"): "b.example.com.", ("b.example.com", "CNAME"): "a.example.com."})
    res = r.resolve_one("a.example.com")
    assert res.status is S.ERROR and "loop" in res.error_detail


def test_chain_limit():
    table = {(f"h{i}.example.com", "CNAME"): f"h{i + 1}.example.com." for i in range(20)}
    r, _ = make(table)
    assert r.resolve_one("h0.example.com", max_chain_depth=3).status is S.ERROR


def test_ipv6_only_host_resolves_via_aaaa():
    r, _ = make({
        ("v6.example.com", "CNAME"): "nodata",
        ("v6.example.com", "A"): "nodata",
        ("v6.example.com", "AAAA"): "2001:db8::1",
    })
    res = r.resolve_one("v6.example.com")
    assert res.status is S.A_RECORD and res.a_records == ["2001:db8::1"]


def test_timeout_is_retried_once_and_not_cached():
    r, fake = make({("t.example.com", "CNAME"): "timeout"})
    assert r.resolve_one("t.example.com").status is S.TIMEOUT
    assert fake.calls.count(("t.example.com", "CNAME")) == 2
    fake.table[("t.example.com", "CNAME")] = "nodata"
    fake.table[("t.example.com", "A")] = "9.9.9.9"
    assert r.resolve_one("t.example.com").status is S.A_RECORD


def test_wildcard_with_rotating_ips_is_detected_and_filtered():
    counter = iter(range(1, 100))

    def resolve(name, rdtype):
        if name.endswith(".example.com") and not name.startswith("real."):
            if rdtype == "CNAME":
                raise dns.resolver.NoAnswer()
            return [f"10.0.0.{next(counter) % 3 + 1}"]
        if name == "real.example.com":
            if rdtype == "CNAME":
                raise dns.resolver.NoAnswer()
            return ["192.0.2.7"]
        raise dns.resolver.NXDOMAIN()

    r = DNSResolver()
    r._resolver = SimpleNamespace(resolve=resolve)
    assert r.detect_wildcard("example.com") is True
    assert r.resolve_one("junk.example.com").status is S.WILDCARD
    assert r.resolve_one("real.example.com").status is S.A_RECORD


def test_no_wildcard_when_probes_do_not_resolve():
    r, _ = make({})
    assert r.detect_wildcard("example.com") is False


def test_resolve_many_keeps_input_order_and_dedupes():
    table = {(f"{n}.example.com", t): v for n in "abc" for t, v in (("CNAME", "nodata"), ("A", "1.1.1.1"))}
    r, _ = make(table)
    out = r.resolve_many(["c.example.com", "a.example.com", "b.example.com", "a.example.com"])
    assert [x.hostname for x in out] == ["c.example.com", "a.example.com", "b.example.com"]


@pytest.mark.parametrize("hosts", [[], ()])
def test_resolve_many_empty(hosts):
    assert DNSResolver().resolve_many(hosts) == []
