from types import SimpleNamespace

import dns.exception
import dns.rcode
import dns.resolver
import pytest

from rimscan_cli.recon import dns_audit
from rimscan_cli.recon.dns_audit import AuditSeverity as Sev, DNSAuditor


def txt(*strings):
    return SimpleNamespace(strings=[s.encode() for s in strings])


def auditor(table):
    a = DNSAuditor()

    def resolve(name, rdtype):
        value = table.get((name, rdtype), "nxdomain")
        if value == "nxdomain":
            raise dns.resolver.NXDOMAIN()
        if value == "nodata":
            raise dns.resolver.NoAnswer()
        if value == "timeout":
            raise dns.exception.Timeout()
        return value

    a.resolver = SimpleNamespace(resolve=resolve)
    return a


@pytest.mark.parametrize("spf,severity", [
    ("v=spf1 include:_spf.google.com -all", None),
    ("v=spf1 include:_spf.google.com ~all", Sev.MEDIUM),
    ("v=spf1 ?all", Sev.HIGH),
    ("v=spf1 +all", Sev.HIGH),
    ("v=spf1 all", Sev.HIGH),
    ("v=spf1 include:x.example", Sev.MEDIUM),
    ("v=spf1 redirect=_spf.example.net", None),
    ("v=spf1 include:x.example redirect=_spf.example.net", None),
    ("v=spf1 redirect=_spf.example.net ~all", Sev.MEDIUM),
])
def test_spf_policies(spf, severity):
    found = auditor({("example.com", "TXT"): [txt(spf)]}).check_spf("example.com")
    assert [f.severity for f in found] == ([severity] if severity else [])


def test_spf_prefix_lookalike_is_not_an_spf_record():
    found = auditor({("example.com", "TXT"): [txt("v=spf10 -all")]}).check_spf("example.com")
    assert [f.detail for f in found] == ["No SPF record found"]


def test_spf_split_across_txt_strings():
    found = auditor({("example.com", "TXT"): [txt("v=spf1 include:a.example ", "-all")]}).check_spf("example.com")
    assert found == []


def test_missing_spf_reported_even_when_domain_has_no_txt_at_all():
    assert [f.detail for f in auditor({("example.com", "TXT"): "nodata"}).check_spf("example.com")] == ["No SPF record found"]


def test_multiple_spf_records_flagged():
    table = {("example.com", "TXT"): [txt("v=spf1 -all"), txt("v=spf1 ~all")]}
    assert auditor(table).check_spf("example.com")[0].severity is Sev.HIGH


def test_timeouts_do_not_produce_findings_but_are_recorded():
    a = auditor({("example.com", "TXT"): "timeout", ("_dmarc.example.com", "TXT"): "timeout"})
    assert a.audit("example.com") == []
    assert len(a.errors) == 2


def test_clean_audit_has_no_errors():
    a = auditor({
        ("example.com", "TXT"): [txt("v=spf1 -all")],
        ("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject")],
    })
    assert a.audit("example.com") == [] and a.errors == []


@pytest.mark.parametrize("record,severity", [
    ("v=DMARC1; p=reject", None),
    ("v=DMARC1; p=quarantine; pct=100", Sev.MEDIUM),
    ("v=DMARC1; p=none; rua=mailto:a@example.com", Sev.HIGH),
])
def test_dmarc_policies(record, severity):
    found = auditor({("_dmarc.example.com", "TXT"): [txt(record)]}).check_dmarc("example.com")
    assert [f.severity for f in found] == ([severity] if severity else [])


def test_missing_dmarc():
    assert auditor({}).check_dmarc("example.com")[0].detail == "No DMARC record found"


def test_subdomain_inherits_parent_dmarc():
    a = auditor({("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject")]})
    assert a.check_dmarc("sub.example.com") == []


def test_subdomain_policy_tag_overrides_p():
    a = auditor({("_dmarc.example.com", "TXT"): [txt("v=DMARC1; p=reject; sp=none")]})
    (finding,) = a.check_dmarc("sub.example.com")
    assert finding.severity is Sev.HIGH and "inherited from example.com" in finding.detail


def test_subdomain_without_any_dmarc_is_reported():
    assert auditor({}).check_dmarc("sub.example.com")[0].detail == "No DMARC record found"


def test_dmarc_lookup_failure_on_subdomain_is_not_a_finding():
    a = auditor({("_dmarc.sub.example.com", "TXT"): "timeout"})
    assert a.check_dmarc("sub.example.com") == [] and a.errors


def test_zone_transfer_reads_only_first_message(monkeypatch):
    a = auditor({
        ("example.com", "NS"): [SimpleNamespace(target="ns1.example.com.")],
        ("ns1.example.com", "A"): ["192.0.2.1"],
    })
    consumed = []

    def fake_xfr(address, domain, lifetime):
        consumed.append("first")
        yield SimpleNamespace(rcode=lambda: dns.rcode.NOERROR, answer=[object()])
        consumed.append("second")
        yield SimpleNamespace(rcode=lambda: dns.rcode.NOERROR, answer=[object()])

    monkeypatch.setattr(dns_audit.dns.query, "xfr", fake_xfr)
    (finding,) = a.check_zone_transfer("example.com")
    assert finding.severity is Sev.CRITICAL and consumed == ["first"]


def test_zone_transfer_refused(monkeypatch):
    a = auditor({
        ("example.com", "NS"): [SimpleNamespace(target="ns1.example.com.")],
        ("ns1.example.com", "A"): ["192.0.2.1"],
    })

    def refused(*args, **kwargs):
        raise dns.exception.FormError()
        yield

    monkeypatch.setattr(dns_audit.dns.query, "xfr", refused)
    assert a.check_zone_transfer("example.com") == []


def test_custom_nameservers_are_used():
    assert DNSAuditor(nameservers=["9.9.9.9"]).resolver.nameservers == ["9.9.9.9"]
