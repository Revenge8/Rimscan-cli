"""Tests against the fingerprint file that actually ships, not the test fixture."""

import ipaddress

import pytest

from rimscan_cli.recon.takeover import FingerprintDatabase

# Takeover-prone services that cannot be matched by a CNAME suffix (nameserver delegation,
# a bare IP, or no public CNAME target). Anything else without a suffix is a bug.
NOT_CNAME_MATCHABLE = {"Digital Ocean", "Getresponse", "Smugsmug", "SmartJobBoard"}


@pytest.fixture(scope="module")
def db():
    return FingerprintDatabase()


@pytest.mark.parametrize("host,service", [
    ("x.pantheonsite.io", "Pantheon"),
    ("docs.readthedocs.io", "Readthedocs"),
    ("x.canny.io", "Canny"),
    ("stats.pingdom.com", "Pingdom"),
    ("a.short.io", "Short.io"),
    ("x.createsend.com", "Campaign Monitor"),
    ("x.cargocollective.com", "Cargo Collective"),
    ("x.ghost.io", "Ghost"),
    ("x.azurewebsites.net", "Microsoft Azure"),
    ("bucket.s3.amazonaws.com", "AWS/S3"),
])
def test_known_services_match(db, host, service):
    assert db.match(host).service == service


def test_every_vulnerable_service_is_matchable_or_documented(db):
    unmatchable = {fp.service for fp in db.fingerprints if fp.vulnerable and not fp.cnames}
    assert unmatchable == NOT_CNAME_MATCHABLE


def test_no_cname_suffix_is_a_url_or_an_ip(db):
    for fp in db.fingerprints:
        for suffix in fp.cnames:
            assert "/" not in suffix and ":" not in suffix
            with pytest.raises(ValueError):
                ipaddress.ip_address(suffix)
