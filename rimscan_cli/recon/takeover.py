"""Subdomain takeover detection using the can-i-take-over-xyz fingerprint database."""

from __future__ import annotations

import html
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Pattern, Sequence, Tuple, Union

import requests

from rimscan_cli.recon._common import all_public
from rimscan_cli.recon._http import make_session, read_capped
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus

__all__ = [
    "DEFAULT_FINGERPRINTS_PATH",
    "TakeoverVerdict",
    "TakeoverFinding",
    "Fingerprint",
    "FingerprintDatabase",
    "TakeoverDetector",
]

DEFAULT_FINGERPRINTS_PATH = Path(__file__).resolve().parents[1] / "data" / "fingerprints.json"
_MAX_BODY_BYTES = 256 * 1024

# The bundled upstream list leaves `cname` empty for many takeover-prone services, and
# matching is by CNAME suffix, so those services could never be detected. These suffixes
# are added to the upstream ones (matched by the entry's `service` name). Services that
# are not identified by a CNAME at all (Digital Ocean NS delegation, for one) stay out.
_SUPPLEMENTAL_CNAMES = {
    "Campaign Monitor": ("createsend.com",),
    "Canny": ("canny.io",),
    "Cargo Collective": ("cargocollective.com",),
    "Pantheon": ("pantheonsite.io",),
    "Pingdom": ("stats.pingdom.com",),
    "Readthedocs": ("readthedocs.io",),
    "Short.io": ("short.io",),
}

# Hosting platforms whose servers belong to someone else. Many of them have an empty
# `cname` list in the upstream fingerprints (GitHub Pages, Heroku, Netlify, Shopify, ...),
# so matching by fingerprint alone would miss them when deciding what is safe to probe.
_HOSTING_PLATFORMS = (
    "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io",
    "herokuapp.com", "herokudns.com", "herokussl.com",
    "netlify.app", "netlify.com", "netlifyglobalcdn.com",
    "myshopify.com", "shopify.com", "shopifycloud.com",
    "vercel.app", "vercel-dns.com", "pages.dev", "workers.dev", "fly.dev", "onrender.com",
    "surge.sh", "ghost.io", "wpengine.com", "wpenginepowered.com",
    "squarespace.com", "wixdns.net", "webflow.io", "tumblr.com", "wordpress.com",
    "cloudfront.net", "amazonaws.com", "elasticbeanstalk.com",
    "azurewebsites.net", "azureedge.net", "trafficmanager.net", "cloudapp.azure.com",
    "zendesk.com", "hubspot.net", "readthedocs.io", "unbouncepages.com",
)


class TakeoverVerdict(Enum):
    VULNERABLE = "vulnerable"
    LIKELY = "likely"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN_SERVICE = "unknown_service"


@dataclass
class TakeoverFinding:
    hostname: str
    verdict: TakeoverVerdict
    service: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    evidence: str = ""


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cnames: Tuple[str, ...]
    vulnerable: bool
    nxdomain: bool
    pattern: Optional[Pattern[str]]
    http_status: Optional[int]

    @classmethod
    def from_entry(cls, entry: dict) -> "Fingerprint":
        text = (entry.get("fingerprint") or "").strip()
        status = entry.get("http_status")
        if text.startswith("HTTP_STATUS="):
            status, text = int(text.split("=", 1)[1]), ""
        service = entry.get("service", "unknown")
        cnames = _usable_cnames(entry.get("cname") or []) + list(_SUPPLEMENTAL_CNAMES.get(service, ()))
        return cls(
            service=service,
            cnames=tuple(dict.fromkeys(cnames)),
            vulnerable=bool(entry.get("vulnerable")),
            nxdomain=bool(entry.get("nxdomain")),
            pattern=_compile_fingerprint(text),
            http_status=status,
        )


def _usable_cnames(values) -> List[str]:
    """Keep real domain suffixes; the upstream list also contains URLs and bare IPs."""
    usable = []
    for value in values:
        value = value.lower().strip().lstrip(".")
        if not value or "/" in value or ":" in value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            usable.append(value)
    return usable


def _compile_fingerprint(text: str) -> Optional[Pattern[str]]:
    """Turn an upstream fingerprint string into a case-insensitive pattern.

    Upstream mixes literal text with regex (`.*`), markdown-escaped pipes (`&#124;`),
    HTML entities, and two alternative phrases joined by "` `".
    """
    if not text or text == "NXDOMAIN":
        return None
    parts = []
    for alternative in text.split("` `"):
        alternative = html.unescape(alternative.replace("&#124;", "|")).strip()
        if not alternative:
            continue
        looks_like_regex = any(token in alternative for token in (".*", "\\", "|"))
        parts.append(alternative if looks_like_regex else re.escape(alternative))
    try:
        return re.compile("|".join(parts), re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(text), re.IGNORECASE)


class FingerprintDatabase:
    def __init__(self, path: Union[str, Path, None] = None):
        source = Path(path) if path else DEFAULT_FINGERPRINTS_PATH
        entries = json.loads(source.read_text(encoding="utf-8"))
        self.fingerprints = [Fingerprint.from_entry(entry) for entry in entries]
        self._suffixes: List[Tuple[str, Fingerprint]] = sorted(
            ((cname, fp) for fp in self.fingerprints for cname in fp.cnames),
            key=lambda pair: len(pair[0]),
            reverse=True,
        )

    def match(self, hostname: str) -> Optional[Fingerprint]:
        hostname = hostname.lower().rstrip(".")
        for suffix, fp in self._suffixes:
            if hostname == suffix or hostname.endswith("." + suffix):
                return fp
        return None

    def is_third_party(self, hostname: str) -> bool:
        """True if `hostname` belongs to a service that is not the scan target's own.

        Covers every fingerprint entry (vulnerable or not) and the built-in list of hosting
        platforms, including those whose upstream entry has no CNAME suffix.
        """
        name = hostname.lower().rstrip(".")
        if self.match(name) is not None:
            return True
        return any(name == suffix or name.endswith("." + suffix) for suffix in _HOSTING_PLATFORMS)


class TakeoverDetector:
    """Flag CNAMEs that point at third-party services with an unclaimed resource.

    Only hosts whose CNAME chain matches a known service are checked. Each such host
    receives at most one HTTPS and one HTTP GET request: the session does not retry and
    redirects are not followed, so the response is the host's own. Hosts that resolve to
    a non-public address are never contacted.
    """

    def __init__(self, database: FingerprintDatabase, timeout: float = 10.0, max_workers: int = 8):
        self.db = database
        self.timeout = timeout
        self.max_workers = max_workers
        self._session = make_session(retries=0)

    def check_many(self, results: Sequence[ResolutionResult]) -> List[Optional[TakeoverFinding]]:
        """Check hosts concurrently; findings follow the order of `results`."""
        if not results:
            return []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(results))) as pool:
            return list(pool.map(self.check, results))

    def check(self, result: ResolutionResult) -> Optional[TakeoverFinding]:
        chain = result.cname_chain
        if result.status not in (ResolutionStatus.CNAME, ResolutionStatus.DANGLING_CNAME) or not chain:
            return None
        dangling = result.status is ResolutionStatus.DANGLING_CNAME

        matched = next(
            ((hop, fp) for hop in reversed(chain) if (fp := self.db.match(hop)) is not None), None
        )
        if matched is None:
            if dangling:
                return self._finding(
                    result, TakeoverVerdict.LIKELY, None,
                    "dangling CNAME: the target does not exist and is not a known service",
                )
            return None
        hop, fp = matched

        if not fp.vulnerable:
            return self._finding(
                result, TakeoverVerdict.NOT_VULNERABLE, fp.service,
                f"matched {fp.service}, which is not takeover-prone",
            )
        if fp.nxdomain:
            if dangling:
                return self._finding(
                    result, TakeoverVerdict.VULNERABLE, fp.service,
                    f"CNAME target {hop} does not resolve and {fp.service} allows claiming it",
                )
            return self._finding(
                result, TakeoverVerdict.NOT_VULNERABLE, fp.service,
                f"{fp.service} target {hop} still resolves",
            )
        if dangling:
            return self._finding(
                result, TakeoverVerdict.LIKELY, fp.service,
                f"CNAME target {hop} does not resolve; {fp.service} is takeover-prone",
            )
        if fp.pattern is None and fp.http_status is None:
            return self._finding(
                result, TakeoverVerdict.LIKELY, fp.service,
                f"points at takeover-prone {fp.service}; no automatic fingerprint, verify manually",
            )
        if result.a_records and not all_public(result.a_records):
            return self._finding(
                result, TakeoverVerdict.UNKNOWN_SERVICE, fp.service,
                "resolves to a non-public address; not probed",
            )
        return self._check_http(result, fp)

    def _check_http(self, result: ResolutionResult, fp: Fingerprint) -> TakeoverFinding:
        response = self._fetch(result.hostname)
        if response is None:
            return self._finding(
                result, TakeoverVerdict.UNKNOWN_SERVICE, fp.service,
                "could not reach the host over HTTP or HTTPS",
            )
        status, body = response
        body_match = fp.pattern is not None and fp.pattern.search(body) is not None
        status_match = fp.http_status is None or status == fp.http_status

        if fp.pattern is not None and body_match and status_match:
            return self._finding(
                result, TakeoverVerdict.VULNERABLE, fp.service,
                f"HTTP {status} body matches the {fp.service} unclaimed-resource page",
            )
        if fp.pattern is not None and body_match:
            return self._finding(
                result, TakeoverVerdict.LIKELY, fp.service,
                f"{fp.service} page text matched but HTTP {status} != expected {fp.http_status}",
            )
        if fp.pattern is None and status_match:
            return self._finding(
                result, TakeoverVerdict.LIKELY, fp.service,
                f"{fp.service} returned the status ({status}) used as its takeover signal",
            )
        return self._finding(
            result, TakeoverVerdict.NOT_VULNERABLE, fp.service,
            f"{fp.service} host responded (HTTP {status}) without the unclaimed-resource page",
        )

    def _fetch(self, hostname: str) -> Optional[Tuple[int, str]]:
        # Redirects are not followed: status-only fingerprints (e.g. an expected 301) would
        # otherwise never match, and we would read pages from hosts outside the target.
        for scheme in ("https", "http"):
            try:
                response = self._session.get(
                    f"{scheme}://{hostname}", timeout=self.timeout, stream=True, allow_redirects=False
                )
                return response.status_code, read_capped(response, _MAX_BODY_BYTES)
            except requests.RequestException:
                continue
        return None

    @staticmethod
    def _finding(
        result: ResolutionResult, verdict: TakeoverVerdict, service: Optional[str], evidence: str
    ) -> TakeoverFinding:
        return TakeoverFinding(result.hostname, verdict, service, list(result.cname_chain), evidence)
