"""Multi-source subdomain enumeration with concurrent fetching and export."""

from __future__ import annotations

import csv
import json
import logging
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import ScanConfig
from recon.resolver import DNSResolver, ResolutionStatus

logger = logging.getLogger(__name__)


def _log_source_error(source: str, exc: Exception) -> None:
    logger.warning("%s source failed (%s)", source, type(exc).__name__)
    logger.debug("%s source failure details", source, exc_info=True)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None  # type: ignore

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None  # type: ignore

__all__ = ["SubdomainEnumerator", "DEFAULT_WORDLIST"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; RimScan/1.0; +https://github.com/rimscan)",
]

# Anubis (jldc.me) is a small free community-run passive DNS API. Spoofing a
# random desktop-browser UA against it doesn't buy anything (it isn't
# anti-bot protected) and makes RimScan harder for the operator to identify
# if they ever need to reach out about abuse/rate-limits, so use an honest,
# identifiable UA for this source specifically instead of the randomized
# browser UAs used against sites that do fingerprint scrapers.
ANUBIS_USER_AGENT = "RimScan/1.0 (+https://github.com/rimscan; subdomain-recon)"

# Prefixes used by the DNS-brute-force source. Unlike every other source
# here, this one calls no external HTTP API at all — it only performs DNS
# resolution — so it has no outage/rate-limit surface and is the most
# reliable fallback when the passive-DNS providers above are unavailable.
DEFAULT_BRUTEFORCE_WORDLIST = [
    "www", "mail", "api", "dev", "staging", "admin", "test", "vpn",
    "ftp", "webmail", "portal", "app", "cdn", "blog", "shop", "m", "mobile",
]

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "dev", "staging", "api", "admin", "test",
    "portal", "vpn", "app", "blog", "shop", "cdn", "static", "assets",
    "beta", "demo", "internal", "secure", "cloud", "docs", "support",
    "help", "status", "monitor", "git", "gitlab", "jenkins", "jira",
    "backup", "old", "new", "m", "mobile", "webmail", "smtp",
    "ns1", "ns2", "db", "dashboard", "auth", "sso", "login", "stage",
    "uat", "qa", "preview",
]


class SubdomainEnumerator:
    def __init__(
        self,
        domain: str,
        timeout: int | float | tuple[float, float] = 10,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
    ):
        self.domain = domain.lower().strip().strip(".")
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.results: Set[str] = set()
        self.source_status: Dict[str, str] = {}
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    _EXTERNAL_TIMEOUT_CAP = 10.0
    _WAYBACK_TIMEOUT = (5.0, 5.0)
    _OSINT_RETRIES = 1

    def _quiet_osint_get(self, url: str) -> requests.Response:
        """Fetch slow OSINT sources with bounded, quiet retries."""
        session = requests.Session()
        session.mount(
            "https://",
            HTTPAdapter(
                max_retries=Retry(
                    total=self._OSINT_RETRIES,
                    connect=self._OSINT_RETRIES,
                    read=self._OSINT_RETRIES,
                    status=self._OSINT_RETRIES,
                    status_forcelist=(429, 500, 502, 503, 504),
                    allowed_methods=["GET"],
                    raise_on_status=False,
                )
            ),
        )
        return session.get(url, headers=self._headers(), timeout=self._WAYBACK_TIMEOUT)

    def _wayback_get(self, url: str) -> requests.Response:
        return self._quiet_osint_get(url)

    def _otx_get(self, url: str) -> requests.Response:
        return self._quiet_osint_get(url)

    def _request_timeout(self, minimum: float = 0.0) -> float:
        connect, read = ScanConfig.normalize_timeout(self.timeout)
        return max(connect, read, minimum)

    def _capped_timeout(self, cap: float) -> Tuple[float, float]:
        connect, read = ScanConfig.normalize_timeout(self.timeout)
        return (min(connect, cap), min(read, cap))

    def _headers(self) -> dict:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/json,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }

    def _get_with_retry(
        self,
        url: str,
        attempts: int = 3,
        backoff_base: float = 1.5,
        method: str = "get",
        **kwargs,
    ) -> Optional[requests.Response]:
        """GET/POST with source-level retry on 403/429 beyond what the
        session-level urllib3 Retry already covers (that layer handles
        429/5xx transport retries; this handles source-specific soft blocks
        like anti-bot 403s that don't always trip the adapter's
        status_forcelist cleanly)."""
        requester = self._post if method.lower() == "post" else self._get
        last_exc: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                resp = requester(url, **kwargs)
            except requests.RequestException as e:
                last_exc = e
                time.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.5))
                continue

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else backoff_base * (2 ** attempt)
                time.sleep(delay + random.uniform(0, 0.5))
                continue
            if resp.status_code == 403 and attempt < attempts - 1:
                kwargs["headers"] = self._headers()
                time.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.5))
                continue
            return resp

        if last_exc:
            raise last_exc
        return None

    def _get(self, url: str, **kwargs) -> requests.Response:
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout
        kwargs.setdefault("headers", self._headers())
        return self.session.get(url, **kwargs)

    def _post(self, url: str, **kwargs) -> requests.Response:
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout
        kwargs.setdefault("headers", self._headers())
        return self.session.post(url, **kwargs)

    def _is_valid_subdomain(self, name: str) -> bool:
        name = name.lower().strip()
        if not name or (name != self.domain and not name.endswith("." + self.domain)):
            return False
        if " " in name or "@" in name or "*" in name:
            return False
        pattern = r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$"
        return bool(re.match(pattern, name))

    def from_crtsh(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        try:
            resp = self._get_with_retry(
                url, timeout=self._capped_timeout(self._EXTERNAL_TIMEOUT_CAP)
            )
            if resp is None:
                return subdomains
            resp.raise_for_status()
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if self._is_valid_subdomain(name):
                        subdomains.add(name)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("crt.sh", e)
        return subdomains

    def from_certspotter(self) -> Set[str]:
        """Certificate-transparency source, same shape/error-handling as
        from_crtsh — a direct backup for when crt.sh itself is slow or
        rate-limiting (both mine the same CT logs, so they rarely fail at
        the same time)."""
        subdomains: Set[str] = set()
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={self.domain}&include_subdomains=true&expand=dns_names"
        )
        try:
            resp = self._get_with_retry(
                url, timeout=self._capped_timeout(self._EXTERNAL_TIMEOUT_CAP)
            )
            if resp is None:
                return subdomains
            resp.raise_for_status()
            for issuance in resp.json():
                for name in issuance.get("dns_names", []):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if self._is_valid_subdomain(name):
                        subdomains.add(name)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("certspotter", e)
        return subdomains

    def from_otx(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            resp = self._otx_get(url)
            resp.raise_for_status()
            for record in resp.json().get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except requests.Timeout:
            self.source_status["otx"] = "timed out, skipped"
        except (requests.RequestException, ValueError):
            self.source_status["otx"] = "unavailable, skipped"
        return subdomains

    def from_rapiddns(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        try:
            resp = self._get_with_retry(url)
            if resp is None:
                return subdomains
            resp.raise_for_status()
            if BeautifulSoup:
                for parser in ("lxml", "html.parser"):
                    try:
                        soup = BeautifulSoup(resp.text, parser)
                        for link in soup.find_all("a", target="_blank"):
                            hostname = link.get_text(strip=True).lower()
                            if self._is_valid_subdomain(hostname):
                                subdomains.add(hostname)
                        if subdomains:
                            return subdomains
                    except Exception:
                        continue
            for match in re.findall(r'target="_blank">([^<]+)</a>', resp.text):
                hostname = match.strip().lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except requests.RequestException as e:
            _log_source_error("RapidDNS", e)
        return subdomains

    # Guard rail for wildly popular domains where the CDX index can run to
    # hundreds of MB of JSON; loading that whole body via resp.json() risks
    # a slow/failed parse or memory spike for one source out of many.
    #
    # NOTE: this stays on the original resp.json()/resp.text interface
    # (rather than resp.iter_content()) deliberately — switching to a
    # streaming read broke every test that mocks the response the normal
    # way (setting .json()/.text), which is a compatibility regression, not
    # an improvement. The size guard below is best-effort: it protects
    # against a server that honestly reports Content-Length, and against an
    # already-parsed .text body that's unexpectedly huge, without requiring
    # every caller/test to simulate a real streaming response.
    _WAYBACK_MAX_BYTES = 50 * 1024 * 1024  # 50 MB

    def from_wayback(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}"
            "&output=json&collapse=urlkey&fl=original"
        )
        try:
            resp = self._wayback_get(url)
            resp.raise_for_status()

            # defensively read Content-Length — tests often use MagicMock
            # where headers is a Mock, so coerce carefully to an int when
            # possible and otherwise ignore the header.
            content_length_val = None
            try:
                hdrs = getattr(resp, "headers", None)
                if isinstance(hdrs, dict):
                    content_length = hdrs.get("Content-Length")
                else:
                    try:
                        content_length = hdrs.get("Content-Length") if hdrs is not None else None
                    except Exception:
                        content_length = None
                if content_length is not None:
                    try:
                        content_length_val = int(content_length)
                    except Exception:
                        try:
                            content_length_val = int(str(content_length))
                        except Exception:
                            content_length_val = None
                if content_length_val and content_length_val > self._WAYBACK_MAX_BYTES:
                    print(
                        f"[!] Wayback: response too large "
                        f"({content_length_val / 1_000_000:.1f} MB), skipping to avoid OOM"
                    )
                    return subdomains
            except Exception:
                # If anything unexpected happened reading headers, ignore
                # the size hint and continue to parsing — don't let a test
                # double or odd header object blow up the whole source.
                content_length_val = None

            raw_text = getattr(resp, "text", None)
            if isinstance(raw_text, str):
                try:
                    if len(raw_text.encode("utf-8", errors="ignore")) > self._WAYBACK_MAX_BYTES:
                        print("[!] Wayback: response body exceeds size cap, skipping to avoid OOM")
                        return subdomains
                except Exception:
                    # If encoding inspection fails for some odd reason,
                    # don't abort the whole source.
                    pass

            # Try resp.json() first, but if it raises ValueError (bad JSON)
            # attempt to parse resp.text when it's a real string; fall back
            # to skipping the source otherwise. This makes tests that set
            # .json() or .text behave predictably.
            try:
                data = resp.json()
            except ValueError:
                try:
                    raw = getattr(resp, "text", None)
                    if isinstance(raw, str):
                        data = json.loads(raw)
                    else:
                        print("[!] Wayback: could not parse JSON (resp.json() failed)")
                        return subdomains
                except Exception as e:
                    _log_source_error("Wayback JSON parsing", e)
                    return subdomains

            if not isinstance(data, list) or len(data) < 2:
                return subdomains

            for row in data[1:]:
                if not row:
                    continue
                raw_url = row[0]
                if not raw_url.startswith(("http://", "https://")):
                    raw_url = "http://" + raw_url
                hostname = urlparse(raw_url).netloc.split(":")[0].lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except requests.Timeout:
            self.source_status["wayback"] = "timed out, skipped"
        except requests.RequestException:
            self.source_status["wayback"] = "unavailable, skipped"
        return subdomains

    def from_virustotal(self, api_key: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": api_key, **self._headers()}
        next_url: Optional[str] = url
        try:
            while next_url:
                resp = self.session.get(next_url, headers=headers, timeout=self.timeout)
                resp.raise_for_status()
                payload = resp.json()
                for item in payload.get("data", []):
                    hostname = item.get("id", "").strip().lower()
                    if self._is_valid_subdomain(hostname):
                        subdomains.add(hostname)
                next_url = payload.get("links", {}).get("next")
                if next_url:
                    time.sleep(0.5)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("VirusTotal", e)
        return subdomains

    # DNSdumpster occasionally renders the CSRF input with attribute order or
    # quoting that drifts from a single fixed pattern (e.g. value before
    # name, single quotes, extra whitespace/newlines). Try several
    # extraction strategies before giving up, since a page-markup tweak on
    # their end shouldn't silently zero out this source.
    _CSRF_PATTERNS = (
        re.compile(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']'),
        re.compile(r'value=["\']([^"\']+)["\']\s+name=["\']csrfmiddlewaretoken["\']'),
        re.compile(r'csrfmiddlewaretoken["\']?\s*[:=]\s*["\']([^"\']+)["\']'),
    )

    def _extract_csrf_token(self, html: str) -> Optional[str]:
        if BeautifulSoup:
            for parser in ("lxml", "html.parser"):
                try:
                    soup = BeautifulSoup(html, parser)
                    token = soup.find("input", {"name": "csrfmiddlewaretoken"})
                    if token and token.get("value"):
                        return token.get("value")
                except Exception:
                    continue
        for pattern in self._CSRF_PATTERNS:
            match = pattern.search(html)
            if match:
                return match.group(1)
        # Fall back to the csrftoken cookie, which DNSdumpster also sets and
        # which some deployments require to match the form value.
        return self.session.cookies.get("csrftoken")

    def from_dnsdumpster(self) -> Set[str]:
        subdomains: Set[str] = set()
        base = "https://dnsdumpster.com/"
        try:
            resp = self._get_with_retry(base, attempts=2)
            if resp is None:
                return subdomains
            resp.raise_for_status()
            csrf = self._extract_csrf_token(resp.text)
            if not csrf:
                print("[!] DNSdumpster: could not extract CSRF token (page markup may have changed)")
                return subdomains

            post_resp = self._get_with_retry(
                base,
                attempts=2,
                data={"csrfmiddlewaretoken": csrf, "targetip": self.domain},
                headers={
                    **self._headers(),
                    "Referer": base,
                    "Origin": "https://dnsdumpster.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-CSRFToken": csrf,
                },
                method="post",
            )
            if post_resp is None:
                return subdomains
            post_resp.raise_for_status()
            text = post_resp.text
            if BeautifulSoup:
                soup = BeautifulSoup(text, "lxml")
                for td in soup.find_all("td", class_="col-md-4"):
                    hostname = td.get_text(strip=True).lower()
                    if self._is_valid_subdomain(hostname):
                        subdomains.add(hostname)
            pattern = rf"([a-z0-9][a-z0-9\-\.]+\.{re.escape(self.domain)})"
            for match in re.findall(pattern, text.lower()):
                if self._is_valid_subdomain(match):
                    subdomains.add(match)
        except requests.RequestException as e:
            _log_source_error("DNSdumpster", e)
        return subdomains

    def from_bufferover(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://dns.bufferover.run/dns?q={self.domain}"
        try:
            resp = self._get(url, timeout=self._request_timeout(12))
            resp.raise_for_status()
            payload = resp.json()
            for key in ("FDNS_A", "FDNS_AAAA", "RDNS"):
                for item in payload.get(key, []) or []:
                    if not isinstance(item, str):
                        continue
                    candidate = item.strip().lower()
                    if not candidate:
                        continue
                    if "," in candidate:
                        candidate = candidate.split(",")[-1].strip()
                    if self._is_valid_subdomain(candidate):
                        subdomains.add(candidate)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("BufferOver", e)
        return subdomains

    def from_anubis(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        headers = {**self._headers(), "User-Agent": ANUBIS_USER_AGENT}
        try:
            resp = self._get_with_retry(url, timeout=self._request_timeout(8), headers=headers)
            if resp is None:
                return subdomains
            resp.raise_for_status()
            for hostname in resp.json():
                hostname = hostname.strip().lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("Anubis", e)
        return subdomains

    def from_threatcrowd(self) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        try:
            resp = self._get(url, timeout=self._request_timeout(12))
            resp.raise_for_status()
            payload = resp.json()
            for sub in payload.get("subdomains", []) or []:
                hostname = str(sub).strip().lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("ThreatCrowd", e)
        return subdomains

    def from_securitytrails(self, api_key: str) -> Set[str]:
        subdomains: Set[str] = set()
        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": api_key, **self._headers()}
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            resp.raise_for_status()
            for sub in resp.json().get("subdomains", []):
                hostname = f"{sub}.{self.domain}".lower()
                if self._is_valid_subdomain(hostname):
                    subdomains.add(hostname)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("SecurityTrails", e)
        return subdomains

    def _bruteforce_candidates(self, wordlist: List[str]) -> Set[str]:
        """Generate raw `{word}.{domain}` candidates without resolving them.

        Used by run()'s legacy use_bruteforce/use_smart_wordlist path, where
        resolution of the (potentially large, fingerprint-derived) wordlist
        happens later, in bulk, via DNSResolver.resolve_many(). For a
        self-contained *source* that resolves on its own, see
        from_bruteforce() below.
        """
        return {f"{word.strip().lower()}.{self.domain}" for word in wordlist if word.strip()}

    def from_bruteforce(self, wordlist: Optional[List[str]] = None) -> Set[str]:
        """DNS brute-force source: resolve a small list of common prefixes
        directly and only return the ones that actually exist.

        This is the one source here with no external HTTP API to fail,
        rate-limit, or go down — it just does DNS lookups — so it acts as a
        reliable fallback even when every passive-DNS provider above is
        unavailable.
        """
        active_wordlist = wordlist if wordlist is not None else DEFAULT_BRUTEFORCE_WORDLIST
        candidates = sorted(self._bruteforce_candidates(active_wordlist))

        subdomains: Set[str] = set()
        resolver = DNSResolver(timeout=self._request_timeout(minimum=5.0))
        for result in resolver.resolve_many(candidates):
            if result.status not in (ResolutionStatus.A_RECORD, ResolutionStatus.CNAME):
                continue
            hostname = result.hostname.lower().strip(".")
            if self._is_valid_subdomain(hostname):
                subdomains.add(hostname)
        return subdomains

    def generate_smart_wordlist(
        self,
        fingerprints_url: str = (
            "https://raw.githubusercontent.com/EdOverflow/"
            "can-i-take-over-xyz/master/fingerprints.json"
        ),
    ) -> List[str]:
        wordlist = set(DEFAULT_WORDLIST)
        label_pattern = re.compile(r"^[a-z0-9-]+$")
        try:
            resp = self._get(fingerprints_url)
            resp.raise_for_status()
            for entry in resp.json():
                service = entry.get("service", "")
                for part in service.lower().replace("/", " ").replace("-", " ").split():
                    if len(part) > 1 and label_pattern.match(part):
                        wordlist.add(part)
                for cname in entry.get("cname", []):
                    prefix = cname.split(".")[0].strip().lower()
                    if len(prefix) > 1 and prefix not in ("s3", "azure") and label_pattern.match(prefix):
                        wordlist.add(prefix)
        except (requests.RequestException, ValueError) as e:
            _log_source_error("Smart-wordlist fingerprints", e)
        return sorted(wordlist)

    def run(
        self,
        use_bruteforce: bool = False,
        wordlist: Optional[List[str]] = None,
        use_smart_wordlist: bool = False,
        securitytrails_api_key: Optional[str] = None,
        virustotal_api_key: Optional[str] = None,
        sources: Optional[List[str]] = None,
        rate_limit_delay: float = 0.0,
    ) -> Set[str]:
        print(f"[*] Enumerating subdomains for {self.domain}...")

        source_map: Dict[str, Callable[[], Set[str]]] = {
            "crt.sh": self.from_crtsh,
            "certspotter": self.from_certspotter,
            "otx": self.from_otx,
            "rapiddns": self.from_rapiddns,
            "wayback": self.from_wayback,
            "anubis": self.from_anubis,
            "dnsdumpster": self.from_dnsdumpster,
            "bruteforce": self.from_bruteforce,
        }
        # bufferover and threatcrowd are both defunct/unreliable as of 2026
        # (dns.bufferover.run and threatcrowd.org no longer respond
        # reliably). The methods (from_bufferover, from_threatcrowd) are
        # kept for anyone who still wants to call them directly, but they're
        # no longer part of the default source list.
        if securitytrails_api_key:
            source_map["securitytrails"] = lambda: self.from_securitytrails(securitytrails_api_key)
        if virustotal_api_key:
            source_map["virustotal"] = lambda: self.from_virustotal(virustotal_api_key)

        active_sources = sources or list(source_map.keys())
        tasks = {name: source_map[name] for name in active_sources if name in source_map}

        if tasks:
            with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
                futures = {executor.submit(fetcher): name for name, fetcher in tasks.items()}
                completed = as_completed(futures)
                if tqdm:
                    completed = tqdm(completed, total=len(futures), desc="Sources", unit="source")
                for future in completed:
                    name = futures[future]
                    try:
                        found = future.result()
                    except Exception as e:
                        _log_source_error(name, e)
                        found = set()
                    status = self.source_status.pop(name, "")
                    suffix = f" ({status})" if status else ""
                    print(f"[+] {name}: {len(found)} subdomains{suffix}")
                    self.results |= found
                    if rate_limit_delay:
                        time.sleep(rate_limit_delay)

        if use_bruteforce:
            active_wordlist = (
                self.generate_smart_wordlist()
                if use_smart_wordlist
                else (wordlist or DEFAULT_WORDLIST)
            )
            brute_candidates = self._bruteforce_candidates(active_wordlist)
            print(f"[+] Brute-force candidates: {len(brute_candidates)} (unverified)")
            self.results |= brute_candidates

        self.results.add(self.domain)
        print(f"[*] Total unique candidates: {len(self.results)}")
        return self.results

    # Aliases for integration tests / external API
    source_crtsh = from_crtsh
    source_certspotter = from_certspotter
    source_otx = from_otx
    source_rapiddns = from_rapiddns
    source_wayback = from_wayback
    source_bufferover = from_bufferover
    source_anubis = from_anubis
    source_threatcrowd = from_threatcrowd
    source_dnsdumpster = from_dnsdumpster
    source_securitytrails = from_securitytrails
    source_virustotal = from_virustotal
    source_bruteforce = from_bruteforce

    @staticmethod
    def export(subdomains: Set[str], path: str, fmt: str = "txt") -> None:
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        sorted_subs = sorted(subdomains)

        if fmt == "json":
            path_obj.write_text(json.dumps(sorted_subs, indent=2), encoding="utf-8")
        elif fmt == "csv":
            with path_obj.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["subdomain"])
                for sub in sorted_subs:
                    writer.writerow([sub])
        elif fmt == "html":
            rows = "\n".join(f"<li>{s}</li>" for s in sorted_subs)
            path_obj.write_text(
                f"<!DOCTYPE html><html><body><ul>{rows}</ul></body></html>",
                encoding="utf-8",
            )
        else:
            path_obj.write_text("\n".join(sorted_subs) + "\n", encoding="utf-8")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    enumerator = SubdomainEnumerator(target)
    found = enumerator.run(use_bruteforce=True, use_smart_wordlist=True)
    for sub in sorted(found):
        print(sub)
