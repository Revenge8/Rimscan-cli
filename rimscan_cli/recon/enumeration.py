"""Subdomain enumeration from public passive-DNS and certificate-transparency sources."""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

import requests

from rimscan_cli.recon._http import make_session, read_capped
from rimscan_cli.recon.resolver import DNSResolver

logger = logging.getLogger(__name__)

__all__ = ["SubdomainEnumerator", "DEFAULT_SOURCES", "BRUTEFORCE_WORDLIST"]

DEFAULT_SOURCES = ("crt.sh", "certspotter", "otx", "rapiddns", "wayback", "anubis")

BRUTEFORCE_WORDLIST = (
    "www", "mail", "ftp", "dev", "staging", "api", "admin", "test", "portal", "vpn",
    "app", "blog", "shop", "cdn", "static", "assets", "beta", "demo", "internal",
    "secure", "cloud", "docs", "support", "help", "status", "monitor", "git",
    "gitlab", "jenkins", "jira", "backup", "old", "new", "m", "mobile", "webmail",
    "smtp", "ns1", "ns2", "db", "dashboard", "auth", "sso", "login", "stage",
    "uat", "qa", "preview",
)

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_WAYBACK_MAX_BYTES = 25 * 1024 * 1024
_RAPIDDNS_LINK = re.compile(r'target="_blank">([^<]+)</a>')


class SubdomainEnumerator:
    def __init__(self, domain: str, timeout: float = 10.0):
        self.domain = domain.lower().strip().strip(".")
        self.timeout = (min(timeout, 5.0), timeout)
        self.session = make_session()
        self.source_status: Dict[str, str] = {}
        self._sources: Dict[str, Callable[[], Set[str]]] = {
            "crt.sh": self.from_crtsh,
            "certspotter": self.from_certspotter,
            "otx": self.from_otx,
            "rapiddns": self.from_rapiddns,
            "wayback": self.from_wayback,
            "anubis": self.from_anubis,
        }

    # -- helpers -----------------------------------------------------------

    def _accept(self, name: str) -> Optional[str]:
        """Normalize a candidate; return it only if it is a valid subdomain of the target."""
        name = name.strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if not name.endswith("." + self.domain) or len(name) > 253:
            return None
        labels = name.split(".")
        if all(_LABEL.fullmatch(label) for label in labels):
            return name
        return None

    def _collect(self, names: Iterable[str]) -> Set[str]:
        return {valid for valid in map(self._accept, names) if valid}

    def _get_json(self, url: str, **kwargs):
        response = self.session.get(url, timeout=self.timeout, **kwargs)
        response.raise_for_status()
        return response.json()

    # -- sources -----------------------------------------------------------

    def from_crtsh(self) -> Set[str]:
        data = self._get_json(f"https://crt.sh/?q=%25.{self.domain}&output=json")
        return self._collect(
            name for entry in data for name in entry.get("name_value", "").split("\n")
        )

    def from_certspotter(self, max_pages: int = 5) -> Set[str]:
        url = "https://api.certspotter.com/v1/issuances"
        params = {"domain": self.domain, "include_subdomains": "true", "expand": "dns_names"}
        names: Set[str] = set()
        for _ in range(max_pages):
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            page = response.json()
            if not page:
                break
            for issuance in page:
                names |= self._collect(issuance.get("dns_names", []))
            params["after"] = page[-1]["id"]
        return names

    def from_otx(self) -> Set[str]:
        data = self._get_json(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        )
        return self._collect(record.get("hostname", "") for record in data.get("passive_dns", []))

    def from_rapiddns(self) -> Set[str]:
        response = self.session.get(
            f"https://rapiddns.io/subdomain/{self.domain}", params={"full": 1}, timeout=self.timeout
        )
        response.raise_for_status()
        return self._collect(_RAPIDDNS_LINK.findall(response.text))

    def from_anubis(self) -> Set[str]:
        return self._collect(self._get_json(f"https://jldc.me/anubis/subdomains/{self.domain}"))

    def from_wayback(self) -> Set[str]:
        response = self.session.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{self.domain}", "output": "json", "fl": "original",
                "collapse": "urlkey", "limit": 100000,
            },
            timeout=self.timeout,
            stream=True,
        )
        response.raise_for_status()
        rows = json.loads(read_capped(response, _WAYBACK_MAX_BYTES))
        hosts = (urlparse(row[0] if "//" in row[0] else "//" + row[0]).hostname or "" for row in rows[1:] if row)
        return self._collect(hosts)

    def from_bruteforce(self, resolver: DNSResolver, wordlist: Iterable[str] = BRUTEFORCE_WORDLIST) -> Set[str]:
        """Resolve common prefixes. The resolver must already have run wildcard detection."""
        candidates = [f"{word.strip().lower()}.{self.domain}" for word in wordlist if word.strip()]
        return {r.hostname for r in resolver.resolve_many(candidates) if r.is_live}

    # -- orchestration -----------------------------------------------------

    def run(
        self,
        sources: Optional[List[str]] = None,
        source_timeout: float = 60.0,
        on_source_done: Optional[Callable[[str, int, str], None]] = None,
    ) -> Set[str]:
        """Query the selected sources concurrently and return the subdomains found.

        A slow or failing source never blocks the others; its outcome is recorded in
        `source_status`. The target domain itself is not included in the result.
        """
        chosen = list(sources) if sources else list(DEFAULT_SOURCES)
        unknown = [name for name in chosen if name not in self._sources]
        if unknown:
            raise ValueError(f"unknown source(s): {', '.join(unknown)}")

        found: Set[str] = set()
        pool = ThreadPoolExecutor(max_workers=len(chosen))
        futures = {pool.submit(self._sources[name]): name for name in chosen}
        done, pending = wait(futures, timeout=source_timeout)
        pool.shutdown(wait=False, cancel_futures=True)

        for future in done:
            name = futures[future]
            try:
                names = future.result()
            except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
                self.source_status[name] = f"failed ({type(exc).__name__})"
                logger.debug("%s failed", name, exc_info=True)
                names = set()
            else:
                self.source_status[name] = "ok"
            found |= names
            if on_source_done:
                on_source_done(name, len(names), self.source_status[name])
        for future in pending:
            name = futures[future]
            self.source_status[name] = "timed out"
            if on_source_done:
                on_source_done(name, 0, "timed out")
        return found
