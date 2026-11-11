"""DNS resolution with CNAME chain tracking and wildcard detection."""

from __future__ import annotations

import copy
import random
import string
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Set, Tuple

import dns.exception
import dns.resolver

from rimscan_cli.recon._common import normalize_name

__all__ = ["ResolutionStatus", "ResolutionResult", "DNSResolver"]


class ResolutionStatus(Enum):
    A_RECORD = "a_record"
    CNAME = "cname"
    DANGLING_CNAME = "dangling_cname"
    NXDOMAIN = "nxdomain"
    NO_RECORD = "no_record"
    WILDCARD = "wildcard"
    TIMEOUT = "timeout"
    ERROR = "error"


# Transient failures are not cached so a flaky lookup can be retried later.
_CACHEABLE = {
    ResolutionStatus.A_RECORD,
    ResolutionStatus.CNAME,
    ResolutionStatus.DANGLING_CNAME,
    ResolutionStatus.NXDOMAIN,
    ResolutionStatus.NO_RECORD,
    ResolutionStatus.WILDCARD,
}


@dataclass
class ResolutionResult:
    hostname: str
    status: ResolutionStatus
    a_records: List[str] = field(default_factory=list)
    cname_target: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    error_detail: Optional[str] = None

    def __repr__(self) -> str:
        if self.status in (ResolutionStatus.CNAME, ResolutionStatus.DANGLING_CNAME):
            return f"<{self.hostname} {self.status.value} via {' -> '.join(self.cname_chain)}>"
        if self.status is ResolutionStatus.A_RECORD:
            return f"<{self.hostname} A {', '.join(self.a_records)}>"
        return f"<{self.hostname} {self.status.value}>"

    @property
    def is_live(self) -> bool:
        """True when the name resolves to at least one address and is not wildcard noise."""
        return bool(self.a_records) and self.status in (
            ResolutionStatus.A_RECORD,
            ResolutionStatus.CNAME,
        )


class DNSResolver:
    def __init__(
        self,
        timeout: float = 5.0,
        max_workers: int = 20,
        nameservers: Optional[Sequence[str]] = None,
    ):
        self.max_workers = max_workers
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._cache: Dict[str, ResolutionResult] = {}
        self._wildcard_domain: Optional[str] = None
        self._wildcard_ips: Set[str] = set()
        self._wildcard_cnames: Set[str] = set()

    # -- wildcard handling -------------------------------------------------

    def detect_wildcard(self, domain: str, probes: int = 3, min_hits: int = 2) -> bool:
        """Resolve random labels under `domain`; if several resolve, it is a wildcard zone.

        CDN-backed wildcards can answer with different addresses for every label, so
        the probes only have to resolve, not agree. Call this before resolving hosts.

        Limitation: a real host that shares its addresses or CNAME target with the
        wildcard cannot be told apart from wildcard noise and is reported as WILDCARD.
        """
        domain = normalize_name(domain)
        self._wildcard_domain = None
        self._wildcard_ips = set()
        self._wildcard_cnames = set()
        self._cache.clear()

        hits: List[ResolutionResult] = []
        for _ in range(probes):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            result = self._resolve_uncached(f"{label}.{domain}")
            if result.is_live:
                hits.append(result)

        if len(hits) < min(min_hits, probes):
            return False
        self._wildcard_domain = domain
        for hit in hits:
            self._wildcard_ips.update(hit.a_records)
            if hit.cname_chain:
                self._wildcard_cnames.add(hit.cname_chain[-1])
        return True

    def _is_wildcard_answer(self, hostname: str, ips: List[str], chain: List[str]) -> bool:
        domain = self._wildcard_domain
        if not domain or not hostname.endswith("." + domain):
            return False
        if chain and chain[-1] in self._wildcard_cnames:
            return True
        return bool(ips) and set(ips) <= self._wildcard_ips

    # -- lookups -----------------------------------------------------------

    def _lookup(self, name: str, rdtype: str) -> Tuple[list, str]:
        """Return (records, state); state is ok, nodata, nxdomain, timeout or error."""
        for attempt in range(2):
            try:
                return list(self._resolver.resolve(name, rdtype)), "ok"
            except dns.resolver.NoAnswer:
                return [], "nodata"
            except dns.resolver.NXDOMAIN:
                return [], "nxdomain"
            except dns.exception.Timeout:
                if attempt == 1:
                    return [], "timeout"
            except dns.exception.DNSException:
                return [], "error"
        return [], "timeout"

    @staticmethod
    def _failure(hostname: str, chain: List[str], state: str) -> ResolutionResult:
        if state == "nxdomain":
            if chain:
                return ResolutionResult(
                    hostname, ResolutionStatus.DANGLING_CNAME, cname_chain=chain, cname_target=chain[-1]
                )
            return ResolutionResult(hostname, ResolutionStatus.NXDOMAIN)
        if state == "timeout":
            return ResolutionResult(hostname, ResolutionStatus.TIMEOUT, cname_chain=chain)
        return ResolutionResult(
            hostname, ResolutionStatus.ERROR, cname_chain=chain, error_detail="DNS lookup failed"
        )

    def _resolve_uncached(self, hostname: str, max_chain_depth: int = 10) -> ResolutionResult:
        chain: List[str] = []
        current = normalize_name(hostname)
        visited = {current}

        while True:
            records, state = self._lookup(current, "CNAME")
            if state == "nodata":
                break
            if state != "ok":
                return self._failure(hostname, chain, state)
            target = normalize_name(str(records[0].target))
            if target in visited:
                return ResolutionResult(
                    hostname, ResolutionStatus.ERROR, cname_chain=chain,
                    error_detail=f"CNAME loop at {target}",
                )
            if len(chain) >= max_chain_depth:
                return ResolutionResult(
                    hostname, ResolutionStatus.ERROR, cname_chain=chain,
                    error_detail=f"CNAME chain longer than {max_chain_depth} hops",
                )
            visited.add(target)
            chain.append(target)
            current = target

        ips: List[str] = []
        for rdtype in ("A", "AAAA"):
            records, state = self._lookup(current, rdtype)
            if state == "ok":
                ips = [str(r) for r in records]
                break
            if state != "nodata":
                return self._failure(hostname, chain, state)

        if not ips:
            if chain:
                return ResolutionResult(
                    hostname, ResolutionStatus.CNAME, cname_chain=chain, cname_target=chain[-1]
                )
            return ResolutionResult(hostname, ResolutionStatus.NO_RECORD)

        if self._is_wildcard_answer(normalize_name(hostname), ips, chain):
            return ResolutionResult(
                hostname, ResolutionStatus.WILDCARD, a_records=ips, cname_chain=chain
            )
        if chain:
            return ResolutionResult(
                hostname, ResolutionStatus.CNAME, a_records=ips,
                cname_chain=chain, cname_target=chain[-1],
            )
        return ResolutionResult(hostname, ResolutionStatus.A_RECORD, a_records=ips)

    # -- public API --------------------------------------------------------

    def resolve_one(self, hostname: str, max_chain_depth: int = 10) -> ResolutionResult:
        key = normalize_name(hostname)
        cached = self._cache.get(key)
        if cached is not None:
            result = copy.deepcopy(cached)
            result.hostname = hostname
            return result
        result = self._resolve_uncached(hostname, max_chain_depth)
        if result.status in _CACHEABLE:
            self._cache[key] = copy.deepcopy(result)
        return result

    def resolve_many(self, hostnames: Sequence[str]) -> List[ResolutionResult]:
        """Resolve hosts concurrently; results follow the order of `hostnames`."""
        names = list(dict.fromkeys(hostnames))
        if not names:
            return []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(names))) as pool:
            return list(pool.map(self.resolve_one, names))
