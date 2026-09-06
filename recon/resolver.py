"""DNS resolution with CNAME chaining, wildcard detection, and caching."""

from __future__ import annotations

import concurrent.futures
import random
import socket
import string
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

__all__ = [
    "ResolutionStatus",
    "ResolutionResult",
    "DNSResolver",
]


class ResolutionStatus(Enum):
    A_RECORD = "a_record"
    CNAME = "cname"
    DANGLING_CNAME = "dangling_cname"
    NXDOMAIN = "nxdomain"
    NO_RECORD = "no_record"
    WILDCARD = "wildcard"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ResolutionResult:
    hostname: str
    status: ResolutionStatus
    a_records: List[str] = field(default_factory=list)
    cname_target: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    historical_cnames: List[str] = field(default_factory=list)
    error_detail: Optional[str] = None

    def __repr__(self) -> str:
        if self.status in (ResolutionStatus.CNAME, ResolutionStatus.DANGLING_CNAME):
            chain_str = " -> ".join(self.cname_chain) if self.cname_chain else self.cname_target
            return f"<{self.hostname} {self.status.value.upper()} chain: {chain_str}>"
        if self.status is ResolutionStatus.A_RECORD:
            return f"<{self.hostname} A -> {', '.join(self.a_records)}>"
        return f"<{self.hostname} {self.status.value}>"


class DNSResolver:
    """Resolve hostnames with CNAME-first logic, wildcard filtering, and result caching."""

    def __init__(self, timeout: float = 5.0, max_workers: int = 20):
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self._cache: Dict[str, ResolutionResult] = {}
        self._wildcard_ips: Optional[set[str]] = None
        self._wildcard_domain: Optional[str] = None

    def detect_wildcard(
        self,
        domain: str,
        probes: int = 3,
        min_agreement: int = 2,
    ) -> bool:
        """Probe multiple random subdomains before declaring a wildcard.

        A single lucky hostname match can be a coincidence or transient DNS issue.
        Downstream logic trusts this value heavily, so require multiple probes to
        agree on overlapping IPs before treating the domain as wildcarded.
        """
        domain = domain.lower().strip(".")
        ip_sets: list[set[str]] = []

        for _ in range(max(1, probes)):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
            probe = f"{label}.{domain}"
            result = self._resolve_uncached(probe)
            if result.status in (ResolutionStatus.A_RECORD, ResolutionStatus.CNAME) and result.a_records:
                ip_sets.append(set(result.a_records))

        self._wildcard_domain = domain

        if len(ip_sets) < min_agreement:
            self._wildcard_ips = set()
            return False

        common = set.intersection(*ip_sets) if ip_sets else set()
        if common:
            self._wildcard_ips = common
            return True

        self._wildcard_ips = set()
        return False

    def resolve_one(self, hostname: str, max_chain_depth: int = 10) -> ResolutionResult:
        key = hostname.lower().strip(".")
        if key in self._cache:
            cached = self._cache[key]
            return ResolutionResult(
                hostname=hostname,
                status=cached.status,
                a_records=list(cached.a_records),
                cname_target=cached.cname_target,
                cname_chain=list(cached.cname_chain),
                historical_cnames=list(cached.historical_cnames),
                error_detail=cached.error_detail,
            )
        result = self._resolve_uncached(hostname, max_chain_depth)
        self._cache[key] = result
        return result

    def _resolve_uncached(self, hostname: str, max_chain_depth: int = 10) -> ResolutionResult:
        chain: List[str] = []
        current = hostname.lower().strip(".")
        visited = {current}

        for _ in range(max_chain_depth):
            cname_target, err = self._query_cname(current)
            if err == "loop":
                return ResolutionResult(
                    hostname, ResolutionStatus.ERROR,
                    cname_chain=chain, error_detail=f"CNAME loop detected at {current}",
                )
            if err == "nxdomain":
                if chain:
                    return ResolutionResult(
                        hostname, ResolutionStatus.DANGLING_CNAME,
                        cname_chain=chain, cname_target=chain[-1],
                    )
                return ResolutionResult(hostname, ResolutionStatus.NXDOMAIN)
            if err == "timeout":
                return ResolutionResult(hostname, ResolutionStatus.TIMEOUT, cname_chain=chain)
            if err == "error":
                return ResolutionResult(
                    hostname, ResolutionStatus.ERROR, cname_chain=chain,
                    error_detail="CNAME lookup failed",
                )
            if cname_target is None:
                break
            if cname_target in visited:
                return ResolutionResult(
                    hostname, ResolutionStatus.ERROR,
                    cname_chain=chain, error_detail=f"CNAME loop detected at {cname_target}",
                )
            visited.add(cname_target)
            chain.append(cname_target)
            current = cname_target
        else:
            return ResolutionResult(
                hostname, ResolutionStatus.ERROR, cname_chain=chain,
                error_detail=f"CNAME chain exceeded {max_chain_depth} hops",
            )

        ips, err = self._query_a(current)
        if err == "nxdomain":
            if chain:
                return ResolutionResult(
                    hostname, ResolutionStatus.DANGLING_CNAME,
                    cname_chain=chain, cname_target=chain[-1],
                )
            return ResolutionResult(hostname, ResolutionStatus.NXDOMAIN)
        if err == "timeout":
            return ResolutionResult(hostname, ResolutionStatus.TIMEOUT, cname_chain=chain)
        if err == "no_record":
            if chain:
                return ResolutionResult(
                    hostname, ResolutionStatus.CNAME,
                    cname_chain=chain, cname_target=chain[-1],
                )
            return ResolutionResult(hostname, ResolutionStatus.NO_RECORD)
        if err == "error":
            return ResolutionResult(
                hostname, ResolutionStatus.ERROR, cname_chain=chain,
                error_detail="A record lookup failed",
            )

        if self._is_wildcard_match(hostname, ips):
            return ResolutionResult(hostname, ResolutionStatus.WILDCARD, a_records=ips, cname_chain=chain)

        if chain:
            return ResolutionResult(
                hostname, ResolutionStatus.CNAME,
                cname_chain=chain, cname_target=chain[-1], a_records=ips,
            )
        return ResolutionResult(hostname, ResolutionStatus.A_RECORD, a_records=ips)

    def _query_cname(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            answer = self.resolver.resolve(hostname, "CNAME")
            return str(answer[0].target).rstrip(".").lower(), None
        except dns.resolver.NoAnswer:
            return None, None
        except dns.resolver.NXDOMAIN:
            return None, "nxdomain"
        except dns.exception.Timeout:
            return None, "timeout"
        except Exception:
            return self._socket_cname(hostname)

    def _query_a(self, hostname: str) -> Tuple[List[str], Optional[str]]:
        try:
            answer = self.resolver.resolve(hostname, "A")
            return [str(r) for r in answer], None
        except dns.resolver.NXDOMAIN:
            return [], "nxdomain"
        except dns.resolver.NoAnswer:
            return self._socket_a(hostname)
        except dns.exception.Timeout:
            return [], "timeout"
        except Exception:
            return self._socket_a(hostname)

    def _socket_cname(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            self.resolver.resolve(hostname, "CNAME")
        except dns.resolver.NoAnswer:
            return None, None
        except dns.resolver.NXDOMAIN:
            return None, "nxdomain"
        except dns.exception.Timeout:
            return None, "timeout"
        except Exception:
            return None, "error"
        return None, None

    def _socket_a(self, hostname: str) -> Tuple[List[str], Optional[str]]:
        try:
            _, _, addrs = socket.gethostbyname_ex(hostname)
            if addrs:
                return addrs, None
            return [], "no_record"
        except socket.gaierror as e:
            code = e.args[0] if e.args else 0
            if code in (socket.EAI_NONAME, 8):  # NXDOMAIN / NAME OR SERVICE NOT KNOWN
                return [], "nxdomain"
            if code in (socket.EAI_NODATA, 7):
                return [], "no_record"
            return [], "error"
        except socket.timeout:
            return [], "timeout"
        except OSError:
            return [], "error"

    def _is_wildcard_match(self, hostname: str, ips: List[str]) -> bool:
        if not self._wildcard_ips or not self._wildcard_domain:
            return False
        parts = hostname.lower().strip(".").split(".")
        domain_parts = self._wildcard_domain.split(".")
        if len(parts) <= len(domain_parts):
            return False
        if ".".join(parts[-len(domain_parts):]) != self._wildcard_domain:
            return False
        return bool(self._wildcard_ips & set(ips))

    def resolve_many(self, hostnames: List[str]) -> List[ResolutionResult]:
        results: List[ResolutionResult] = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for h in hostnames:
                    try:
                        futures[executor.submit(self.resolve_one, h)] = h
                    except RuntimeError:
                        results.append(ResolutionResult(
                            hostname=h,
                            status=ResolutionStatus.ERROR,
                            error_detail="scheduler unavailable",
                        ))
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
        except RuntimeError:
            resolved_hosts = {r.hostname for r in results}
            for h in hostnames:
                if h not in resolved_hosts:
                    results.append(ResolutionResult(
                        hostname=h,
                        status=ResolutionStatus.ERROR,
                        error_detail="scheduler unavailable",
                    ))
        return results

    @staticmethod
    def categorize(results: List[ResolutionResult]) -> Dict[ResolutionStatus, List[ResolutionResult]]:
        buckets: Dict[ResolutionStatus, List[ResolutionResult]] = {s: [] for s in ResolutionStatus}
        for r in results:
            buckets[r.status].append(r)
        return buckets

    def categorize_results(self, results: List[ResolutionResult]) -> Dict[ResolutionStatus, List[ResolutionResult]]:
        """Instance wrapper so callers (and mocks) can categorize via the resolver object."""
        return self.categorize(results)


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else [
        "www.github.com",
        "google.com",
        "this-should-not-exist-rimscan-test.com",
        "totally-fake-xyz123.github.com",
    ]
    resolver = DNSResolver()
    if len(sys.argv) > 1:
        resolver.detect_wildcard(".".join(sys.argv[1].split(".")[-2:]))
    print(f"[*] Resolving {len(targets)} hostnames...")
    results = resolver.resolve_many(targets)
    buckets = DNSResolver.categorize(results)
    for status, items in buckets.items():
        if items:
            print(f"\n[{status.value.upper()}] ({len(items)})")
            for r in items:
                print(f"  {r}")