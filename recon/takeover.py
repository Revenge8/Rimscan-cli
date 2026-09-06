"""Subdomain takeover detection using EdOverflow fingerprints database."""

from __future__ import annotations
import json
import sys
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

from recon.resolver import ResolutionResult, ResolutionStatus

__all__ = [
    "TakeoverVerdict",
    "TakeoverFinding",
    "FingerprintDatabase",
    "TakeoverDetector",
]

REMOTE_FINGERPRINTS_URL = (
    "https://raw.githubusercontent.com/EdOverflow/"
    "can-i-take-over-xyz/master/fingerprints.json"
)
LOCAL_FINGERPRINTS_PATH = Path(__file__).resolve().parents[1] / "data" / "fingerprints.json"
FINGERPRINTS_URL = str(LOCAL_FINGERPRINTS_PATH)

# Fingerprint strings too generic to prove anything when matched by body
# text alone (no CNAME suffix to anchor them to a specific service). Some
# fingerprints.json entries use plain HTTP error phrasing that an ordinary
# server could produce for completely unrelated reasons — e.g. Cargo
# Collective and Fly.io both use the literal string "404 Not Found".
GENERIC_FINGERPRINTS = {
    "404 not found",
    "not found",
    "page not found",
    "site not found",
    "web site not found",
    "no site for domain",
}


class TakeoverVerdict(Enum):
    VULNERABLE = "vulnerable"
    LIKELY = "likely"
    NOT_VULNERABLE = "not_vulnerable"
    UNKNOWN_SERVICE = "unknown_service"
    HISTORICAL_CANDIDATE = "historical_candidate"
@dataclass
class TakeoverFinding:
    hostname: str
    verdict: TakeoverVerdict
    service: Optional[str] = None
    cname_chain: List[str] = field(default_factory=list)
    evidence: str = ""

    def __repr__(self) -> str:
        svc = f" ({self.service})" if self.service else ""
        return f"<{self.hostname} [{self.verdict.value.upper()}]{svc}: {self.evidence}>"


class FingerprintDatabase:
    def __init__(self, url: str = FINGERPRINTS_URL, timeout: int = 10):
        self.entries: List[dict] = []
        self.unmatchable_services: List[str] = []
        self._suffix_map: List[Tuple[str, dict]] = []
        self._load(url, timeout)

    def _load(self, url: str, timeout: int) -> None:
        sources: list[str] = []
        if url.startswith(("http://", "https://")):
            sources = [url, str(LOCAL_FINGERPRINTS_PATH)]
        else:
            local_path = Path(url)
            if not local_path.is_absolute():
                local_path = (Path.cwd() / local_path).resolve()
            sources = [str(local_path), str(LOCAL_FINGERPRINTS_PATH), REMOTE_FINGERPRINTS_URL]

        last_error: Exception | None = None
        for source in sources:
            try:
                if source.startswith(("http://", "https://")):
                    resp = requests.get(source, timeout=timeout)
                    resp.raise_for_status()
                    self.entries = resp.json()
                else:
                    path = Path(source)
                    if not path.exists():
                        continue
                    self.entries = json.loads(path.read_text(encoding="utf-8"))
                break
            except (requests.RequestException, ValueError, OSError) as e:
                last_error = e
                continue
        else:
            logger.error("Could not load takeover fingerprints (%s)", type(last_error).__name__ if last_error else "unknown")
            logger.debug("Takeover fingerprint load failure details", exc_info=True)
            print("[!] Could not load fingerprints database")
            return

        for entry in self.entries:
            cnames = entry.get("cname", [])
            if not cnames:
                self.unmatchable_services.append(entry.get("service", "?"))
                continue
            for cname in cnames:
                self._suffix_map.append((cname.lower().lstrip("."), entry))
        self._suffix_map.sort(key=lambda pair: len(pair[0]), reverse=True)

    def match(self, hostname: str) -> Optional[dict]:
        hostname = hostname.lower().rstrip(".")
        for suffix, entry in self._suffix_map:
            if hostname == suffix or hostname.endswith("." + suffix):
                return entry
        return None


class TakeoverDetector:
    """Detect subdomain takeover candidates; require CNAME + HTTP match for VULNERABLE."""

    def __init__(self, fingerprint_db: FingerprintDatabase, timeout: int = 10):
        self.db = fingerprint_db
        self.timeout = timeout
        self._session = requests.Session()

    def check_and_verify(self, result: ResolutionResult, verifier=None) -> Optional[TakeoverFinding]:
        """Like check(), but layers an active read-only existence check on
        top of the fingerprint-only verdict, so callers can distinguish
        "matches a vulnerable fingerprint" (recall-oriented) from "confirmed
        unclaimed right now" (precision-oriented).

        `verifier` is a recon.verify.ServiceVerifier (or anything exposing
        the same `.verify(service, **kwargs)` interface). Passed in rather
        than imported directly so this module doesn't require the boto3/
        verify.py dependency chain when only doing fingerprint detection.
        """
        finding = self.check(result)
        if finding is None:
            return None

        if verifier is None or finding.verdict not in (
            TakeoverVerdict.VULNERABLE,
            TakeoverVerdict.LIKELY,
        ):
            return finding

        service = (finding.service or "").lower()
        verify_key = next((v for k, v in _VERIFIABLE_SERVICES.items() if k in service), None)
        if verify_key is None:
            return TakeoverFinding(
                hostname=finding.hostname,
                verdict=TakeoverVerdict.UNVERIFIED_MANUAL,
                service=finding.service,
                cname_chain=finding.cname_chain,
                evidence=f"{finding.evidence}; no active verifier available for this service",
            )

        host = finding.hostname.split(".")[0]
        chain = finding.cname_chain or []
        kwargs: dict = {}

        if verify_key == "azure":
            if not chain:
                return TakeoverFinding(
                    finding.hostname, TakeoverVerdict.UNVERIFIED_MANUAL, finding.service,
                    chain, f"{finding.evidence}; no CNAME chain available to derive storage account",
                )
            parts = chain[-1].split(".")
            if len(parts) < 3 or "blob" not in parts:
                return TakeoverFinding(
                    finding.hostname, TakeoverVerdict.UNVERIFIED_MANUAL, finding.service,
                    chain, f"{finding.evidence}; could not derive Azure storage account from chain",
                )
            kwargs = {"account_name": parts[0], "container_name": host}
        elif verify_key == "github":
            username = chain[-1].split(".")[0] if chain else host
            kwargs = {"username": username}
        elif verify_key in ("aws/s3", "google cloud storage"):
            kwargs = {"bucket_name": host}
        else:  # heroku, digitalocean
            kwargs = {"app_name": host}

        try:
            verified = verifier.verify(verify_key, **kwargs)
        except Exception as e:
            return TakeoverFinding(
                finding.hostname, TakeoverVerdict.UNVERIFIED_MANUAL, finding.service,
                chain, f"{finding.evidence}; active verification errored: {e}",
            )

        if verified is True:
            return TakeoverFinding(
                finding.hostname, TakeoverVerdict.VERIFIED_VULNERABLE, finding.service,
                chain, f"{finding.evidence}; active check confirms target name is currently unclaimed",
            )
        if verified is False:
            return TakeoverFinding(
                finding.hostname, TakeoverVerdict.FALSE_POSITIVE, finding.service,
                chain, f"{finding.evidence}; active check found target name already claimed/private",
            )
        return TakeoverFinding(
            finding.hostname, TakeoverVerdict.UNVERIFIED_MANUAL, finding.service,
            chain, f"{finding.evidence}; active check was inconclusive, needs manual review",
        )

    def check(self, result: ResolutionResult) -> Optional[TakeoverFinding]:
        if result.status is ResolutionStatus.WILDCARD:
            return None

        if result.status is ResolutionStatus.NXDOMAIN and result.historical_cnames:
            return TakeoverFinding(
                hostname=result.hostname,
                verdict=TakeoverVerdict.HISTORICAL_CANDIDATE,
                evidence=(
                    "currently NXDOMAIN but appeared in passive sources "
                    f"before ({', '.join(result.historical_cnames)}) — needs manual check"
                ),
            )

        if result.status not in (
            ResolutionStatus.CNAME,
            ResolutionStatus.DANGLING_CNAME,
            ResolutionStatus.A_RECORD,
        ):
            return None

        chain = result.cname_chain or ([result.cname_target] if result.cname_target else [])

        if result.status is ResolutionStatus.A_RECORD:
            return self._check_via_homepage_fingerprint(result.hostname)

        if not chain:
            return None

        entry = None
        matched_hop = ""
        for hop in reversed(chain):
            entry = self.db.match(hop)
            if entry:
                matched_hop = hop
                break

        if entry is None:
            if result.status is ResolutionStatus.DANGLING_CNAME:
                return TakeoverFinding(
                    hostname=result.hostname,
                    verdict=TakeoverVerdict.LIKELY,
                    cname_chain=chain,
                    evidence="dangling CNAME chain, target service not in fingerprint database",
                )
            return self._check_via_homepage_fingerprint(result.hostname, chain)

        service_name = entry.get("service", "unknown")

        if not entry.get("vulnerable", False):
            return TakeoverFinding(
                hostname=result.hostname,
                verdict=TakeoverVerdict.NOT_VULNERABLE,
                service=service_name,
                cname_chain=chain,
                evidence=f"matched {service_name}, not marked vulnerable in fingerprints.json",
            )

        if entry.get("nxdomain") and result.status is ResolutionStatus.DANGLING_CNAME:
            return TakeoverFinding(
                hostname=result.hostname,
                verdict=TakeoverVerdict.VULNERABLE,
                service=service_name,
                cname_chain=chain,
                evidence=(
                    f"CNAME -> {matched_hop} NXDOMAIN, matches known-vulnerable NXDOMAIN fingerprint"
                ),
            )

        fingerprint_text = entry.get("fingerprint")
        if fingerprint_text and fingerprint_text != "NXDOMAIN":
            return self._check_http_fingerprint(
                result.hostname,
                service_name,
                chain,
                fingerprint_text,
                entry.get("http_status"),
                require_cname=True,
            )

        return TakeoverFinding(
            hostname=result.hostname,
            verdict=TakeoverVerdict.LIKELY,
            service=service_name,
            cname_chain=chain,
            evidence=f"matched vulnerable service {service_name}, needs manual review",
        )

    def _check_http_fingerprint(
        self,
        hostname: str,
        service_name: str,
        chain: List[str],
        fingerprint_text: str,
        expected_status: Optional[int],
        require_cname: bool = False,
    ) -> TakeoverFinding:
        reached = False
        for scheme in ("https://", "http://"):
            try:
                resp = self._session.get(
                    f"{scheme}{hostname}", timeout=self.timeout, allow_redirects=True
                )
            except requests.RequestException:
                continue

            reached = True
            body_match = fingerprint_text.lower() in resp.text.lower()
            status_match = expected_status is None or resp.status_code == expected_status

            if body_match and status_match:
                verdict = (
                    TakeoverVerdict.VULNERABLE
                    if require_cname and chain
                    else TakeoverVerdict.LIKELY
                )
                return TakeoverFinding(
                    hostname=hostname,
                    verdict=verdict,
                    service=service_name,
                    cname_chain=chain,
                    evidence=f"HTTP {resp.status_code} body matched {service_name}'s fingerprint",
                )
            if body_match and not status_match:
                return TakeoverFinding(
                    hostname=hostname,
                    verdict=TakeoverVerdict.LIKELY,
                    service=service_name,
                    cname_chain=chain,
                    evidence=f"fingerprint matched but status {resp.status_code} != expected {expected_status}",
                )

        if reached:
            return TakeoverFinding(
                hostname=hostname,
                verdict=TakeoverVerdict.NOT_VULNERABLE,
                service=service_name,
                cname_chain=chain,
                evidence=f"service identified as {service_name} but page doesn't match fingerprint",
            )

        return TakeoverFinding(
            hostname=hostname,
            verdict=TakeoverVerdict.UNKNOWN_SERVICE,
            service=service_name,
            cname_chain=chain,
            evidence="could not reach host over HTTP/HTTPS to verify",
        )

    def _check_via_homepage_fingerprint(
        self, hostname: str, chain: Optional[List[str]] = None
    ) -> Optional[TakeoverFinding]:
        """For services without CNAME suffixes (Akamai, Fastly, Firebase, etc.)."""
        chain = chain or []
        body = None
        status_code = None
        for scheme in ("https://", "http://"):
            try:
                resp = self._session.get(
                    f"{scheme}{hostname}", timeout=self.timeout, allow_redirects=True
                )
                body = resp.text.lower()
                status_code = resp.status_code
                break
            except requests.RequestException:
                continue

        if body is None:
            return None

        for entry in self.db.entries:
            if not entry.get("vulnerable"):
                continue
            fp = entry.get("fingerprint", "")
            expected_status = entry.get("http_status")
            if not fp or fp == "NXDOMAIN":
                continue
            if fp.lower() in GENERIC_FINGERPRINTS:
                continue
            if fp.lower() not in body:
                continue
            if expected_status is not None and status_code != expected_status:
                continue
            specific_enough = len(fp) >= 15
            return TakeoverFinding(
                hostname=hostname,
                verdict=TakeoverVerdict.VULNERABLE if specific_enough else TakeoverVerdict.LIKELY,
                service=entry.get("service"),
                cname_chain=chain,
                evidence=(
                    f"homepage body matched {entry.get('service')}'s fingerprint "
                    "(no CNAME suffix available)"
                ),
            )
        return None


if __name__ == "__main__":
    from recon.resolver import DNSResolver

    db = FingerprintDatabase()
    print(f"[*] Loaded {len(db.entries)} fingerprint entries")
    usable = len(db.entries) - len(db.unmatchable_services)
    print(f"[*] {len(db._suffix_map)} usable CNAME suffixes across {usable} services")
    print(f"[*] {len(db.unmatchable_services)} services require homepage fingerprint only")

    detector = TakeoverDetector(db)
    resolver = DNSResolver()

    targets = sys.argv[1:] if len(sys.argv) > 1 else ["shop.github.com", "www.reddit.com"]
    for host in targets:
        result = resolver.resolve_one(host)
        finding = detector.check(result)
        print(f"\n{result}")
        print(f"  -> {finding if finding else 'no takeover-relevant finding'}") 