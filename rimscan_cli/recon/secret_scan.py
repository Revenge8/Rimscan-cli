"""Detect credentials exposed in publicly served files."""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Pattern, Set, Tuple

import requests

from rimscan_cli.recon._http import make_session, read_capped

__all__ = ["SecretFinding", "SecretScanner", "SECRET_PATTERNS", "COMMON_PATHS"]

logger = logging.getLogger(__name__)

COMMON_PATHS = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.js",
    "/app.js",
    "/main.js",
    "/static/js/main.js",
    "/assets/env.js",
    "/api/config",
)

# Config-style files are never legitimately served as HTML; an HTML answer is a soft 404.
_NON_HTML_PATHS = {"/.env", "/.env.local", "/.env.production"}
_MAX_BODY_BYTES = 1024 * 1024
_CONTEXT_RADIUS = 40
_AWS_CONTEXT_RADIUS = 80

SECRET_PATTERNS: Dict[str, Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "stripe_live_key": re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}

# A bare 40-character base64 string is too common (hashes, build ids) to report alone.
_AWS_SECRET_CONTEXT = re.compile(r"aws|secret", re.IGNORECASE)

Span = Tuple[int, int]


def _redact(value: str) -> str:
    return "***" if len(value) <= 8 else f"{value[:4]}...{value[-4:]}"


def _merge_spans(spans: Iterable[Span]) -> List[Span]:
    merged: List[Span] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _redacted_window(line: str, start: int, end: int, spans: List[Span]) -> str:
    """Text around a match with every credential on the line redacted.

    The window never cuts through a credential: if an edge lands inside one, the window
    grows to include it whole, so no fragment of a secret is left unredacted.
    """
    low = max(0, start - _CONTEXT_RADIUS)
    high = min(len(line), end + _CONTEXT_RADIUS)
    for span_start, span_end in spans:
        if span_start < low < span_end:
            low = span_start
        if span_start < high < span_end:
            high = span_end
    parts: List[str] = []
    position = low
    for span_start, span_end in spans:
        if span_end <= low or span_start >= high:
            continue
        parts.append(line[position:span_start])
        parts.append(_redact(line[span_start:span_end]))
        position = span_end
    parts.append(line[position:high])
    return "".join(parts).strip()


@dataclass
class SecretFinding:
    secret_type: str
    source: str
    line_number: Optional[int] = None
    entropy: float = 0.0
    # The raw value is kept out of repr() and to_dict() on purpose; `context` is built
    # already redacted by the scanner and is redacted again on output as a second layer.
    match: str = field(default="", repr=False)
    context: str = field(default="", repr=False)

    def redacted_match(self) -> str:
        return _redact(self.match)

    def redacted_context(self) -> str:
        text = self.context
        for pattern in SECRET_PATTERNS.values():
            text = pattern.sub(lambda m: _redact(m.group()), text)
        return text

    def to_dict(self) -> dict:
        return {
            "secret_type": self.secret_type,
            "match": self.redacted_match(),
            "source": self.source,
            "line_number": self.line_number,
            "entropy": self.entropy,
            "context": self.redacted_context(),
        }


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in Counter(data).values())


class SecretScanner:
    def __init__(
        self,
        min_entropy: float = 4.5,
        timeout: Tuple[float, float] = (5.0, 10.0),
        max_workers: int = 8,
    ):
        self.min_entropy = min_entropy
        self.timeout = timeout
        self.max_workers = max_workers
        self._session = make_session(retries=1)

    def scan_text(self, text: str, source: str = "unknown") -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            hits: List[Tuple[int, int, str, str, float]] = []
            for secret_type, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(line):
                    value = match.group(0)
                    entropy = shannon_entropy(value)
                    if secret_type == "aws_secret_key":
                        nearby = line[max(0, match.start() - _AWS_CONTEXT_RADIUS):match.end() + _AWS_CONTEXT_RADIUS]
                        if entropy < self.min_entropy or not _AWS_SECRET_CONTEXT.search(nearby):
                            continue
                    hits.append((match.start(), match.end(), secret_type, value, entropy))
            if not hits:
                continue
            spans = _merge_spans((start, end) for start, end, *_ in hits)
            for start, end, secret_type, value, entropy in hits:
                findings.append(
                    SecretFinding(
                        secret_type, source, line_no, round(entropy, 2),
                        match=value, context=_redacted_window(line, start, end, spans),
                    )
                )
        return findings

    def scan_domain(self, hosts: Iterable[str], max_hosts: int = 50) -> List[SecretFinding]:
        """Fetch a fixed list of well-known paths on each host and scan the responses.

        Sends up to len(COMMON_PATHS) GET requests per host (HTTP only if HTTPS fails to
        connect). Redirects are not followed. At most `max_hosts` hosts are scanned; a
        warning is logged when the list is longer. A response body is reported once per
        host, so soft-404 pages do not repeat, but the same leak on two hosts is
        reported for both. Callers must have permission to test every host passed in.
        """
        host_list = list(dict.fromkeys(hosts))
        if len(host_list) > max_hosts:
            logger.warning("Secret scan limited to %d of %d hosts", max_hosts, len(host_list))
            host_list = host_list[:max_hosts]
        urls = [(host, path) for host in host_list for path in COMMON_PATHS]
        seen_bodies: Set[Tuple[str, str]] = set()
        findings: List[SecretFinding] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for host, url, body in pool.map(lambda hp: (hp[0], *self._fetch(*hp)), urls):
                if body is None:
                    continue
                digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
                if (host, digest) in seen_bodies:
                    continue
                seen_bodies.add((host, digest))
                findings.extend(self.scan_text(body, source=url))
        return findings

    def _fetch(self, host: str, path: str) -> Tuple[str, Optional[str]]:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}{path}"
            try:
                response = self._session.get(
                    url, timeout=self.timeout, stream=True, allow_redirects=False
                )
            except requests.RequestException:
                continue
            if response.status_code >= 400:
                response.close()
                return url, None
            if path in _NON_HTML_PATHS and "html" in response.headers.get("Content-Type", "").lower():
                response.close()
                return url, None
            return url, read_capped(response, _MAX_BODY_BYTES)
        return f"https://{host}{path}", None
