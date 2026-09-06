"""Secrets and credential exposure scanner."""

from __future__ import annotations

import math
import re
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Pattern, Tuple, Union

import requests

logger = logging.getLogger(__name__)

__all__ = ["SecretFinding", "SecretScanner", "SecretsScanner", "SECRET_PATTERNS"]

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
    "/robots.txt",
)


SECRET_PATTERNS: Dict[str, Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "github_token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "stripe_key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\."),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}


@dataclass
class SecretFinding:
    secret_type: str
    match: str
    source: str
    line_number: Optional[int] = None
    entropy: float = 0.0
    verified: Optional[bool] = None
    context: str = ""

    def redacted_match(self) -> str:
        if len(self.match) <= 8:
            return "***"
        return f"{self.match[:4]}...{self.match[-4:]}"


class SecretScanner:
    """Pattern-based secret detection with optional entropy scoring."""

    def __init__(
        self,
        min_entropy: float = 4.5,
        timeout: Union[int, float, Tuple[float, float]] = (10, 30),
        authorized: bool = False,
    ):
        self.min_entropy = min_entropy
        self.timeout = timeout
        self.authorized = authorized
        self.patterns = dict(SECRET_PATTERNS)
        self._session = requests.Session()

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def scan_text(self, text: str, source: str = "unknown") -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for secret_type, pattern in self.patterns.items():
                for match in pattern.finditer(line):
                    value = match.group(0)
                    entropy = self.shannon_entropy(value)
                    if secret_type == "aws_secret_key" and entropy < self.min_entropy:
                        continue
                    findings.append(
                        SecretFinding(
                            secret_type=secret_type,
                            match=value,
                            source=source,
                            line_number=line_no,
                            entropy=round(entropy, 2),
                            context=line.strip()[:120],
                        )
                    )
        return findings

    def scan_files(self, paths: Iterable[str]) -> List[SecretFinding]:
        all_findings: List[SecretFinding] = []
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    all_findings.extend(self.scan_text(f.read(), source=path))
            except OSError as e:
                logger.error("Could not read secret-scan input %s (%s)", path, type(e).__name__)
                logger.debug("Secret-scan input failure details", exc_info=True)
        return all_findings

    def scan_response_body(self, body: str, url: str) -> List[SecretFinding]:
        return self.scan_text(body, source=url)

    def scan_domain(self, domain: str, hosts: Optional[List[str]] = None) -> List[SecretFinding]:
        """Fetch common paths on apex/www and scan response bodies for secrets."""
        if not self.authorized:
            raise PermissionError(
                "SecretScanner requires authorized=True — this method sends live "
                "requests to the target's endpoints and must not run against a "
                "domain without explicit permission to test it."
            )
        domain = domain.lower().strip(".")
        hosts = hosts or [domain, f"www.{domain}"]
        findings: List[SecretFinding] = []

        for host in hosts:
            for path in COMMON_PATHS:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}{path}"
                    try:
                        resp = self._session.get(url, timeout=self.timeout, allow_redirects=True)
                        if resp.status_code >= 400:
                            continue
                        findings.extend(self.scan_response_body(resp.text, url))
                        break
                    except requests.RequestException:
                        continue
        return findings

    def scan(self, domain: str) -> List[SecretFinding]:
        """Alias used by CLI/API."""
        return self.scan_domain(domain)


class SecretsScanner(SecretScanner):
    """Backward-compatible alias for SecretScanner."""
