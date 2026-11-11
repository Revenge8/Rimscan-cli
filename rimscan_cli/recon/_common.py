"""Small helpers shared by the recon modules, the scanner and the CLI."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

__all__ = [
    "HOST_LABEL",
    "all_public",
    "is_public_address",
    "is_valid_hostname",
    "normalize_domain",
    "normalize_name",
]

HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalize_name(name: str) -> str:
    """Lowercase a DNS name and strip whitespace and leading/trailing dots."""
    return name.strip().lower().strip(".")


def is_valid_hostname(name: str) -> bool:
    """True if every label is a valid LDH label and the whole name fits in 253 characters."""
    return len(name) <= 253 and all(HOST_LABEL.fullmatch(label) for label in name.split("."))


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII hostname, or raise ValueError if `value` is not a domain name."""
    domain = value.strip().lower().rstrip(".")
    if not domain or any(char in domain for char in "/:@ ?#"):
        raise ValueError("domain must be a bare hostname such as example.com (no scheme, path, port or user)")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not supported; pass a domain name")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"{value!r} is not a valid domain name") from None
    if len(domain.split(".")) < 2 or not is_valid_hostname(domain):
        raise ValueError(f"{value!r} is not a valid domain name")
    return domain


def is_public_address(value: str) -> bool:
    """True for a globally routable IP address (not loopback, private, link-local, ...)."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def all_public(addresses: Iterable[str]) -> bool:
    """True if there is at least one address and every one of them is globally routable."""
    addresses = list(addresses)
    return bool(addresses) and all(is_public_address(address) for address in addresses)
