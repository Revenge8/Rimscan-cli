"""Shared HTTP session: one honest User-Agent and one retry policy."""

from __future__ import annotations

import re

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rimscan_cli import __version__

USER_AGENT = f"rimscan-cli/{__version__} (+https://rimscan.cloud)"

_CHARSET = re.compile(r"charset=\s*[\"']?([\w.:-]+)", re.IGNORECASE)


def make_session(retries: int = 2) -> requests.Session:
    """Build a session. Pass ``retries=0`` when each request must be sent at most once.

    A server-supplied ``Retry-After`` header is ignored: urllib3 would sleep for as long as
    the server asks (the request timeout does not cover that sleep), so a scanned host could
    stall a worker thread for hours. Retries use the short exponential backoff instead.
    """
    retry = Retry(
        total=retries,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
        respect_retry_after_header=False,
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.max_redirects = 5
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _declared_charset(response: requests.Response) -> str:
    """Charset from the Content-Type header, or UTF-8.

    ``response.encoding`` is not used: for ``text/*`` without a charset, requests guesses
    ISO-8859-1, which garbles the non-Latin fingerprints and secrets we match against.
    """
    headers = getattr(response, "headers", None) or {}
    match = _CHARSET.search(headers.get("Content-Type", ""))
    return match.group(1).strip("\"'") if match else "utf-8"


def read_capped(response: requests.Response, limit: int) -> str:
    """Read at most `limit` bytes of a streamed response and decode them."""
    body = bytearray()
    for chunk in response.iter_content(chunk_size=16 * 1024):
        body.extend(chunk)
        if len(body) >= limit:
            break
    response.close()
    data = bytes(body[:limit])
    try:
        return data.decode(_declared_charset(response), errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")
