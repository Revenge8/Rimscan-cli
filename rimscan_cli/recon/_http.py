"""Shared HTTP session: one honest User-Agent and one retry policy."""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rimscan_cli import __version__

USER_AGENT = f"rimscan-cli/{__version__} (+https://rimscan.cloud)"


def make_session(retries: int = 2) -> requests.Session:
    retry = Retry(
        total=retries,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.max_redirects = 5
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def read_capped(response: requests.Response, limit: int) -> str:
    """Read at most `limit` bytes of a streamed response and decode them."""
    body = bytearray()
    for chunk in response.iter_content(chunk_size=16 * 1024):
        body.extend(chunk)
        if len(body) >= limit:
            break
    response.close()
    return bytes(body[:limit]).decode(response.encoding or "utf-8", errors="replace")
