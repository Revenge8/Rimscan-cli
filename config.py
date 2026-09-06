"""Small, database-free configuration helpers for the standalone CLI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union

TimeoutValue = Union[int, float, Tuple[float, float]]


@dataclass
class ScanConfig:
    """Runtime settings used by the passive recon modules."""

    domain: str = ""
    http_timeout: TimeoutValue = (10.0, 30.0)
    max_retries: int = 3
    backoff_factor: float = 1.0

    @staticmethod
    def normalize_timeout(timeout: TimeoutValue) -> Tuple[float, float]:
        if isinstance(timeout, (int, float)):
            return (float(timeout), float(timeout))
        return timeout

