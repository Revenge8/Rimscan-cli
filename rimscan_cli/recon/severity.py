"""Severity levels shared by every audit module."""

from __future__ import annotations

from enum import Enum

__all__ = ["Severity"]


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
