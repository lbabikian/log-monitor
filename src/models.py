"""
src/models.py
Defines the canonical event model used by detectors and parsers
"""

from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict

# Enum for diff event types
class Kind(str, Enum):
    AUTH_FAIL = "auth.fail"
    AUTH_SUCCESS = "auth.success"
    HTTP_404 = "http.404"

# Dataclass for actual log events
@dataclass(frozen=True)
class Event:
    """
    Represents a parsed log event.
    Attributes:
        ts: Event timestamp (timezone-aware if possible)
        src_ip: Source IP address (e.g., attacker)
        dst_ip: Destination IP (e.g., host being attacked)
        kind: Event type (auth.fail, auth.success, etc.)
        meta: Arbitrary metadata (username, service, etc.)
    """
    ts: datetime
    src_ip: Optional[str]
    dst_ip: Optional[str]
    kind: Kind               
    meta: Dict[str, str]