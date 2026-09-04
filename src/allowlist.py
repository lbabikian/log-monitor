"""
src/allowlist.py
Source-IP allowlisting, applied as a pipeline stage between parsing and
detection:

    log source -> parser -> Event -> [allowlist] -> detector -> alert -> sink

Filtering here rather than inside each detector means a new rule inherits
allowlisting for free, and detectors stay concerned only with detection.

Entries are single addresses or CIDR ranges, IPv4 or IPv6:

    10.0.0.0/8
    192.168.1.5
    2001:db8::/32

Blank lines and `#` comments are ignored, so the same syntax works for a
--allow flag and for an --allow-file.
"""

import ipaddress
from typing import Iterable, List, Optional

from .models import Event


class AllowlistError(ValueError):
    """Raised when an allowlist entry cannot be parsed."""


class Allowlist:
    """A set of trusted source networks. Empty by default, which allows nothing."""

    def __init__(self, entries: Iterable[str] = ()):
        self.networks: List[ipaddress._BaseNetwork] = []
        for raw in entries:
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                # strict=False so a bare host address is accepted as a /32 or /128.
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise AllowlistError(f"invalid allowlist entry {entry!r}: {exc}") from exc

    @classmethod
    def from_file(cls, path: str) -> "Allowlist":
        """One entry per line. Comments and blank lines are ignored."""
        with open(path, "r", encoding="utf-8") as fh:
            return cls(fh.readlines())

    def __bool__(self) -> bool:
        return bool(self.networks)

    def __len__(self) -> int:
        return len(self.networks)

    def contains(self, ip: Optional[str]) -> bool:
        """True if ip falls inside any allowlisted network."""
        if not ip or not self.networks:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Unparseable address: not allowlisted, so it still reaches the
            # detectors. Failing open here would be a silent detection gap.
            return False
        return any(addr in net for net in self.networks)

    def permits(self, ev: Event) -> bool:
        """True if this event should be passed on to the detectors."""
        return not self.contains(ev.src_ip)
