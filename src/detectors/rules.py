"""
src/detectors/rules.py
Detection rules. Each rule consumes Events and returns an alert dict or None.

Two rules ship today, deliberately covering the two halves of the brute-force
problem:

    FailedLoginBurst  one IP against one host        ATT&CK T1110.001
    FailedLoginSpray  many IPs against one account   ATT&CK T1110.003 / .004

Both share the same sliding-window primitive and the same de-spam gate.
See DESIGN.md for why the thresholds are what they are.
"""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Optional, Tuple

from ..models import Event, Kind


class _AlertGate:
    """
    Shared de-spam gate.

    A detector that fires on every event past its threshold produces an alert
    stream nobody can triage. This gate answers one question - "should this
    count produce an alert?" - and owns the state needed to answer it.

    threshold: count at which the first alert fires
    step:      if set, re-alert every +step past the threshold;
               if None, alert once per burst and stay silent until reset()

    reset() is the important half. Without it, a key that once crossed the
    threshold stays permanently gated, so a second burst from the same IP is
    silently swallowed. Callers must reset() whenever a key's count falls back
    below the threshold.
    """

    def __init__(self, threshold: int, step: Optional[int] = None):
        self.threshold = threshold
        self.step = step
        self._last: Dict[str, int] = {}

    def reset(self, key: str) -> None:
        """The burst decayed. Re-arm so the next crossing counts as new."""
        self._last.pop(key, None)

    def should_fire(self, key: str, count: int) -> bool:
        prev = self._last.get(key)
        if prev is None:
            # First crossing for this key since the last reset.
            fire = True
        elif self.step:
            # Re-alert on threshold, threshold+step, threshold+2*step, ...
            fire = (count - self.threshold) % self.step == 0 and count != prev
        else:
            # One alert per burst. reset() is what re-arms this.
            fire = False
        self._last[key] = count
        return fire


class FailedLoginBurst:
    """
    Detects N or more failed auth attempts from the same source IP inside a
    sliding window - the classic single-source brute-force pattern.

    ATT&CK T1110.001 (Brute Force: Password Guessing).

    window_seconds: size of the sliding time window
    threshold:      failures inside that window required to alert
    step:           re-alert every +step further failures; None = once per burst
    """

    rule = "auth_failed_burst"

    def __init__(
        self,
        window_seconds: int = 60,
        threshold: int = 5,
        step: Optional[int] = None,
    ):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.step = step
        self.by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.gate = _AlertGate(threshold, step)

    def _trim(self, ip: str, now_ts: datetime) -> Deque[datetime]:
        dq = self.by_ip[ip]
        while dq and (now_ts - dq[0]) > self.window:
            dq.popleft()
        return dq

    def handle(self, ev: Event) -> Optional[dict]:
        # Only failed auth events that carry a source IP are in scope.
        if ev.kind is not Kind.AUTH_FAIL or not ev.src_ip:
            return None

        ip = ev.src_ip
        self.by_ip[ip].append(ev.ts)
        dq = self._trim(ip, ev.ts)

        count = len(dq)
        if count < self.threshold:
            # The burst has decayed below the threshold. Re-arm the gate so a
            # later burst from this same IP alerts again, and drop the key
            # entirely if nothing is left in its window.
            self.gate.reset(ip)
            if not dq:
                self.by_ip.pop(ip, None)
            return None

        if not self.gate.should_fire(ip, count):
            return None

        window_s = int(self.window.total_seconds())
        return {
            "rule": self.rule,
            "ip": ip,
            "count": count,
            "window_seconds": window_s,
            "user": (ev.meta or {}).get("user"),
            "last_ts": ev.ts.isoformat(),
            "message": f"Failed SSH logins from {ip}: {count} in {window_s}s",
        }


class FailedLoginSpray:
    """
    Detects one account being attacked from many distinct source IPs inside a
    sliding window - the distributed pattern FailedLoginBurst cannot see,
    because no single IP ever crosses the per-IP threshold.

    ATT&CK T1110.003 (Password Spraying) / T1110.004 (Credential Stuffing).

    Keyed by username rather than source IP, which is the whole point: the
    signal is the breadth of sources, not the depth of any one of them.

    window_seconds: size of the sliding time window
    min_ips:        distinct source IPs inside that window required to alert
    step:           re-alert every +step further distinct IPs; None = once per burst
    """

    rule = "auth_failed_spray"

    def __init__(
        self,
        window_seconds: int = 120,
        min_ips: int = 5,
        step: Optional[int] = None,
    ):
        self.window = timedelta(seconds=window_seconds)
        self.min_ips = min_ips
        self.step = step
        self.by_user: Dict[str, Deque[Tuple[datetime, str]]] = defaultdict(deque)
        # Per-user IP -> in-window occurrence count, so the distinct-IP count is
        # a len() rather than a rescan of the deque on every event.
        self.ip_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
        self.gate = _AlertGate(min_ips, step)

    def _trim(self, user: str, now_ts: datetime) -> Deque[Tuple[datetime, str]]:
        dq = self.by_user[user]
        counts = self.ip_counts[user]
        while dq and (now_ts - dq[0][0]) > self.window:
            _, expired_ip = dq.popleft()
            remaining = counts.get(expired_ip, 0) - 1
            if remaining <= 0:
                counts.pop(expired_ip, None)
            else:
                counts[expired_ip] = remaining
        return dq

    def handle(self, ev: Event) -> Optional[dict]:
        if ev.kind is not Kind.AUTH_FAIL or not ev.src_ip:
            return None

        user = (ev.meta or {}).get("user")
        if not user:
            # Nothing to key on. Local sudo failures land here.
            return None

        self.by_user[user].append((ev.ts, ev.src_ip))
        counts = self.ip_counts[user]
        counts[ev.src_ip] = counts.get(ev.src_ip, 0) + 1

        dq = self._trim(user, ev.ts)
        distinct_ips = len(self.ip_counts[user])

        if distinct_ips < self.min_ips:
            self.gate.reset(user)
            if not dq:
                self.by_user.pop(user, None)
                self.ip_counts.pop(user, None)
            return None

        if not self.gate.should_fire(user, distinct_ips):
            return None

        window_s = int(self.window.total_seconds())
        attempts = len(dq)
        return {
            "rule": self.rule,
            "user": user,
            "ip_count": distinct_ips,
            "ips": sorted(self.ip_counts[user]),
            "count": attempts,
            "window_seconds": window_s,
            "last_ts": ev.ts.isoformat(),
            "message": (
                f"Distributed failed SSH logins for '{user}': "
                f"{distinct_ips} source IPs, {attempts} attempts in {window_s}s"
            ),
        }
