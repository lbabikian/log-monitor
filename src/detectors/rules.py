from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Optional
from ..models import Event, Kind

class FailedLoginBurst:
    """
    Detects N or more failed auth attempts from the same source IP inside a sliding window

    window_seconds: size of sliding time window (e.g., 60)
    threshold: number of failures to trigger an alert (e.g., 5)
    step: if set (e.g., 5), re-alert only on every +step after first threshold crossing
          e.g., counts 5,10,15...; if None, alert only when crossing threshold
    """
    def __init__(self, window_seconds: int = 60, threshold: int = 5, step: Optional[int] = None):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.step = step  # None = only on first crossing; int = re-alert every +step
        self.by_ip: Dict[str, Deque] = defaultdict(deque)
        self.last_alert_count: Dict[str, int] = {}  # ip -> last count we alerted on

    def _trim(self, ip: str, now_ts):
        dq = self.by_ip[ip]
        while dq and (now_ts - dq[0]) > self.window:
            dq.popleft()
        if not dq:
            # Optional tidy-up to avoid a dict of empty deques
            self.by_ip.pop(ip, None)
            self.last_alert_count.pop(ip, None)
        return dq

    def handle(self, ev: Event):
        # Only care about failed auth with a source IP
        if ev.kind is not Kind.AUTH_FAIL or not ev.src_ip:
            return None

        ip = ev.src_ip
        dq = self.by_ip[ip]
        dq.append(ev.ts)
        dq = self._trim(ip, ev.ts)

        count = len(dq)
        if count < self.threshold:
            # The burst has decayed below the threshold. Clear the de-spam
            # state so a later burst from this same IP alerts again, instead
            # of staying gated for the lifetime of the process.
            self.last_alert_count.pop(ip, None)
            return None

        # De-spam logic: send only on crossing threshold or every +step
        prev = self.last_alert_count.get(ip)
        should_send = False
        if prev is None:
            # First time we ever crossed for this IP
            should_send = True
        elif self.step:
            # Re-alert only on multiples: threshold, threshold+step, ...
            if count >= self.threshold and (count - self.threshold) % self.step == 0 and count != prev:
                should_send = True
        else:
            # No step: only alert once per burst until it falls below threshold again
            if prev < self.threshold:
                should_send = True

        # Update last seen count
        self.last_alert_count[ip] = count

        if not should_send:
            return None

        # Optional: bubble up username if the parser captured it
        user = ev.meta.get("user") if ev.meta else None

        return {
            "rule": "auth_failed_burst",
            "ip": ip,
            "count": count,
            "window_seconds": int(self.window.total_seconds()),
            "user": user,
            "last_ts": ev.ts.isoformat(),
            "message": f"Failed SSH logins from {ip}: {count} in {int(self.window.total_seconds())}s",
        }