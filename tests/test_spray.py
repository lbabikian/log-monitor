"""
Tests for FailedLoginSpray - the distributed pattern the per-IP burst rule
cannot see. ATT&CK T1110.003 / T1110.004.
"""

from datetime import datetime, timedelta, timezone

from src.detectors.rules import FailedLoginBurst, FailedLoginSpray
from src.models import Event, Kind


def _ev(ip, ts, kind=Kind.AUTH_FAIL, user="admin"):
    return Event(ts=ts, src_ip=ip, dst_ip=None, kind=kind, meta={"user": user})


def _spray(det, base, n_ips, attempts=1, gap=1, user="admin"):
    """Drive n_ips distinct sources at one account. Returns every alert emitted."""
    alerts = []
    t = 0
    for i in range(n_ips):
        for _ in range(attempts):
            ts = base + timedelta(seconds=t)
            alerts.append(det.handle(_ev(f"198.51.100.{i + 11}", ts, user=user)))
            t += gap
    return alerts


def test_no_alert_below_distinct_ip_threshold():
    det = FailedLoginSpray(window_seconds=120, min_ips=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert not any(_spray(det, base, n_ips=4))


def test_alert_fires_on_distinct_ip_threshold():
    det = FailedLoginSpray(window_seconds=120, min_ips=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    fired = [a for a in _spray(det, base, n_ips=5) if a]
    assert len(fired) == 1
    alert = fired[0]
    assert alert["rule"] == "auth_failed_spray"
    assert alert["user"] == "admin"
    assert alert["ip_count"] == 5
    assert len(alert["ips"]) == 5


def test_repeated_failures_from_one_ip_do_not_trigger_spray():
    """Depth is the burst rule's job. Spray only cares about breadth."""
    det = FailedLoginSpray(window_seconds=120, min_ips=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = [det.handle(_ev("203.0.113.5", base + timedelta(seconds=i))) for i in range(20)]
    assert not any(alerts)


def test_the_two_rules_cover_each_other():
    """
    The distributed pattern slips past the burst rule entirely; the spray rule
    catches it. This is the gap DESIGN.md documents, asserted rather than
    described.
    """
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    burst = FailedLoginBurst(window_seconds=120, threshold=5)
    spray = FailedLoginSpray(window_seconds=120, min_ips=5)

    burst_alerts, spray_alerts = [], []
    t = 0
    for i in range(8):
        for _ in range(2):  # two attempts per IP - never reaches the burst threshold
            ev = _ev(f"198.51.100.{i + 11}", base + timedelta(seconds=t))
            burst_alerts.append(burst.handle(ev))
            spray_alerts.append(spray.handle(ev))
            t += 3

    assert not any(burst_alerts), "burst rule should not see a distributed attack"
    assert any(spray_alerts), "spray rule must catch what the burst rule misses"


def test_separate_users_tracked_independently():
    det = FailedLoginSpray(window_seconds=120, min_ips=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    assert not any(_spray(det, base, n_ips=2, user="alice"))
    fired = [a for a in _spray(det, base, n_ips=3, user="bob") if a]
    assert len(fired) == 1
    assert fired[0]["user"] == "bob"


def test_ips_outside_window_are_dropped():
    det = FailedLoginSpray(window_seconds=10, min_ips=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    det.handle(_ev("198.51.100.1", base))
    det.handle(_ev("198.51.100.2", base + timedelta(seconds=1)))
    # Big gap: the first two have aged out, so this is the only IP in window.
    assert det.handle(_ev("198.51.100.3", base + timedelta(seconds=500))) is None


def test_second_spray_against_same_user_alerts_again():
    det = FailedLoginSpray(window_seconds=30, min_ips=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    assert len([a for a in _spray(det, base, n_ips=3) if a]) == 1
    later = base + timedelta(seconds=600)
    assert len([a for a in _spray(det, later, n_ips=3) if a]) == 1


def test_ignores_events_without_ip_or_user():
    det = FailedLoginSpray(min_ips=1)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    # sudo-style failure: a username but no source IP
    assert det.handle(_ev(None, base, user="lucy")) is None
    # an event with no username to key on
    assert det.handle(Event(base, "1.2.3.4", None, Kind.AUTH_FAIL, {})) is None


def test_ignores_successful_logins():
    det = FailedLoginSpray(min_ips=1)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert det.handle(_ev("1.2.3.4", base, kind=Kind.AUTH_SUCCESS)) is None


def test_distinct_ip_bookkeeping_survives_partial_expiry():
    """
    The per-user IP counter is decremented as entries expire. An IP seen twice
    must not vanish from the distinct count when only its first entry ages out.
    """
    det = FailedLoginSpray(window_seconds=20, min_ips=2)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    det.handle(_ev("198.51.100.1", base))
    det.handle(_ev("198.51.100.1", base + timedelta(seconds=15)))
    # At t=25 the first entry for .1 has expired but the second has not.
    alert = det.handle(_ev("198.51.100.2", base + timedelta(seconds=25)))
    assert alert is not None
    assert alert["ip_count"] == 2
