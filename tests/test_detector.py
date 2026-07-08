from datetime import datetime, timedelta, timezone

from src.detectors.rules import FailedLoginBurst
from src.models import Event, Kind


def _ev(ip, ts, kind=Kind.AUTH_FAIL, user="bob"):
    return Event(ts=ts, src_ip=ip, dst_ip=None, kind=kind, meta={"user": user})


def test_no_alert_below_threshold():
    det = FailedLoginBurst(window_seconds=60, threshold=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alert = None
    for i in range(4):
        alert = det.handle(_ev("1.2.3.4", base + timedelta(seconds=i)))
    assert alert is None


def test_alert_fires_on_threshold_crossing():
    det = FailedLoginBurst(window_seconds=60, threshold=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alert = None
    for i in range(5):
        alert = det.handle(_ev("1.2.3.4", base + timedelta(seconds=i)))
    assert alert is not None
    assert alert["ip"] == "1.2.3.4"
    assert alert["count"] == 5
    assert alert["rule"] == "auth_failed_burst"


def test_no_duplicate_alert_while_burst_continues():
    det = FailedLoginBurst(window_seconds=60, threshold=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = [det.handle(_ev("1.2.3.4", base + timedelta(seconds=i))) for i in range(8)]
    fired = [a for a in alerts if a]
    assert len(fired) == 1


def test_events_outside_window_are_trimmed():
    det = FailedLoginBurst(window_seconds=10, threshold=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    det.handle(_ev("1.2.3.4", base))
    det.handle(_ev("1.2.3.4", base + timedelta(seconds=1)))
    # big gap - the first two events should have aged out of the window
    alert = det.handle(_ev("1.2.3.4", base + timedelta(seconds=100)))
    assert alert is None


def test_ignores_events_without_src_ip():
    det = FailedLoginBurst(threshold=1)
    ev = _ev(None, datetime(2025, 1, 1, tzinfo=timezone.utc))
    assert det.handle(ev) is None


def test_ignores_non_failure_events():
    det = FailedLoginBurst(threshold=1)
    ev = _ev("1.2.3.4", datetime(2025, 1, 1, tzinfo=timezone.utc), kind=Kind.AUTH_SUCCESS)
    assert det.handle(ev) is None


def test_step_reveals_only_on_multiples():
    det = FailedLoginBurst(window_seconds=60, threshold=3, step=2)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = [det.handle(_ev("1.2.3.4", base + timedelta(seconds=i))) for i in range(7)]
    fired_counts = [a["count"] for a in alerts if a]
    assert fired_counts == [3, 5, 7]


def test_separate_ips_tracked_independently():
    det = FailedLoginBurst(window_seconds=60, threshold=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for i in range(2):
        assert det.handle(_ev("1.1.1.1", base + timedelta(seconds=i))) is None
    for i in range(3):
        alert = det.handle(_ev("2.2.2.2", base + timedelta(seconds=i)))
    assert alert is not None
    assert alert["ip"] == "2.2.2.2"
