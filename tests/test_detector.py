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


def test_second_burst_from_same_ip_alerts_again():
    """
    Regression: the de-spam gate used to keep the last alerted count forever,
    so once an IP had crossed the threshold it never alerted again. An attacker
    who paused and resumed was detected exactly once, then silently ignored.
    """
    det = FailedLoginBurst(window_seconds=60, threshold=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    first = [det.handle(_ev("1.2.3.4", base + timedelta(seconds=i))) for i in range(3)]
    assert sum(a is not None for a in first) == 1

    # Long quiet period: the whole first burst ages out of the window.
    later = base + timedelta(seconds=600)
    second = [det.handle(_ev("1.2.3.4", later + timedelta(seconds=i))) for i in range(3)]
    assert sum(a is not None for a in second) == 1


def test_burst_decay_then_recross_alerts_again():
    """Same re-arming behaviour, but the window only partially drains."""
    det = FailedLoginBurst(window_seconds=10, threshold=3)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    fired = [det.handle(_ev("9.9.9.9", base + timedelta(seconds=i))) for i in range(3)]
    assert sum(a is not None for a in fired) == 1

    # Gap longer than the window, then a fresh run of failures.
    resume = base + timedelta(seconds=45)
    fired2 = [det.handle(_ev("9.9.9.9", resume + timedelta(seconds=i))) for i in range(3)]
    assert sum(a is not None for a in fired2) == 1


def test_step_mode_also_re_arms_after_decay():
    det = FailedLoginBurst(window_seconds=10, threshold=3, step=2)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)

    for i in range(3):
        det.handle(_ev("8.8.8.8", base + timedelta(seconds=i)))

    resume = base + timedelta(seconds=60)
    fired = [det.handle(_ev("8.8.8.8", resume + timedelta(seconds=i))) for i in range(3)]
    assert [a["count"] for a in fired if a] == [3]


def test_alert_carries_targeted_username():
    det = FailedLoginBurst(window_seconds=60, threshold=2)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    det.handle(_ev("1.2.3.4", base, user="root"))
    alert = det.handle(_ev("1.2.3.4", base + timedelta(seconds=1), user="root"))
    assert alert["user"] == "root"
