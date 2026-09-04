from datetime import datetime, timezone

import pytest

from src.allowlist import Allowlist, AllowlistError
from src.models import Event, Kind


def _ev(ip):
    return Event(
        ts=datetime(2025, 1, 1, tzinfo=timezone.utc),
        src_ip=ip,
        dst_ip=None,
        kind=Kind.AUTH_FAIL,
        meta={"user": "lucy"},
    )


def test_empty_allowlist_allows_nothing_through_the_filter():
    al = Allowlist()
    assert not al
    assert al.contains("10.0.0.1") is False
    assert al.permits(_ev("10.0.0.1")) is True


def test_single_host_entry():
    al = Allowlist(["192.168.1.5"])
    assert al.contains("192.168.1.5") is True
    assert al.contains("192.168.1.6") is False


def test_cidr_range():
    al = Allowlist(["10.0.0.0/8"])
    assert al.contains("10.1.2.3") is True
    assert al.contains("11.0.0.1") is False


def test_ipv6_entry():
    al = Allowlist(["2001:db8::/32"])
    assert al.contains("2001:db8::1") is True
    assert al.contains("2001:dead::1") is False


def test_multiple_entries():
    al = Allowlist(["10.0.0.0/8", "192.168.1.5"])
    assert len(al) == 2
    assert al.contains("10.9.9.9") is True
    assert al.contains("192.168.1.5") is True
    assert al.contains("8.8.8.8") is False


def test_comments_and_blank_lines_ignored():
    al = Allowlist(["# jump box", "", "   ", "10.0.0.1  # ops laptop"])
    assert len(al) == 1
    assert al.contains("10.0.0.1") is True


def test_invalid_entry_raises():
    with pytest.raises(AllowlistError):
        Allowlist(["not-an-ip"])


def test_unparseable_address_is_not_allowlisted():
    """Failing open here would be a silent detection gap."""
    al = Allowlist(["10.0.0.0/8"])
    assert al.contains("999.999.999.999") is False
    assert al.contains(None) is False


def test_permits_filters_events():
    al = Allowlist(["10.0.0.0/8"])
    assert al.permits(_ev("10.0.0.5")) is False
    assert al.permits(_ev("203.0.113.9")) is True


def test_event_without_ip_is_never_filtered():
    al = Allowlist(["10.0.0.0/8"])
    assert al.permits(_ev(None)) is True


def test_from_file(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("# internal scanners\n10.0.0.0/8\n\n192.168.1.5\n")
    al = Allowlist.from_file(str(path))
    assert len(al) == 2
    assert al.contains("10.5.5.5") is True
