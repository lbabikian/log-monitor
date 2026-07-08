from src.parsers import auth
from src.models import Kind


def test_parse_failed_password_syslog():
    line = "Oct  9 14:00:00 mypc sshd[1111]: Failed password for invalid user lucy from 192.168.0.10 port 52022 ssh2"
    ev = auth.parse(line)
    assert ev is not None
    assert ev.kind is Kind.AUTH_FAIL
    assert ev.src_ip == "192.168.0.10"
    assert ev.meta["user"] == "lucy"


def test_parse_accepted_password():
    line = "Oct  9 14:02:00 mypc sshd[1116]: Accepted password for lucy from 192.168.0.10 port 52022 ssh2"
    ev = auth.parse(line)
    assert ev is not None
    assert ev.kind is Kind.AUTH_SUCCESS
    assert ev.src_ip == "192.168.0.10"


def test_parse_iso_timestamp():
    line = "2025-10-09T15:52:17.954711-07:00 mypc sshd[1]: Failed password for root from 10.0.0.5 port 22 ssh2"
    ev = auth.parse(line)
    assert ev is not None
    assert ev.ts.tzinfo is not None
    assert ev.src_ip == "10.0.0.5"


def test_parse_sudo_failure_has_no_ip():
    line = (
        "Oct  9 14:05:00 mypc sudo: pam_unix(sudo:auth): authentication "
        "failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=lucy rhost=  user=lucy"
    )
    ev = auth.parse(line)
    assert ev is not None
    assert ev.src_ip is None
    assert ev.meta["user"] == "lucy"


def test_parse_unmatched_line_returns_none():
    assert auth.parse("this is not a log line") is None


def test_parse_line_without_timestamp_returns_none():
    assert auth.parse("Failed password for root from 1.2.3.4 port 22 ssh2") is None
