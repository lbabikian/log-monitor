"""
End-to-end tests: real log files in, alerts out, through main().
These are the tests that would catch a pipeline wiring mistake that every
unit test still passes.
"""

import json
import os

import pytest

from src.main import EXIT_ERROR, EXIT_OK, EXIT_USAGE, main

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BURST_LOG = os.path.join(REPO, "samples", "auth_small.log")
SPRAY_LOG = os.path.join(REPO, "samples", "auth_spray.log")


def test_burst_sample_fires_burst_alert(capsys):
    assert main([BURST_LOG, "--no-spray"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "auth_failed_burst" in out
    assert "192.168.0.10" in out


def test_spray_sample_fires_spray_alert(capsys):
    assert main([SPRAY_LOG]) == EXIT_OK
    out = capsys.readouterr().out
    assert "auth_failed_spray" in out
    assert "admin" in out


def test_spray_sample_does_not_trip_the_burst_rule(capsys):
    """No single IP in the spray sample reaches the per-IP threshold."""
    assert main([SPRAY_LOG, "--no-spray"]) == EXIT_OK
    assert "auth_failed_burst" not in capsys.readouterr().out


def test_json_mode_emits_parseable_objects(capsys):
    assert main([SPRAY_LOG, "--json"]) == EXIT_OK
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert lines
    for line in lines:
        payload = json.loads(line)
        assert "rule" in payload
        assert "message" in payload


def test_allowlisted_source_suppresses_the_alert(capsys):
    assert main([BURST_LOG, "--no-spray", "--allow", "192.168.0.0/16"]) == EXIT_OK
    assert "auth_failed_burst" not in capsys.readouterr().out


def test_allowlist_file_suppresses_the_alert(tmp_path, capsys):
    path = tmp_path / "allow.txt"
    path.write_text("# lab network\n192.168.0.10\n")
    assert main([BURST_LOG, "--no-spray", "--allow-file", str(path)]) == EXIT_OK
    assert "auth_failed_burst" not in capsys.readouterr().out


def test_missing_file_exits_with_error(capsys):
    assert main(["/no/such/file.log"]) == EXIT_ERROR
    assert "no such file" in capsys.readouterr().err


def test_invalid_allowlist_entry_is_a_usage_error(capsys):
    assert main([BURST_LOG, "--allow", "not-an-ip"]) == EXIT_USAGE
    assert "invalid allowlist entry" in capsys.readouterr().err


def test_disabling_every_rule_is_a_usage_error(capsys):
    assert main([BURST_LOG, "--no-burst", "--no-spray"]) == EXIT_USAGE
    assert "nothing to do" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--threshold", "--spray-ips"])
def test_nonsense_thresholds_rejected(flag, capsys):
    assert main([BURST_LOG, flag, "0"]) == EXIT_USAGE
    assert "at least 1" in capsys.readouterr().err


def test_stdin_mode(monkeypatch, capsys):
    import io

    with open(SPRAY_LOG) as fh:
        monkeypatch.setattr("sys.stdin", io.StringIO(fh.read()))
    assert main(["-"]) == EXIT_OK
    assert "auth_failed_spray" in capsys.readouterr().out
