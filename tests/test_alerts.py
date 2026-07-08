import json

from src.alerts import console


def _alert():
    return {
        "rule": "auth_failed_burst",
        "ip": "1.2.3.4",
        "count": 5,
        "window_seconds": 60,
        "message": "Failed SSH logins from 1.2.3.4: 5 in 60s",
    }


def test_send_text_mode(capsys):
    console.send(_alert())
    out = capsys.readouterr().out
    assert "1.2.3.4" in out
    assert "auth_failed_burst" in out


def test_send_json_mode(capsys):
    console.send(_alert(), json_mode=True)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["ip"] == "1.2.3.4"
    assert data["count"] == 5
