"""
src/alerts/console.py
Handles alert output to the console (stdout/stderr)

Supports:
- plaintext human readable alerts (default)
- JSON mode for integration or piping to other tools
"""
import json
import sys

def send(alert: dict, *, json_mode: bool = False) -> None:
    """
    Print an alert to stdout
    Args:
        alert: A dictionary containing alert metadata
        json_mode: If True, emits the alert as a JSON object (for piping to tools
    """
    if json_mode:
        print(json.dumps(alert, default=str))
        return

    msg = alert.get("message", "alert")
    rule = alert.get("rule", "rule")
    ip = alert.get("ip", "?")
    cnt = alert.get("count", "?")
    win = alert.get("window_seconds", "?")
    print(f"[ALERT] {msg}  [rule={rule} ip={ip} count={cnt} window={win}s]")

def debug(text: str) -> None:
    """
    Print debug messages to stderr to not mix with main alerts
    """
    print(f"[debug] {text}", file=sys.stderr)