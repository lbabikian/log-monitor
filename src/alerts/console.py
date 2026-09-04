"""
src/alerts/console.py
Handles alert output to the console (stdout/stderr)

Supports:
- plaintext human readable alerts (default)
- JSON mode for integration or piping to other tools

The plaintext form is a message plus a bracketed detail block. The block is
built from whichever fields the rule actually produced, so a new detector gets
sensible output without touching this module.
"""
import json
import sys

# (alert key, label shown to the reader, suffix) in display order.
_FIELDS = (
    ("ip", "ip", ""),
    ("user", "user", ""),
    ("ip_count", "ips", ""),
    ("count", "count", ""),
    ("window_seconds", "window", "s"),
)


def _details(alert: dict) -> str:
    parts = [f"rule={alert.get('rule', 'rule')}"]
    for key, label, suffix in _FIELDS:
        value = alert.get(key)
        if value is None:
            continue
        parts.append(f"{label}={value}{suffix}")
    return " ".join(parts)


def send(alert: dict, *, json_mode: bool = False) -> None:
    """
    Print an alert to stdout.

    Args:
        alert: A dictionary containing alert metadata
        json_mode: If True, emits the alert as a JSON object (for piping to tools)
    """
    if json_mode:
        print(json.dumps(alert, default=str), flush=True)
        return

    print(f"[ALERT] {alert.get('message', 'alert')}  [{_details(alert)}]", flush=True)


def debug(text: str) -> None:
    """
    Print debug messages to stderr to not mix with main alerts
    """
    print(f"[debug] {text}", file=sys.stderr)
