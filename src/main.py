"""
src/main.py
Entry point for the Log Monitor
Reads log lines (file or stdin), parses them into events,
applies detection rules, and dispatches alerts
"""

import argparse
import os
import sys
from src.parsers import auth as p_auth
from src.detectors.rules import FailedLoginBurst
from src.alerts import console as alert_console
from src.tailer import follow, read_lines as file_read_lines  # adjust import if path differs

SAMPLE = os.path.join(os.path.dirname(__file__), '..', 'samples', 'auth_small.log')

def iter_lines(path: str, follow_flag: bool):
    """Return an iterator of log files (supports stdin and follow mode)"""

    if path == '-':
        for l in sys.stdin:
            yield l.rstrip('\n')
        return

    if follow_flag:
        # follow() yields new lines as they're written (tail -f)
        for l in follow(path):
            yield l
        return

    # normal static read
    for l in file_read_lines(path):
        yield l

def main(argv=None):
    parser = argparse.ArgumentParser(description="Real-time log monitor")
    parser.add_argument("path", nargs="?", default=SAMPLE, help="Path to log file")
    parser.add_argument("--follow", action="store_true", help="Follow file like tail -f")
    parser.add_argument("--window", type=int, default=60, help="Sliding window size (sec)")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for alert")
    parser.add_argument("--json", action="store_true", help="Emit alerts as JSON (for piping to other tools)")
    args = parser.parse_args(argv)

    detector = FailedLoginBurst(window_seconds=args.window, threshold=args.threshold)

    try:
        for line in iter_lines(args.path, args.follow):
            ev = p_auth.parse(line)
            if not ev:
                continue

            alert = detector.handle(ev)
            if alert:
                alert_console.send(alert, json_mode=args.json)

    except KeyboardInterrupt:
        print("\n[Log Monitor] Stopped by user.")
    except Exception as e:
        print(f"[Log Monitor] Error: {e}")


if __name__ == "__main__":
    main()