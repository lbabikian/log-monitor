"""
src/main.py
Entry point for the Log Monitor.

Reads log lines (file or stdin), parses them into events, drops anything from
an allowlisted source, runs the events past every enabled detector, and
dispatches the resulting alerts.

    log source -> parser -> Event -> allowlist -> detectors -> alert -> sink

Exit codes:
    0  clean run
    1  runtime error (unreadable file, unexpected failure)
    2  bad usage or bad configuration
  130  interrupted with Ctrl-C
"""

import argparse
import os
import sys
from typing import Iterable, List

from src.alerts import console as alert_console
from src.allowlist import Allowlist, AllowlistError
from src.detectors.rules import FailedLoginBurst, FailedLoginSpray
from src.parsers import auth as p_auth
from src.tailer import follow, read_lines as file_read_lines

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "auth_small.log")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130


def iter_lines(path: str, follow_flag: bool) -> Iterable[str]:
    """Yield log lines from stdin, a followed file, or a static file."""
    if path == "-":
        for line in sys.stdin:
            yield line.rstrip("\n")
        return

    if follow_flag:
        # follow() yields new lines as they're written (tail -f)
        for line in follow(path):
            yield line
        return

    for line in file_read_lines(path):
        yield line


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Real-time SSH auth log monitor with sliding-window brute-force detection"
    )
    parser.add_argument("path", nargs="?", default=SAMPLE, help="Path to log file, or - for stdin")
    parser.add_argument("--follow", action="store_true", help="Follow file like tail -f")
    parser.add_argument("--json", action="store_true", help="Emit alerts as JSON (for piping)")

    burst = parser.add_argument_group("burst rule (one IP, ATT&CK T1110.001)")
    burst.add_argument("--window", type=int, default=60, help="Sliding window size in seconds (default 60)")
    burst.add_argument("--threshold", type=int, default=5, help="Failures in window required to alert (default 5)")
    burst.add_argument("--no-burst", action="store_true", help="Disable the per-IP burst rule")

    spray = parser.add_argument_group("spray rule (many IPs, ATT&CK T1110.003/.004)")
    spray.add_argument("--spray-window", type=int, default=120, help="Sliding window size in seconds (default 120)")
    spray.add_argument("--spray-ips", type=int, default=5, help="Distinct source IPs required to alert (default 5)")
    spray.add_argument("--no-spray", action="store_true", help="Disable the per-user spray rule")

    alw = parser.add_argument_group("allowlisting")
    alw.add_argument("--allow", action="append", default=[], metavar="IP|CIDR",
                     help="Trusted source to ignore; repeatable")
    alw.add_argument("--allow-file", metavar="PATH", help="File of trusted sources, one per line")

    return parser


def build_detectors(args) -> List:
    detectors = []
    if not args.no_burst:
        detectors.append(FailedLoginBurst(window_seconds=args.window, threshold=args.threshold))
    if not args.no_spray:
        detectors.append(FailedLoginSpray(window_seconds=args.spray_window, min_ips=args.spray_ips))
    return detectors


def build_allowlist(args) -> Allowlist:
    # --allow flags and --allow-file lines go through one constructor, so both
    # get the same parsing and the same error messages.
    entries = list(args.allow)
    if args.allow_file:
        with open(args.allow_file, "r", encoding="utf-8") as fh:
            entries.extend(fh.readlines())
    return Allowlist(entries)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.threshold < 1 or args.spray_ips < 1:
        print("[log-monitor] thresholds must be at least 1", file=sys.stderr)
        return EXIT_USAGE
    if args.window < 1 or args.spray_window < 1:
        print("[log-monitor] window sizes must be at least 1 second", file=sys.stderr)
        return EXIT_USAGE

    detectors = build_detectors(args)
    if not detectors:
        print("[log-monitor] every rule is disabled - nothing to do", file=sys.stderr)
        return EXIT_USAGE

    try:
        allowlist = build_allowlist(args)
    except AllowlistError as exc:
        print(f"[log-monitor] {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"[log-monitor] cannot read allowlist: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        for line in iter_lines(args.path, args.follow):
            ev = p_auth.parse(line)
            if not ev:
                continue
            if not allowlist.permits(ev):
                continue
            for detector in detectors:
                alert = detector.handle(ev)
                if alert:
                    alert_console.send(alert, json_mode=args.json)
    except KeyboardInterrupt:
        print("\n[log-monitor] stopped by user.", file=sys.stderr)
        return EXIT_INTERRUPT
    except FileNotFoundError:
        print(f"[log-monitor] no such file: {args.path}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"[log-monitor] cannot read {args.path}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `| head`). Not an error.
        return EXIT_OK

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
