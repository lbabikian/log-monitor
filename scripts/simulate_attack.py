#!/usr/bin/env python3
"""
scripts/simulate_attack.py
Generates synthetic sshd auth-log traffic so the detector can be demoed and
validated without needing a real attack or real (sensitive) log data.

Modes:
  benign      - normal, well-behaved logins only. No alert should fire.
  burst       - one IP hammering a single account past the threshold.
                Triggers FailedLoginBurst with default settings.
  distributed - many IPs, a few attempts each, against one account
                (credential stuffing / password spraying). Deliberately
                stays under the per-IP threshold, so FailedLoginBurst never
                sees it - this is the traffic FailedLoginSpray exists for.
  mixed       - benign traffic with one embedded burst (default demo).

Usage:
  python scripts/simulate_attack.py --mode mixed | python -m src.main -
  python scripts/simulate_attack.py --mode burst --speed 0.3 | python -m src.main - --follow
"""
import argparse
import random
import time
from datetime import datetime, timedelta

USERNAMES = ["root", "admin", "ubuntu", "test", "deploy", "lucy"]
HOSTNAME = "monitored-host"


def _fmt(ts: datetime) -> str:
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"


def failed(ts, ip, user, pid):
    port = random.randint(1024, 65535)
    return f"{_fmt(ts)} {HOSTNAME} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"


def accepted(ts, ip, user, pid):
    port = random.randint(1024, 65535)
    return f"{_fmt(ts)} {HOSTNAME} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def gen_benign(start, count=10):
    lines = []
    ts = start
    for i in range(count):
        ip = f"10.0.0.{random.randint(2, 50)}"
        user = random.choice(USERNAMES)
        lines.append((ts, accepted(ts, ip, user, 1000 + i)))
        ts += timedelta(seconds=random.randint(5, 30))
    return lines


def gen_burst(start, ip="203.0.113.77", user="root", count=8, gap=2):
    lines = []
    ts = start
    for i in range(count):
        lines.append((ts, failed(ts, ip, user, 2000 + i)))
        ts += timedelta(seconds=gap)
    return lines


def gen_distributed(start, user="admin", attackers=12, attempts_per_ip=2, gap=3):
    """
    Many source IPs, a few attempts each, all against one account.

    Source IPs are assigned deterministically rather than at random: two
    attackers drawing the same address would quietly reduce the distinct-IP
    count and make the demo flaky.
    """
    lines = []
    ts = start
    for a in range(attackers):
        ip = f"198.51.100.{a + 11}"
        for _ in range(attempts_per_ip):
            lines.append((ts, failed(ts, ip, user, 3000 + a)))
            ts += timedelta(seconds=gap)
    return lines


def build(mode: str, start: datetime):
    if mode == "benign":
        return gen_benign(start, count=15)
    if mode == "burst":
        return gen_burst(start)
    if mode == "distributed":
        return gen_distributed(start)
    # mixed (default): benign traffic with a burst dropped in the middle
    benign_a = gen_benign(start, count=6)
    burst = gen_burst(start + timedelta(seconds=90))
    benign_b = gen_benign(start + timedelta(seconds=200), count=6)
    return sorted(benign_a + burst + benign_b, key=lambda pair: pair[0])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate synthetic SSH auth-log traffic for demoing/testing the detector"
    )
    parser.add_argument(
        "--mode", choices=["benign", "burst", "distributed", "mixed"], default="mixed"
    )
    parser.add_argument(
        "--speed", type=float, default=0.0, help="Seconds to sleep between lines (0 = dump instantly)"
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="Seed the RNG so a run is reproducible"
    )
    args = parser.parse_args(argv)

    if args.seed is not None:
        random.seed(args.seed)

    start = datetime.now()
    for _, line in build(args.mode, start):
        print(line, flush=True)
        if args.speed > 0:
            time.sleep(args.speed)


if __name__ == "__main__":
    main()
