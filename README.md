# Log Monitor - SSH Brute-Force Detector

[![CI](https://github.com/lbabikian/log-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/lbabikian/log-monitor/actions/workflows/ci.yml)

A real-time log monitor that watches SSH authentication logs, parses login
attempts, and detects brute-force patterns using a sliding-window algorithm.

Brute force has two shapes, and one detector cannot see both. This tool ships
a rule for each: **one IP hammering one host** (ATT&CK T1110.001), and **many
IPs quietly working the same account** (T1110.003/.004), which is structurally
invisible to the first. `scripts/simulate_attack.py` generates both patterns so
you can watch each rule catch what the other misses.

Built as a small, dependency-free tool with a clean pipeline:
`parser -> Event -> allowlist -> detector -> alert`, so new log sources or
detection rules can be added without touching the rest of the system. See
[DESIGN.md](DESIGN.md) for the reasoning behind the architecture, including
why the thresholds are the numbers they are.

## Demo

No real attack (or real log data) required - `scripts/simulate_attack.py`
generates synthetic sshd traffic and pipes it straight into the monitor:

```
$ python scripts/simulate_attack.py --mode burst | python -m src.main -
[ALERT] Failed SSH logins from 203.0.113.77: 5 in 60s  [rule=auth_failed_burst ip=203.0.113.77 user=root count=5 window=60s]
```

The distributed pattern - twelve IPs, two attempts each, one target account -
never crosses the per-IP threshold, and is caught by the second rule instead:

```
$ python scripts/simulate_attack.py --mode distributed | python -m src.main -
[ALERT] Distributed failed SSH logins for 'admin': 5 source IPs, 9 attempts in 120s  [rule=auth_failed_spray user=admin ips=5 count=9 window=120s]
```

Or against the bundled sample logs:

```
$ python -m src.main samples/auth_small.log
[ALERT] Failed SSH logins from 192.168.0.10: 5 in 60s  [rule=auth_failed_burst ip=192.168.0.10 user=lucy count=5 window=60s]

$ python -m src.main samples/auth_spray.log
[ALERT] Distributed failed SSH logins for 'admin': 5 source IPs, 9 attempts in 120s  [rule=auth_failed_spray user=admin ips=5 count=9 window=120s]
```

## Detection rules

| Rule | Keyed by | Fires when | ATT&CK |
|---|---|---|---|
| `auth_failed_burst` | source IP | 5 failures from one IP in 60s | T1110.001 |
| `auth_failed_spray` | username | 5 distinct IPs against one account in 120s | T1110.003 / .004 |

Both run by default and both can fire on the same traffic - they answer
different questions. Defaults are tunable; see Usage.

## Features

- Parses OpenSSH `auth.log` (both legacy syslog and ISO-8601 timestamp formats)
- Sliding-window brute-force detection, keyed per source IP
- Distributed-attack detection, keyed per username
- Source allowlisting by IP or CIDR, v4 and v6, inline or from a file
- Batch mode (read a file once), `tail -f`-style follow mode, and stdin piping
- De-spammed alerting: fires once per burst, not once per failed attempt
- JSON alert output (`--json`) for piping into other tooling
- Synthetic attack traffic generator for demos and validation
- Meaningful exit codes, so it composes in scripts and CI
- Zero runtime dependencies - Python standard library only

## Installation

```
git clone https://github.com/lbabikian/log-monitor.git
cd log-monitor
python -m venv .venv && source .venv/bin/activate
pip install -e .              # installs the `log-monitor` command
pip install -r requirements-dev.txt   # only needed to run the tests
```

Without installing, everything also works run in place from the repo root:

```
python -m src.main samples/auth_small.log
```

## Usage

```
log-monitor samples/auth_small.log              # batch mode
log-monitor /var/log/auth.log --follow          # live tail -f mode
log-monitor --json samples/auth_spray.log       # JSON alerts, for piping
tail -f /var/log/auth.log | log-monitor -       # read from stdin
```

Tuning the rules:

```
log-monitor --window 30 --threshold 3           # burst rule: 3 failures in 30s
log-monitor --spray-window 300 --spray-ips 8    # spray rule: 8 IPs in 5 minutes
log-monitor --no-spray                          # per-IP rule only
log-monitor --no-burst                          # per-user rule only
```

Allowlisting trusted sources:

```
log-monitor --allow 10.0.0.0/8 --allow 192.168.1.5
log-monitor --allow-file /etc/log-monitor/allow.txt
```

`--allow-file` takes one entry per line; `#` comments and blank lines are
ignored. A shared service account hit from many machines is the most likely
false positive for the spray rule, and allowlisting is the intended fix.

**Exit codes:** `0` clean run · `1` runtime error · `2` bad usage or
configuration · `130` interrupted.

## Architecture

```
log source -> parser -> Event -> allowlist -> detector -> alert -> sink
```

- `src/parsers/auth.py` - regex-based sshd log parser, returns a common `Event`
- `src/models.py` - the `Event` dataclass shared by every parser and detector
- `src/allowlist.py` - CIDR-aware source filtering, applied before detection
- `src/detectors/rules.py` - `FailedLoginBurst`, `FailedLoginSpray`, and the shared de-spam gate
- `src/alerts/console.py` - alert sink (plaintext or JSON)
- `src/tailer.py` - file reading, including a `tail -f` follower
- `scripts/simulate_attack.py` - synthetic sshd traffic generator for demos/testing

Full rationale for these choices - why a deque instead of a database, how the
distinct-IP count stays O(1), why detection is keyed two different ways, and a
de-spam bug that hid a whole class of attack - is in [DESIGN.md](DESIGN.md).

## Testing

```
pip install -r requirements-dev.txt
pytest
```

Covers timestamp/regex parsing, both detectors (threshold crossing, window
expiry, de-spam and re-arming, per-key isolation, distinct-IP bookkeeping
across partial expiry), allowlist matching, and end-to-end runs through
`main()` including exit codes and JSON output.

One test is worth calling out: `test_the_two_rules_cover_each_other` asserts
the handoff between the rules directly - the burst rule stays silent on
distributed traffic, the spray rule fires on it. The property the design
depends on is pinned by a test rather than only described in prose.

## Limitations / Roadmap

This project deliberately draws a scope boundary rather than half-implementing
everything at once:

- **In-memory state only** - restarting the process forgets any in-progress
  burst. A persistent store (SQLite/Redis) is the natural next step.
- **Thresholds are defaults, not a baseline** - they are tuned against the
  sample logs here, not against production traffic. See DESIGN.md for how you
  would actually set them on a real host.
- **Console-only alerting** - no webhook/Slack/email sink yet.
- **Local file/stdin input only** - no network listener, which keeps the
  attack surface intentionally minimal for a CLI tool.
- **Legacy syslog timestamps assume the current year** - `auth.log` omits the
  year, so December logs replayed in January will be misdated. ISO-8601 lines
  are unaffected.
- **No offline cracking detection** (ATT&CK T1110.002) - it produces no
  authentication events, so no auth.log tool can see it.

## License

MIT - see [LICENSE](LICENSE).
