# Log Monitor - SSH Brute-Force Detector

A real-time log monitor that watches SSH authentication logs, parses login
attempts, and detects brute-force patterns using a sliding-window algorithm
- e.g. repeated failed logins from the same IP within a configurable time
window. Maps to **MITRE ATT&CK T1110.001 (Brute Force: Password Guessing)**.

Built as a small, dependency-free tool with a clean pipeline: `parser ->
Event -> detector -> alert`, so new log sources or detection rules can be
added without touching the rest of the system. See [DESIGN.md](DESIGN.md)
for the reasoning behind the architecture.

## Demo

No real attack (or real log data) required - `scripts/simulate_attack.py`
generates synthetic sshd traffic and pipes it straight into the monitor:

```
$ python scripts/simulate_attack.py --mode burst | python -m src.main -
[ALERT] Failed SSH logins from 203.0.113.77: 5 in 60s  [rule=auth_failed_burst ip=203.0.113.77 count=5 window=60s]
```

Or against the bundled sample log:

```
$ python -m src.main samples/auth_small.log
[ALERT] Failed SSH logins from 192.168.0.10: 5 in 60s  [rule=auth_failed_burst ip=192.168.0.10 count=5 window=60s]
```

## Features

- Parses OpenSSH `auth.log` (both legacy syslog and ISO-8601 timestamp formats)
- Sliding-window brute-force detection, keyed per source IP
- Batch mode (read a file once), `tail -f`-style follow mode, and stdin piping
- De-spammed alerting: fires once per burst, not once per failed attempt
- JSON alert output (`--json`) for piping into other tooling
- Synthetic attack traffic generator for demos and validation
- Zero runtime dependencies - Python standard library only

## Installation

```
git clone <this-repo>
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
log-monitor samples/auth_small.log             # batch mode
log-monitor /var/log/auth.log --follow          # live tail -f mode
log-monitor --window 30 --threshold 3           # tune the detection rule
log-monitor --json samples/auth_small.log       # JSON alerts, for piping
tail -f /var/log/auth.log | log-monitor -       # read from stdin
```

`--window` is the sliding window size in seconds (default 60), `--threshold`
is the number of failures inside that window required to fire an alert
(default 5).

## Architecture

```
log source -> parser -> Event -> detector -> alert -> sink
```

- `src/parsers/auth.py` - regex-based sshd log parser, returns a common `Event`
- `src/models.py` - the `Event` dataclass shared by every parser and detector
- `src/detectors/rules.py` - `FailedLoginBurst`, a deque-based sliding-window rule
- `src/alerts/console.py` - alert sink (plaintext or JSON)
- `src/tailer.py` - file reading, including a `tail -f` follower
- `scripts/simulate_attack.py` - synthetic sshd traffic generator for demos/testing

Full rationale for these choices - why a deque instead of a database, why
detection is IP-keyed, the ATT&CK mapping in detail - is in
[DESIGN.md](DESIGN.md).

## Testing

```
pip install -r requirements-dev.txt
pytest
```

Covers the timestamp/regex parsing, the sliding-window detector (threshold
crossing, window expiry, de-spam/re-alert behavior, per-IP isolation), and
the alert sink's text/JSON output.

## Limitations / Roadmap

This project deliberately draws a scope boundary rather than half-implementing
everything at once:

- **In-memory state only** - restarting the process forgets any in-progress
  burst. A persistent store (SQLite/Redis) is the natural next step.
- **IP-keyed detection only** - a distributed attack (many IPs, few attempts
  each, same target account - ATT&CK T1110.003/T1110.004) will not cross the
  per-IP threshold today. `scripts/simulate_attack.py --mode distributed`
  demonstrates this gap on purpose. A username-keyed detector is the planned
  fix, reusing the same sliding-window primitive.
- **No allowlisting** - no way yet to exclude known-safe IPs (e.g. your own
  jump box or internal scanners).
- **Console-only alerting** - no webhook/Slack/email sink yet.
- **Local file/stdin input only** - no network listener, which keeps the
  attack surface intentionally minimal for a CLI tool.

## License

MIT - see [LICENSE](LICENSE).
