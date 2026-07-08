# Design Notes

Why things are built this way, for a reader who wants the reasoning, not
just the code.

## Event pipeline

```
log source -> parser -> Event (dataclass) -> detector -> alert (dict) -> sink
```

`Event` (`src/models.py`) is the seam between input format and detection
logic. Every source-specific parser targets the same contract, so adding a
new log source (a different SSH daemon, a VPN, a WAF) only means writing a
new parser module - detectors and alerting never have to change.

## Why a deque-based sliding window, not a database

`FailedLoginBurst` (`src/detectors/rules.py`) keeps one `collections.deque`
per source IP holding recent failure timestamps. Appends are O(1), and
`_trim` pops expired timestamps off the left, so steady-state cost per
event is O(1) amortized. For a single-process CLI tool watching one host's
auth log, that's the right tradeoff: no external dependency, no schema, and
negligible memory for realistic attack volumes.

The real cost of this choice: state is in-memory only, so a restart forgets
in-progress bursts, and nothing is shared across multiple monitor processes
on different hosts. A persistent store (SQLite for single-host durability,
Redis for multi-host) is the natural next step - it's an extension of the
same "count events for key X in the last N seconds" query, not a redesign.

## De-spam logic

Without throttling, a sustained attack would fire one alert per event past
the threshold - noise nobody can act on. The detector alerts once per burst
(on the first threshold crossing) and stays silent until that IP's window
fully clears, optionally re-alerting every `step` further failures for
long-running attacks. This trades a little detection latency for an alert
stream a human can actually triage.

## Why detection is keyed by IP, not global

Keying by source IP is the highest-precision signal available without
external context (no allowlist, no ASN/geo data), and it's the classic
brute-force pattern. It has a known blind spot, demonstrated on purpose by
`scripts/simulate_attack.py --mode distributed`: many IPs, few attempts
each, same target account - none individually cross the per-IP threshold.
Closing that gap means adding a second detector keyed by username instead
of IP, not changing this one (see README "Roadmap").

## MITRE ATT&CK mapping

The burst detector implements a detection for **T1110 - Brute Force**,
specifically **T1110.001 - Password Guessing** (repeated password attempts
against a single account/service from one source). The distributed-attempt
blind spot described above corresponds to **T1110.003/T1110.004 - Password
Spraying / Credential Stuffing**, which is explicitly out of scope for the
current detector and tracked as future work rather than silently unhandled.
