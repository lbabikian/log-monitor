# Design Notes

Why things are built this way, for a reader who wants the reasoning, not
just the code.

## Event pipeline

```
log source -> parser -> Event (dataclass) -> allowlist -> detector -> alert (dict) -> sink
```

`Event` (`src/models.py`) serves as the boundary between input format and
detection logic. Every source-specific parser targets the same contract, so
adding a new log source (a different SSH daemon, a VPN, a WAF) only means
writing a new parser module - detectors and alerting never have to change.

Allowlisting sits between parsing and detection rather than inside any rule.
A new detector inherits it for free, and detectors stay concerned only with
detection.

## The two rules, and why there are two

Brute force has two shapes, and one detector cannot see both:

| | `FailedLoginBurst` | `FailedLoginSpray` |
|---|---|---|
| Keyed by | source IP | username |
| Signal | depth - one source, many attempts | breadth - one account, many sources |
| ATT&CK | T1110.001 Password Guessing | T1110.003 / .004 Spraying, Credential Stuffing |
| Defaults | 5 failures in 60s | 5 distinct IPs in 120s |

The distributed case is not a tuning problem for the burst rule - it is
structurally invisible to it. Twelve IPs making two attempts each never
crosses a per-IP threshold of five, no matter how the threshold is set.
Lowering it far enough to catch them would alert on every mistyped password
on the host. The only fix is a second key, which is why `FailedLoginSpray`
exists as a separate rule rather than as a parameter on the first.

Both rules run by default and both can fire on the same traffic. That is
intended: they are answering different questions, and an attack that is both
deep and wide deserves both alerts.

## Why these thresholds

The data structure choices below are cheap to justify. The threshold choices
are the ones that actually decide whether this tool is useful, so they get
their own section.

**Burst: 5 failures from one IP in 60 seconds.**

The floor is set by what a legitimate user can produce. OpenSSH's default
`MaxAuthTries` is 6 per connection, and a client typically gives up after 3
password prompts before the user reconnects and tries again. So a real person
fumbling a password, or a stale key retrying, lands in the region of 3-4
failures per minute. Automated guessing lands two or three orders of magnitude
above that - tens to hundreds per minute. There is a wide, quiet gap between
those two populations, and 5-in-60 sits at the bottom of it: above ordinary
human error, far below any tool worth detecting.

The asymmetry matters when picking where in that gap to sit. Too low and you
page someone because a colleague fat-fingered their password twice; a few of
those and the alert gets muted, which costs you every real detection after it.
Too high and slow credential-guessing walks underneath it indefinitely.
Alert fatigue is the more expensive failure, so the threshold sits nearer the
human end than the floor allows rather than as low as it could go.

**Spray: 5 distinct source IPs against one account in 120 seconds.**

Here the reasoning is about identity, not volume. A real user has one or two
addresses in a two-minute span - a laptop, maybe a phone flapping between
wifi and cellular. Five distinct sources failing against a single account in
that window is not a person having a bad morning.

The window is twice the burst window because distributed attacks are
deliberately slow; that is the entire point of distributing them. A 60-second
window would let an attacker evade detection simply by pacing.

**What these numbers are not.** They are defaults tuned against the sample
logs in this repo, not against a production baseline, and this is the honest
limit of what a project like this can claim. Deploying properly means
collecting two weeks of real `auth.log`, taking the 99th percentile of
per-IP failures-per-minute across known-good sources, and setting the
threshold above that line rather than above an assumption. Both rules take
their window and threshold as constructor arguments and CLI flags precisely
because the defaults are a starting point, not an answer.

The known false-positive sources, in rough order of likelihood:

- **Shared service accounts.** One `deploy` account used by a whole team from
  many machines looks exactly like a spray. This is the single most likely
  false positive and the main reason allowlisting exists.
- **CI runners and internal scanners** hitting a host from a pool of ephemeral
  addresses.
- **NAT and jump boxes**, where many users share a source address, inflating
  per-IP failure counts.
- **Expired credentials after a rotation**, where a fleet of machines all
  begin failing against the same account at once.

## Why a deque-based sliding window, not a database

`FailedLoginBurst` (`src/detectors/rules.py`) keeps one `collections.deque`
per source IP holding recent failure timestamps. Appends are O(1), and `_trim`
pops expired timestamps off the left, so steady-state cost per event is O(1)
amortized. For a single-process CLI tool watching one host's auth log, that's
the right tradeoff: no external dependency, no schema, and negligible memory
for realistic attack volumes.

The real cost of this choice: state is in-memory only, so a restart forgets
in-progress bursts, and nothing is shared across multiple monitor processes on
different hosts. A persistent store (SQLite for single-host durability, Redis
for multi-host) is the natural next step - it's an extension of the same
"count events for key X in the last N seconds" query, not a redesign.

## Counting distinct IPs without rescanning

`FailedLoginSpray` needs a *distinct* count, not a total, which is a different
problem: the obvious implementation rebuilds a set from the deque on every
event, making each event O(window) instead of O(1).

Instead it carries a second structure - a per-user `{ip: occurrences}` dict
maintained alongside the deque. An arrival increments the entry; an expiry
decrements it and deletes it at zero. The distinct count is then `len()` of
that dict. Appends and expiries stay O(1) amortized, matching the burst rule,
at the cost of one more dict to keep consistent with the deque.

That consistency is the thing worth testing, and
`test_distinct_ip_bookkeeping_survives_partial_expiry` is the test that pins
it: an IP seen twice must not disappear from the distinct count when only its
first entry ages out.

## De-spam logic, and a bug that lived in it

Without throttling, a sustained attack would fire one alert per event past the
threshold - noise nobody can act on. Both rules share `_AlertGate`, which
alerts once per burst (on the first threshold crossing) and stays silent until
that key's window clears, optionally re-alerting every `step` further events
for long-running attacks. This trades a little detection latency for an alert
stream a human can actually triage.

The gate has two halves, and the first version of this code only had one. It
recorded the count it last alerted on, but never cleared that record when the
count fell back below the threshold. The result: once an IP had crossed the
threshold, it was gated *permanently*. An attacker who ran a burst, paused
until the window drained, and resumed was detected exactly once and then
silently ignored for the lifetime of the process - which is precisely the
behaviour a patient attacker exhibits.

The unit tests at the time did not catch it because they all tested de-spam
*within* a single burst. The regression that does catch it,
`test_second_burst_from_same_ip_alerts_again`, runs two bursts separated by a
gap longer than the window. `reset()` is now the explicit other half of the
gate's contract, and the docstring says so, because the failure mode is silent
and a future rule keyed on something else would reintroduce it the same way.

## Why detection is keyed by IP, then also by username

Keying by source IP is the highest-precision signal available without external
context (no allowlist, no ASN/geo data), and it's the classic brute-force
pattern. Its blind spot - many IPs, few attempts each, one target account - is
now covered by `FailedLoginSpray` keyed on username instead, reusing the same
sliding-window primitive rather than complicating the first rule.

`scripts/simulate_attack.py --mode distributed` generates exactly that traffic,
and `test_the_two_rules_cover_each_other` asserts the handoff directly: the
burst rule stays silent on it, the spray rule fires. The property is pinned by
a test rather than described in prose.

## Allowlisting

`Allowlist` (`src/allowlist.py`) holds `ipaddress` networks and is applied as a
pipeline stage. Entries are single addresses or CIDR ranges, v4 or v6, since
`ip_network(..., strict=False)` accepts a bare host as a /32 or /128 and the
distinction is not worth exposing to the user.

One deliberate choice: an address that cannot be parsed is treated as *not*
allowlisted, so it still reaches the detectors. Failing open would turn a
malformed log line into a silent detection gap, which is the worse direction
to be wrong in. An invalid entry in the allowlist *configuration*, by contrast,
is a hard startup error - that one is the operator's mistake, and failing loudly
at launch is better than discovering at 3am that a rule was never active.

## MITRE ATT&CK mapping

`FailedLoginBurst` implements a detection for **T1110 - Brute Force**,
specifically **T1110.001 - Password Guessing** (repeated password attempts
against a single account/service from one source).

`FailedLoginSpray` covers **T1110.003 - Password Spraying** and
**T1110.004 - Credential Stuffing**, both of which present as one account
under attack from many sources.

What remains unmapped is **T1110.002 - Password Cracking**, which happens
offline against stolen hashes and produces no authentication log events at
all. It is out of scope by nature rather than by choice, and no amount of
auth.log analysis will surface it.
