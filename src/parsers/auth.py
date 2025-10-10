"""
parses lines from /var/log/auth.log (sshd) and return an event
looks for: 
-SSH failed pwd         -> kind='auth.fail'
-SSH successful pwd     -> kind='auth.success'
-sudo/local auth failures w/o IP  (for per-user rules)

"""
import re
from datetime import datetime, timezone
from typing import Optional
from ..models import Event, Kind

# Timestamp prefixes
TS_RE = re.compile(r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})')
TS_ISO_RE = re.compile(r'^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?P<tz>Z|[+-]\d{2}:\d{2}))')
MONTHS = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}

# SSH auth lines
FAIL_RE = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
OK_RE   = re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')

# Sudo/local auth failures w/o IP
SUDO_FAIL_RE = re.compile(r'pam_unix\((?:sudo|login):auth\): authentication failure;.*?user=(?P<user>\S+)')



def _parse_ts(line: str) -> Optional[datetime]:
    # ISO 8601 (e.g., 2025-10-09T15:52:17.954711-07:00)
    m = TS_ISO_RE.search(line)
    if m:
        iso = m['iso'].replace('Z', '+00:00')
        try:
            return datetime.fromisoformat(iso)  # tz-aware
        except ValueError:
            pass

    # Legacy syslog style (e.g., Oct  9 15:52:17); assume current year, UTC
    m = TS_RE.search(line)
    if m:
        now = datetime.now(timezone.utc)
        return datetime(
            year=now.year,
            month=MONTHS[m['mon']],
            day=int(m['day']),
            hour=int(m['h']),
            minute=int(m['m']),
            second=int(m['s']),
            tzinfo=timezone.utc,
        )
    return None

def parse(line: str) -> Optional[Event]:
    ts = _parse_ts(line)
    if not ts:
        return None

    # SSH: failed password
    g = FAIL_RE.search(line)
    if g:
        return Event(ts, g['ip'], None, Kind.AUTH_FAIL, {'user': g['user'], 'service': 'sshd'})

    # SSH: accepted password
    g = OK_RE.search(line)
    if g:
        return Event(ts, g['ip'], None, Kind.AUTH_SUCCESS, {'user': g['user'], 'service': 'sshd'})

    # Sudo/login failures w/o IP / this enables a future "per-user burst" detector
    g = SUDO_FAIL_RE.search(line)
    if g:
        return Event(ts, None, None, Kind.AUTH_FAIL, {'user': g['user'], 'service': 'sudo'})

    return None