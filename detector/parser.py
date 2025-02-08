"""Apache/Nginx Combined Log Format parser."""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import pandas as pd

# Combined Log Format pattern
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
_PATTERN = re.compile(
    r'^(\S+)'           # 1  IP
    r' \S+ \S+'         #    ident, auth (ignored)
    r' \[(.+?)\]'       # 2  timestamp
    r' "(\S+)'          # 3  method
    r' (\S+)'           # 4  path
    r' \S+"'            #    protocol
    r' (\d{3})'         # 5  status
    r' (\S+)'           # 6  size (may be "-")
    r' "(.+?)"'         # 7  referrer
    r' "(.+?)"$'        # 8  user-agent
)

_TS_FORMAT = '%d/%b/%Y:%H:%M:%S %z'


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int           # bytes; 0 when "-"
    referrer: str
    user_agent: str
    hour: int           # 0-23, derived from timestamp


def parse_line(line: str) -> Optional[LogEntry]:
    """Return a LogEntry or None if the line is malformed."""
    m = _PATTERN.match(line.strip())
    if not m:
        return None
    ip, ts_raw, method, path, status, size_raw, referrer, ua = m.groups()
    try:
        ts   = datetime.strptime(ts_raw, _TS_FORMAT)
        size = int(size_raw) if size_raw != '-' else 0
    except (ValueError, OverflowError):
        return None
    return LogEntry(
        ip=ip,
        timestamp=ts,
        method=method,
        path=path,
        status=int(status),
        size=size,
        referrer=referrer,
        user_agent=ua,
        hour=ts.hour,
    )


def parse_file(path: str) -> pd.DataFrame:
    """Parse a log file into a DataFrame. Malformed lines are silently skipped."""
    entries = []
    skipped = 0
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            entry = parse_line(line)
            if entry:
                entries.append(entry.__dict__)
            else:
                skipped += 1

    if skipped:
        print(f'[parser] skipped {skipped} malformed line(s)')

    if not entries:
        return pd.DataFrame(columns=[
            'ip', 'timestamp', 'method', 'path',
            'status', 'size', 'referrer', 'user_agent', 'hour',
        ])

    return pd.DataFrame(entries)
