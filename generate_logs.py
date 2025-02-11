#!/usr/bin/env python3
"""
Generate a 10 000-line sample access log with planted anomalies.

Planted anomalies:
  - 10.0.0.1  → 15 × HTTP 401  (brute force)
  - 10.0.0.2  → 30 × HTTP 404  (404 flood)
  - 10.0.0.3  → 80 requests with "Googlebot/2.1 (+http://bot.google.com/bot.html)" UA (crawler)
  - 10.0.0.4  → 3 large POST responses (>10 MB)
  - 10.0.0.5  → 5 requests with "curl/7.88.1" UA (suspicious UA)
  - 10.0.0.6  → 12 requests at 02:00 (off-hours)
"""

import random
import sys
from datetime import datetime, timezone, timedelta

IST = timezone(timedelta(hours=5, minutes=30))

NORMAL_IPS  = [f'192.168.1.{i}' for i in range(10, 110)]
NORMAL_UAS  = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
]
PATHS       = ['/','  /about','/api/users','/api/posts','/login','/dashboard','/static/app.js','/static/style.css']
STATUSES    = [200]*70 + [301]*5 + [302]*5 + [400]*5 + [403]*3 + [500]*2


def ts(hour: int = None) -> str:
    h = hour if hour is not None else random.randint(8, 22)
    dt = datetime(2025, 2, 8, h, random.randint(0, 59), random.randint(0, 59), tzinfo=IST)
    return dt.strftime('%d/%b/%Y:%H:%M:%S %z')


def normal_line(ip: str = None, ua: str = None, status: int = None,
                hour: int = None, size: int = None, method: str = 'GET') -> str:
    ip     = ip     or random.choice(NORMAL_IPS)
    ua     = ua     or random.choice(NORMAL_UAS)
    status = status or random.choice(STATUSES)
    path   = random.choice(PATHS)
    sz     = size   or random.randint(200, 5000)
    return (f'{ip} - - [{ts(hour)}] "{method} {path} HTTP/1.1" '
            f'{status} {sz} "-" "{ua}"')


def generate(output: str = 'sample.log', n: int = 10_000):
    lines = []

    # ── Planted anomalies ──────────────────────────────────────────────
    # 1. Brute force: 10.0.0.1 → 15 × 401
    for _ in range(15):
        lines.append(normal_line(ip='10.0.0.1', status=401, method='POST'))

    # 2. 404 flood: 10.0.0.2 → 30 × 404
    for _ in range(30):
        lines.append(normal_line(ip='10.0.0.2', status=404))

    # 3. Crawler: 10.0.0.3 → 80 requests with bot UA
    for _ in range(80):
        lines.append(normal_line(ip='10.0.0.3',
                                 ua='Googlebot/2.1 (+http://www.google.com/bot.html)'))

    # 4. Large upload: 10.0.0.4 → 3 large POST responses
    for _ in range(3):
        lines.append(normal_line(ip='10.0.0.4', method='POST',
                                 size=random.randint(10_485_760, 52_428_800)))

    # 5. Suspicious UA: 10.0.0.5 → 5 curl requests
    for _ in range(5):
        lines.append(normal_line(ip='10.0.0.5', ua='curl/7.88.1'))

    # 6. Off-hours: 10.0.0.6 → 12 requests at 02:xx
    for _ in range(12):
        lines.append(normal_line(ip='10.0.0.6', hour=2))

    # ── Normal traffic ─────────────────────────────────────────────────
    while len(lines) < n:
        lines.append(normal_line())

    random.shuffle(lines)

    with open(output, 'w') as fh:
        fh.write('\n'.join(lines) + '\n')

    print(f'Generated {len(lines):,} log lines → {output}')
    print('Planted anomalies:')
    print('  10.0.0.1 → brute force (15 × 401)')
    print('  10.0.0.2 → 404 flood   (30 × 404)')
    print('  10.0.0.3 → crawler     (80 × Googlebot UA)')
    print('  10.0.0.4 → large POST  (3 × >10 MB)')
    print('  10.0.0.5 → suspicious  (5 × curl UA)')
    print('  10.0.0.6 → off-hours   (12 × 02:xx)')


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else 'sample.log'
    generate(out)
