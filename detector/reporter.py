"""Terminal reporter (ANSI colour) and JSON file writer."""

import json
from dataclasses import asdict
from typing import List

from detector.detectors import Alert

# ANSI colour codes — no external deps
_COLOURS = {
    'HIGH':   '\033[91m',  # red
    'MEDIUM': '\033[93m',  # yellow
    'LOW':    '\033[94m',  # blue
    'RESET':  '\033[0m',
    'BOLD':   '\033[1m',
    'DIM':    '\033[2m',
}

_ICONS = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🔵'}


def print_report(alerts: List[Alert], use_colour: bool = True) -> None:
    """Print a formatted alert summary to stdout."""
    def c(colour: str, text: str) -> str:
        return f"{_COLOURS[colour]}{text}{_COLOURS['RESET']}" if use_colour else text

    if not alerts:
        print(c('DIM', 'No anomalies detected.'))
        return

    counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for a in alerts:
        counts[a.severity] += 1

    print()
    print(c('BOLD', '═' * 60))
    print(c('BOLD', '  LOG ANOMALY REPORT'))
    print(c('BOLD', '═' * 60))
    print(f"  Total alerts : {len(alerts)}")
    h, m, l = counts['HIGH'], counts['MEDIUM'], counts['LOW']
    print(f"  {c('HIGH',   f'HIGH   : {h}')}")
    print(f"  {c('MEDIUM', f'MEDIUM : {m}')}")
    print(f"  {c('LOW',    f'LOW    : {l}')}")
    print(c('BOLD', '─' * 60))
    print()

    # Group by severity order
    for severity in ('HIGH', 'MEDIUM', 'LOW'):
        group = [a for a in alerts if a.severity == severity]
        if not group:
            continue
        print(c('BOLD', f'  {_ICONS[severity]}  {severity}'))
        for a in group:
            cat   = c(severity, f'[{a.category.upper():15s}]')
            ip    = c('BOLD', a.ip.ljust(16))
            print(f'    {cat} {ip} — {a.detail}  (n={a.count})')
        print()


def write_json(alerts: List[Alert], output_path: str) -> None:
    """Serialise alerts to a JSON file."""
    data = [asdict(a) for a in alerts]
    with open(output_path, 'w') as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f'[reporter] {len(alerts)} alert(s) written to {output_path}')
