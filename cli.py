#!/usr/bin/env python3
"""
log-anomaly-detector — CLI entry point

Usage:
    python cli.py access.log
    python cli.py access.log --config config.json --output alerts.json --no-colour
"""

import argparse
import json
import sys

from detector.parser import parse_file
from detector.detectors import run_all
from detector.reporter import print_report, write_json


def load_config(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f'[cli] config file "{path}" not found — using defaults', file=sys.stderr)
        return {}
    except json.JSONDecodeError as e:
        print(f'[cli] invalid config JSON: {e}', file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog='log-anomaly-detector',
        description='Detect anomalies in Apache/Nginx access logs',
    )
    parser.add_argument('logfile',            help='Path to log file')
    parser.add_argument('--config', '-c',     default='config.json', help='JSON config file (default: config.json)')
    parser.add_argument('--output', '-o',     default='alerts.json',  help='JSON output file (default: alerts.json)')
    parser.add_argument('--no-colour',        action='store_true',    help='Disable ANSI colour output')
    args = parser.parse_args()

    config = load_config(args.config)

    print(f'[cli] parsing {args.logfile} …')
    df = parse_file(args.logfile)

    if df.empty:
        print('[cli] no valid log lines found — exiting')
        sys.exit(0)

    print(f'[cli] {len(df):,} log lines parsed')

    alerts = run_all(df, config)

    print_report(alerts, use_colour=not args.no_colour)
    write_json(alerts, args.output)


if __name__ == '__main__':
    main()
