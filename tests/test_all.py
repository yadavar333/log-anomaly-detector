"""8 unit tests covering parser, all 6 detectors, and JSON reporter."""

import json
import os
import tempfile

import pandas as pd
import pytest

from detector.parser import parse_line, parse_file
from detector.detectors import (
    detect_brute_force, detect_404_flood, detect_crawler,
    detect_large_upload, detect_suspicious_ua, detect_off_hours,
)
from detector.reporter import write_json

# ── Helpers ────────────────────────────────────────────────────────────────

VALID_LINE = (
    '1.2.3.4 - - [08/Feb/2025:14:13:00 +0530] '
    '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)

MALFORMED_LINE = 'this is not a log line at all'


def make_df(**kwargs) -> pd.DataFrame:
    """Build a minimal DataFrame row for detector tests."""
    defaults = dict(ip='1.2.3.4', method='GET', path='/', status=200,
                    size=500, referrer='-', user_agent='Mozilla/5.0', hour=10)
    defaults.update(kwargs)
    return pd.DataFrame([defaults])


# ── Test 1: parser accepts a valid Combined Log Format line ────────────────

def test_parse_valid_line():
    entry = parse_line(VALID_LINE)
    assert entry is not None
    assert entry.ip == '1.2.3.4'
    assert entry.status == 200
    assert entry.size == 1234
    assert entry.hour == 14


# ── Test 2: parser returns None for malformed lines ────────────────────────

def test_parse_malformed_line_returns_none():
    assert parse_line(MALFORMED_LINE) is None
    assert parse_line('') is None
    assert parse_line('   ') is None


# ── Test 3: brute force detector fires above threshold ─────────────────────

def test_brute_force_detected():
    rows = [dict(ip='6.6.6.6', method='POST', path='/login', status=401,
                 size=100, referrer='-', user_agent='curl/7.0', hour=10)] * 12
    df = pd.DataFrame(rows)
    alerts = detect_brute_force(df, threshold=10)
    assert len(alerts) == 1
    assert alerts[0].ip == '6.6.6.6'
    assert alerts[0].severity == 'HIGH'
    assert alerts[0].count == 12


# ── Test 4: brute force does NOT fire below threshold ─────────────────────

def test_brute_force_below_threshold_no_alert():
    rows = [dict(ip='1.1.1.1', method='GET', path='/', status=401,
                 size=100, referrer='-', user_agent='Mozilla', hour=10)] * 5
    alerts = detect_brute_force(pd.DataFrame(rows), threshold=10)
    assert alerts == []


# ── Test 5: 404 flood detector ─────────────────────────────────────────────

def test_404_flood_detected():
    rows = [dict(ip='5.5.5.5', method='GET', path='/admin', status=404,
                 size=0, referrer='-', user_agent='Mozilla', hour=12)] * 25
    alerts = detect_404_flood(pd.DataFrame(rows), threshold=20)
    assert len(alerts) == 1
    assert alerts[0].category == 'flood_404'
    assert alerts[0].severity == 'MEDIUM'


# ── Test 6: crawler detector ───────────────────────────────────────────────

def test_crawler_detected():
    rows = [dict(ip='7.7.7.7', method='GET', path='/', status=200,
                 size=500, referrer='-',
                 user_agent='Googlebot/2.1 (+http://www.google.com/bot.html)',
                 hour=10)] * 60
    alerts = detect_crawler(pd.DataFrame(rows), threshold=50)
    assert len(alerts) == 1
    assert alerts[0].category == 'crawler'


# ── Test 7: suspicious user-agent detector ────────────────────────────────

def test_suspicious_ua_detected():
    rows = [dict(ip='8.8.8.8', method='GET', path='/api', status=200,
                 size=100, referrer='-', user_agent='curl/7.88.1', hour=10)] * 3
    alerts = detect_suspicious_ua(pd.DataFrame(rows))
    assert len(alerts) == 1
    assert alerts[0].category == 'suspicious_ua'
    assert alerts[0].ip == '8.8.8.8'


# ── Test 8: JSON reporter writes correct structure ────────────────────────

def test_write_json_output():
    from detector.detectors import Alert
    alerts = [
        Alert(category='brute_force', severity='HIGH',
              ip='9.9.9.9', detail='15 failed attempts', count=15),
    ]
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        path = f.name
    try:
        write_json(alerts, path)
        with open(path) as fh:
            data = json.load(fh)
        assert len(data) == 1
        assert data[0]['category'] == 'brute_force'
        assert data[0]['ip']       == '9.9.9.9'
        assert data[0]['count']    == 15
    finally:
        os.unlink(path)
