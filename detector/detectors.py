"""Six anomaly detectors operating on a parsed log DataFrame."""

from dataclasses import dataclass, field
from typing import List

import pandas as pd


@dataclass
class Alert:
    category: str       # brute_force | flood_404 | crawler | large_upload | suspicious_ua | off_hours
    severity: str       # HIGH | MEDIUM | LOW
    ip: str
    detail: str
    count: int


def detect_brute_force(df: pd.DataFrame, threshold: int = 10) -> List[Alert]:
    """IPs with >= threshold 401 responses (failed auth)."""
    alerts = []
    failed = df[df['status'] == 401].groupby('ip').size()
    for ip, count in failed.items():
        if count >= threshold:
            alerts.append(Alert(
                category='brute_force',
                severity='HIGH',
                ip=ip,
                detail=f'{count} failed auth attempts (HTTP 401)',
                count=count,
            ))
    return alerts


def detect_404_flood(df: pd.DataFrame, threshold: int = 20) -> List[Alert]:
    """IPs with >= threshold 404 responses (directory scanning)."""
    alerts = []
    floods = df[df['status'] == 404].groupby('ip').size()
    for ip, count in floods.items():
        if count >= threshold:
            alerts.append(Alert(
                category='flood_404',
                severity='MEDIUM',
                ip=ip,
                detail=f'{count} Not-Found responses — possible directory scan',
                count=count,
            ))
    return alerts


def detect_crawler(df: pd.DataFrame, threshold: int = 50) -> List[Alert]:
    """IPs whose user-agent contains crawler/bot/spider keywords."""
    keywords = r'bot|crawler|spider|scraper|scan|harvest'
    mask = df['user_agent'].str.lower().str.contains(keywords, regex=True, na=False)
    crawler_df = df[mask]
    alerts = []
    for ip, grp in crawler_df.groupby('ip'):
        count = len(grp)
        if count >= threshold:
            sample_ua = grp['user_agent'].iloc[0]
            alerts.append(Alert(
                category='crawler',
                severity='LOW',
                ip=ip,
                detail=f'{count} requests with crawler UA — e.g. "{sample_ua[:60]}"',
                count=count,
            ))
    return alerts


def detect_large_upload(df: pd.DataFrame, threshold_bytes: int = 10_485_760) -> List[Alert]:
    """POST requests where response size exceeds threshold (default 10 MB)."""
    mask = (df['method'] == 'POST') & (df['size'] > threshold_bytes)
    large = df[mask]
    alerts = []
    for ip, grp in large.groupby('ip'):
        max_size = grp['size'].max()
        alerts.append(Alert(
            category='large_upload',
            severity='MEDIUM',
            ip=ip,
            detail=f'POST response size up to {max_size:,} bytes ({len(grp)} request(s))',
            count=len(grp),
        ))
    return alerts


def detect_suspicious_ua(df: pd.DataFrame) -> List[Alert]:
    """IPs using automation tool user-agents (curl, wget, python-requests, etc.)."""
    keywords = r'^curl/|^wget/|python-requests|go-http-client|libwww-perl|java/'
    mask = df['user_agent'].str.lower().str.contains(keywords, regex=True, na=False)
    sus_df = df[mask]
    alerts = []
    for ip, grp in sus_df.groupby('ip'):
        ua = grp['user_agent'].iloc[0]
        alerts.append(Alert(
            category='suspicious_ua',
            severity='LOW',
            ip=ip,
            detail=f'{len(grp)} request(s) with automation UA: "{ua[:60]}"',
            count=len(grp),
        ))
    return alerts


def detect_off_hours(df: pd.DataFrame, off_hours: List[int] = None) -> List[Alert]:
    """IPs active during off-hours (default 23:00–05:59)."""
    if off_hours is None:
        off_hours = [23, 0, 1, 2, 3, 4, 5]
    mask = df['hour'].isin(off_hours)
    night_df = df[mask]
    alerts = []
    for ip, grp in night_df.groupby('ip'):
        count = len(grp)
        hours = sorted(grp['hour'].unique().tolist())
        alerts.append(Alert(
            category='off_hours',
            severity='LOW',
            ip=ip,
            detail=f'{count} request(s) during off-hours {hours}',
            count=count,
        ))
    return alerts


def run_all(df: pd.DataFrame, config: dict) -> List[Alert]:
    """Run all 6 detectors and return combined alert list."""
    alerts: List[Alert] = []
    alerts += detect_brute_force(df,    threshold=config.get('brute_force_threshold', 10))
    alerts += detect_404_flood(df,      threshold=config.get('flood_404_threshold', 20))
    alerts += detect_crawler(df,        threshold=config.get('crawler_threshold', 50))
    alerts += detect_large_upload(df,   threshold_bytes=config.get('upload_threshold_bytes', 10_485_760))
    alerts += detect_suspicious_ua(df)
    alerts += detect_off_hours(df,      off_hours=config.get('off_hours', [23, 0, 1, 2, 3, 4, 5]))
    return alerts
