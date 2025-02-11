# Log Anomaly Detector

CLI tool that parses Apache/Nginx Combined Log Format files and detects 6 anomaly categories. Outputs a coloured terminal report and a JSON alert file. All thresholds are configurable via a JSON config file.

## Stack
Python · Pandas · Regex · argparse · pytest

## Detectors

| Category | Severity | What it flags |
|----------|----------|---------------|
| `brute_force` | HIGH | IPs with ≥ N × HTTP 401 responses |
| `flood_404` | MEDIUM | IPs with ≥ N × HTTP 404 responses (directory scanning) |
| `crawler` | LOW | IPs whose user-agent matches bot/spider/crawler keywords |
| `large_upload` | MEDIUM | POST requests where response size exceeds threshold |
| `suspicious_ua` | LOW | Requests from curl, wget, python-requests, etc. |
| `off_hours` | LOW | Requests arriving during configured off-hours |

## Usage

```bash
pip install -r requirements.txt

# Generate 10k-line sample log with planted anomalies
python generate_logs.py sample.log

# Analyse
python cli.py sample.log
python cli.py sample.log --config config.json --output alerts.json
python cli.py sample.log --no-colour      # disable ANSI colour
```

## Sample Output

```
════════════════════════════════════════════════════════════
  LOG ANOMALY REPORT
════════════════════════════════════════════════════════════
  Total alerts : 6
  HIGH   : 1
  MEDIUM : 2
  LOW    : 3
────────────────────────────────────────────────────────────

  🔴  HIGH
    [BRUTE_FORCE    ] 10.0.0.1  — 15 failed auth attempts (HTTP 401)  (n=15)

  🟡  MEDIUM
    [FLOOD_404      ] 10.0.0.2  — 30 Not-Found responses — possible directory scan  (n=30)
    [LARGE_UPLOAD   ] 10.0.0.4  — POST response size up to 44,707,450 bytes  (n=3)

  🔵  LOW
    [CRAWLER        ] 10.0.0.3  — 80 requests with crawler UA  (n=80)
    [SUSPICIOUS_UA  ] 10.0.0.5  — 5 request(s) with automation UA: "curl/7.88.1"  (n=5)
    [OFF_HOURS      ] 10.0.0.6  — 12 request(s) during off-hours [0, 1, 2, 3]  (n=12)
```

## Config

Edit `config.json` to tune thresholds:

```json
{
  "brute_force_threshold":   10,
  "flood_404_threshold":     20,
  "crawler_threshold":       50,
  "upload_threshold_bytes":  10485760,
  "off_hours":               [23, 0, 1, 2, 3, 4, 5]
}
```

## Tests

```bash
pytest tests/ -v --cov=detector
```

8 tests covering the parser, all 6 detectors, and the JSON reporter.

## Project Structure

```
log-anomaly-detector/
├── detector/
│   ├── parser.py       # regex → DataFrame, malformed-line handling
│   ├── detectors.py    # 6 detection functions
│   └── reporter.py     # ANSI colour terminal + JSON file writer
├── tests/
│   └── test_all.py     # 8 pytest unit tests
├── cli.py              # argparse entry point
├── config.json         # default thresholds
└── generate_logs.py    # 10k-line log generator with planted anomalies
```
