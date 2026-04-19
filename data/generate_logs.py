#!/usr/bin/env python3
"""
Generate 30 days of synthetic Velaris.io log data.

Produces CloudWatch Insights-format JSON (same @timestamp/@message structure
as real exports) so ingest.py processes them without modification.

Two ground-truth incidents are injected on the evaluation day (2026-04-18):
  INCIDENT_1  14:00-14:30  token-ms HTTP 500 spike       (dependency failure)
  INCIDENT_2  18:30-19:00  success-plan latency + 503s   (resource contention)

Usage:
    python data/generate_logs.py
    python ingestion/ingest.py data/raw/synthetic-*.json
"""
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)  # reproducible runs

# ---------------------------------------------------------------------------
# Time windows
# ---------------------------------------------------------------------------
BASELINE_START = datetime(2026, 3, 20, 0, 0, 0)   # 29 days of normal traffic
EVAL_DAY_END   = datetime(2026, 4, 19, 0, 0, 0)   # exclusive end

INCIDENT_1 = (datetime(2026, 4, 18, 14, 0), datetime(2026, 4, 18, 14, 30))
INCIDENT_2 = (datetime(2026, 4, 18, 18, 30), datetime(2026, 4, 18, 19, 0))

OUT_DIR = Path(__file__).parent / 'raw'

TENANTS = ['velaris_prod', 'acme_corp', 'contoso', 'northwind', 'pop_v1_template']

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt_ts(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime('%Y-%m-%d %H:%M:%S.') + f'{ms:03d}'


def inner_ts(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{ms:03d}Z'


def new_corr() -> str:
    return str(uuid.uuid4())


def new_span() -> str:
    return str(random.randint(10**17, 10**18 - 1))


def traffic_weight(dt: datetime) -> float:
    """0.2–1.0 multiplier — lower at night and weekends."""
    if dt.hour < 6 or dt.hour >= 22:
        return 0.2
    if dt.weekday() >= 5:                       # weekend
        return 0.4
    if 9 <= dt.hour < 18:                       # core business hours
        return 1.0
    return 0.6


def in_window(dt: datetime, window: tuple) -> bool:
    return window[0] <= dt < window[1]


# ---------------------------------------------------------------------------
# Format A  —  token-ms
# ---------------------------------------------------------------------------

def _ansi(level: str) -> tuple[str, str]:
    codes = {'info': '32', 'error': '31', 'warn': '33', 'debug': '34'}
    c = codes.get(level, '32')
    return f'\x1b[{c}m', '\x1b[39m'


def make_token_request(dt: datetime, method: str, path: str,
                       status: int, duration_ms: float) -> list[dict]:
    trace = new_span()
    span  = new_span()
    dd    = json.dumps({
        'dd': {
            'env': 'dev',
            'service': 'dev-internal-token-ms-service',
            'span_id': span,
            'trace_id': trace,
            'version': 'token-ms',
        }
    })

    start_msg = (
        f'\x1b[32minfo\x1b[39m: [Start Request] {method} {path} {dd}'
    )

    on, off = _ansi('info' if status < 400 else 'error')
    bytes_out = random.randint(1100, 1400) if status == 200 else 118
    end_msg = (
        f'{on}info{off}: [End Request] {method} {path} '
        f'{status} {bytes_out} - {duration_ms:.3f} ms'
    )

    end_dt = dt + timedelta(milliseconds=duration_ms)
    return [
        {'@timestamp': fmt_ts(dt),    '@message': start_msg},
        {'@timestamp': fmt_ts(end_dt), '@message': end_msg},
        {'@timestamp': fmt_ts(end_dt), '@message': {
            'dd': {'env': 'dev', 'service': 'dev-internal-token-ms-service',
                   'span_id': span, 'trace_id': trace, 'version': 'token-ms'}
        }},
    ]


def generate_token_ms(dt: datetime, incident: bool) -> list[dict]:
    entries: list[dict] = []
    w = traffic_weight(dt)

    # Health check every minute
    entries += make_token_request(
        dt, 'GET', '/csm/v1/token-generation/health',
        200, round(random.uniform(0.2, 1.5), 3),
    )

    # Business requests: 4-8 per minute during business hours (realistic API load)
    if 7 <= dt.hour < 21:
        n_requests = int(w * random.randint(4, 8))
        for _ in range(n_requests):
            offset_ms = random.uniform(0, 55_000)
            req_dt    = dt + timedelta(milliseconds=offset_ms)
            if incident:
                error_prob = 0.70           # 70 % error rate during incident
                duration   = random.uniform(180, 400)
            else:
                error_prob = 0.008          # 0.8 % baseline error rate
                duration   = random.uniform(8, 45)
            status = 500 if random.random() < error_prob else 200
            path   = random.choice([
                '/csm/v1/token-generation/internal/token',
                '/csm/v1/token-generation/internal/applicationToken',
                '/csm/v1/token-generation/internal/tenantApplicationToken',
            ])
            entries += make_token_request(req_dt, 'POST', path, status, round(duration, 3))

    return entries


# ---------------------------------------------------------------------------
# Format B  —  success-plan-ms
# ---------------------------------------------------------------------------

def make_success_plan_request(dt: datetime, status: int,
                              duration_ms: float) -> list[dict]:
    corr  = new_corr()
    its   = inner_ts(dt)
    on_s, off_s = _ansi('info')
    on_e, off_e = _ansi('info' if status < 400 else 'error')

    bytes_out = random.choice([256, 257]) if status == 200 else 0
    level_e   = 'info' if status < 400 else 'error'

    start = (
        f'{on_s}info{off_s}|NO_CORRELATION|NO_TENANT|{its}:'
        f'\tGET /csm/v1/success-plan/health'
    )
    end_dt = dt + timedelta(milliseconds=duration_ms)
    end    = (
        f'{on_e}{level_e}{off_e}|{corr}|NO_TENANT|{inner_ts(end_dt)}:'
        f'\t[{corr}] GET /csm/v1/success-plan/health '
        f'{status} {bytes_out} - {duration_ms:.3f} ms'
    )
    return [
        {'@timestamp': fmt_ts(dt),    '@message': start},
        {'@timestamp': fmt_ts(end_dt), '@message': end},
    ]


def generate_success_plan(dt: datetime, incident: bool) -> list[dict]:
    entries: list[dict] = []
    w = traffic_weight(dt)
    if w < 0.3:
        return entries

    # 3-6 requests per minute during active hours
    n_requests = max(1, int(w * random.randint(3, 6)))
    for _ in range(n_requests):
        offset_ms = random.uniform(0, 55_000)
        req_dt    = dt + timedelta(milliseconds=offset_ms)
        if incident:
            duration = random.uniform(800, 5000)
            status   = 503 if random.random() < 0.35 else 200
        else:
            duration = max(0.1, random.gauss(1.2, 0.8))
            status   = 200
        entries += make_success_plan_request(req_dt, status, round(duration, 3))

    return entries


# ---------------------------------------------------------------------------
# Format C  —  crm-event-handler
# ---------------------------------------------------------------------------

def make_handler_entry(dt: datetime, level: str, tenant: str,
                       operation: str, message: str) -> dict:
    corr   = new_corr()
    its    = inner_ts(dt)
    on, off = _ansi(level)
    msg    = (
        f'{on}{level}{off}|{corr}|{tenant}|{its}|H->V|{operation}:'
        f'\t{message}'
    )
    return {'@timestamp': fmt_ts(dt), '@message': msg}


def generate_event_handler(dt: datetime, incident: bool) -> list[dict]:
    entries: list[dict] = []

    # Interval sync every 15 minutes
    if dt.minute % 15 != 0 or random.random() > 0.9:
        return entries

    tenant = random.choice(TENANTS)

    # Baseline: ~3 % SQS error rate
    if random.random() < 0.03:
        entries.append(make_handler_entry(
            dt, 'error', tenant, 'INTERVAL_SYNC',
            'Processing Failed: SQS connection timeout — retrying',
        ))
        entries.append(make_handler_entry(
            dt, 'warn', tenant, 'INTERVAL_SYNC',
            'Retrying event',
        ))
    else:
        emails = random.randint(0, 12)
        entries.append(make_handler_entry(
            dt, 'info', tenant, 'INTERVAL_SYNC',
            f'INFO|EMAIL|HUBSPOT_EMAIL/INTERVAL_SYNC|Fetched {emails} emails.',
        ))
        entries.append(make_handler_entry(
            dt, 'info', tenant, 'INTERVAL_SYNC',
            'INFO|EMAIL|HUBSPOT_EMAIL/INTERVAL_SYNC|All email pages fetched.',
        ))

    return entries


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def generate_all() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    token_entries:   list[dict] = []
    success_entries: list[dict] = []
    handler_entries: list[dict] = []

    current  = BASELINE_START
    step     = timedelta(minutes=1)
    total    = int((EVAL_DAY_END - BASELINE_START).total_seconds() / 60)
    reported = -1

    print(f'Generating {total:,} minutes of synthetic logs...')

    while current < EVAL_DAY_END:
        pct = int(100 * (current - BASELINE_START).total_seconds() /
                  (EVAL_DAY_END - BASELINE_START).total_seconds())
        if pct != reported:
            print(f'  {pct:3d}%  {current.date()}', end='\r', flush=True)
            reported = pct

        inc1 = in_window(current, INCIDENT_1)
        inc2 = in_window(current, INCIDENT_2)

        token_entries   += generate_token_ms(current,    incident=inc1)
        success_entries += generate_success_plan(current, incident=inc2)
        handler_entries += generate_event_handler(current, incident=False)

        current += step

    print()

    files = {
        'synthetic-token-ms.json':       token_entries,
        'synthetic-success-plan.json':   success_entries,
        'synthetic-event-handler.json':  handler_entries,
    }

    for name, data in files.items():
        path = OUT_DIR / name
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        kb = path.stat().st_size // 1024
        print(f'  {name}: {len(data):,} entries  ({kb:,} KB)')

    print('\nIncident ground truth:')
    print(f'  INCIDENT_1  {INCIDENT_1[0]} – {INCIDENT_1[1].strftime("%H:%M")}  '
          f'token-ms 500 spike')
    print(f'  INCIDENT_2  {INCIDENT_2[0]} – {INCIDENT_2[1].strftime("%H:%M")}  '
          f'success-plan latency spike')
    print('\nNext step:')
    print('  python ingestion/ingest.py data/raw/synthetic-token-ms.json '
          'data/raw/synthetic-success-plan.json data/raw/synthetic-event-handler.json')


if __name__ == '__main__':
    generate_all()
