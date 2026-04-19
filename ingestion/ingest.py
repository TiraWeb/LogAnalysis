#!/usr/bin/env python3
"""
Ingest CloudWatch Insights JSON exports into OpenObserve.

Handles three log formats used across Velaris.io microservices:
  Format A  token-ms       "info: [End Request] POST /path 200 118 - 11ms {dd json}"
  Format B  success-plan   "info|corr_id|tenant|ts:\t[corr] GET /path 200 257 - 0.3ms"
  Format C  event-handlers "error|corr_id|tenant|ts|direction|OPERATION:\tMessage text"
"""
import re
import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')

OZ_URL    = os.getenv('OPENOBSERVE_URL',    'http://localhost:5080')
OZ_USER   = os.getenv('OPENOBSERVE_USER',   'admin@velaris.local')
OZ_PASS   = os.getenv('OPENOBSERVE_PASS',   'Admin1234!')
OZ_ORG    = os.getenv('OPENOBSERVE_ORG',    'default')
OZ_STREAM = os.getenv('OPENOBSERVE_STREAM', 'velaris_logs')

BATCH_SIZE = 500

ANSI_RE       = re.compile(r'\x1b\[[0-9;]*m')
LEVEL_RE      = re.compile(r'^(info|error|warn|debug|trace)', re.IGNORECASE)
HTTP_RE       = re.compile(
    r'(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(/\S*)'
    r'(?:\s+(\d{3})\s+(\d+|-)\s+-\s+([\d.]+)\s+ms)?'
)
# Lines that are part of a stack trace / object dump — skip these
NOISE_RE = re.compile(r"^\s{2,}|^[{}]$|^\s*['\"]?\s*at\s+\w")

# URL path segment → canonical service name
PATH_SERVICE_MAP = {
    'success-plan':     'success-plan-ms',
    'token-generation': 'token-ms',
}


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub('', s)


def ts_to_us(ts_str: str) -> int:
    """'2026-04-19 15:28:02.019' → microseconds since epoch."""
    dt = datetime.strptime(ts_str.strip(), '%Y-%m-%d %H:%M:%S.%f')
    return int(dt.timestamp() * 1_000_000)


def extract_http(text: str) -> dict:
    m = HTTP_RE.search(text)
    if not m:
        return {}
    rec = {'method': m.group(1), 'path': m.group(2)}
    if m.group(3):
        rec['status_code'] = int(m.group(3))
    if m.group(4) and m.group(4) != '-':
        rec['response_bytes'] = int(m.group(4))
    if m.group(5):
        rec['duration_ms'] = float(m.group(5))
    return rec


def service_from_path(path: str) -> str | None:
    for segment in path.split('/'):
        if segment in PATH_SERVICE_MAP:
            return PATH_SERVICE_MAP[segment]
    return None


def _parse_format_a(clean: str, record: dict) -> dict | None:
    """token-ms: 'info: [action] METHOD /path [status bytes - dur ms] [{dd}]'"""
    m = LEVEL_RE.match(clean)
    if not m:
        return None
    record['level'] = m.group(1).lower()
    rest = clean[clean.index(':') + 1:].strip()

    # Extract and remove the trailing {"dd":{...}} blob
    idx = rest.find('{"dd":')
    if idx >= 0:
        try:
            dd = json.loads(rest[idx:])['dd']
            record['service']  = dd.get('service')
            record['trace_id'] = dd.get('trace_id')
            record['span_id']  = dd.get('span_id')
            rest = rest[:idx].strip()
        except (json.JSONDecodeError, KeyError):
            pass

    # Strip [Start Request] / [End Request] action tag
    act_m = re.match(r'\[([^\]]+)\]\s*', rest)
    if act_m:
        record['action'] = act_m.group(1)
        rest = rest[act_m.end():]

    record['message'] = rest
    return record


def _parse_format_bc(clean: str, record: dict) -> dict | None:
    """
    Format B (4 pipe parts): info|corr|tenant|inner_ts:\tmessage
    Format C (6 pipe parts): info|corr|tenant|inner_ts|direction|OP:\tmessage
    """
    parts = clean.split('|', 5)
    m = LEVEL_RE.match(parts[0])
    record['level'] = m.group(1).lower() if m else 'info'

    record['correlation_id'] = (
        parts[1]
        if len(parts) > 1 and parts[1] not in ('NO_CORRELATION', '')
        else None
    )
    record['tenant'] = (
        parts[2]
        if len(parts) > 2 and parts[2] not in ('NO_TENANT', '')
        else None
    )

    if len(parts) == 6:
        # Format C — direction + operation
        record['direction'] = parts[4]
        tail = parts[5]
        if '\t' in tail:
            op, msg = tail.split('\t', 1)
            record['operation'] = op.rstrip(':')
            record['message']   = msg
        else:
            record['message'] = tail
    else:
        # Format B — message follows inner timestamp after tab
        tail = parts[3] if len(parts) > 3 else ''
        record['message'] = tail.split('\t', 1)[1] if '\t' in tail else tail

    return record


def parse_entry(raw_ts: str, raw_msg, fallback_service: str) -> dict | None:
    # Bare dict entries are dd context objects logged separately — skip
    if isinstance(raw_msg, dict):
        return None

    clean = strip_ansi(str(raw_msg)).strip()

    if not clean or NOISE_RE.match(clean):
        return None

    try:
        _timestamp = ts_to_us(raw_ts)
    except ValueError:
        return None

    record: dict = {'_timestamp': _timestamp}

    # Route to correct parser based on position of first pipe vs first colon
    pipe_pos  = clean.find('|')
    colon_pos = clean.find(':')

    if 0 < pipe_pos < 10:
        result = _parse_format_bc(clean, record)
    elif 0 < colon_pos < 10:
        result = _parse_format_a(clean, record)
    else:
        return None

    if result is None:
        return None

    # Attach HTTP fields parsed from the message text
    record.update(extract_http(record.get('message', '')))

    # Service name: Format A extracts from dd.service; others use path or fallback
    if not record.get('service'):
        record['service'] = (
            service_from_path(record['path'])
            if 'path' in record
            else fallback_service
        )

    # Convenience boolean columns used by the analytics engine
    record['is_error']   = record.get('level') == 'error'
    record['is_warning'] = record.get('level') == 'warn'

    if 'message' in record:
        record['message'] = record['message'][:1000]

    return record


def push_batch(records: list, session: requests.Session) -> None:
    url = f'{OZ_URL}/api/{OZ_ORG}/{OZ_STREAM}/_json'
    resp = session.post(url, json=records, timeout=30)
    resp.raise_for_status()


def ingest_file(
    fpath: Path,
    service_override: str | None,
    session: requests.Session,
) -> tuple[int, int]:
    fallback = service_override or fpath.stem.lower().replace(' ', '-')

    with open(fpath, encoding='utf-8') as f:
        entries = json.load(f)

    records: list[dict] = []
    skipped = 0
    for entry in entries:
        rec = parse_entry(
            entry.get('@timestamp', ''),
            entry.get('@message', ''),
            fallback,
        )
        if rec:
            records.append(rec)
        else:
            skipped += 1

    sent = 0
    for i in range(0, len(records), BATCH_SIZE):
        push_batch(records[i : i + BATCH_SIZE], session)
        sent += len(records[i : i + BATCH_SIZE])

    return sent, skipped


def main() -> None:
    ap = argparse.ArgumentParser(
        description='Ingest CloudWatch Insights JSON exports into OpenObserve'
    )
    ap.add_argument(
        'files', nargs='*',
        help='JSON files to ingest (default: every *.json in data/raw/)',
    )
    ap.add_argument('--service', help='Force a service name for all files')
    args = ap.parse_args()

    if args.files:
        files = [Path(f) for f in args.files]
    else:
        raw_dir = Path(__file__).parent.parent / 'data' / 'raw'
        files   = sorted(raw_dir.glob('*.json'))

    if not files:
        print('No JSON files found. Drop exports into data/raw/ or pass paths as arguments.')
        sys.exit(1)

    session = requests.Session()
    session.auth = (OZ_USER, OZ_PASS)
    session.headers['Content-Type'] = 'application/json'

    total_sent = total_skipped = 0
    for fpath in files:
        print(f'  {fpath.name}', end=' ... ', flush=True)
        try:
            sent, skipped = ingest_file(fpath, args.service, session)
            total_sent    += sent
            total_skipped += skipped
            print(f'{sent} ingested, {skipped} skipped')
        except requests.HTTPError as e:
            print(f'FAILED ({e})')

    print(f'\nDone — {total_sent} records ingested, {total_skipped} skipped')


if __name__ == '__main__':
    main()
