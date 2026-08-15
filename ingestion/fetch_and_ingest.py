#!/usr/bin/env python3
"""
fetch_and_ingest.py — fetch real DEV logs from all ECS services and ingest into OpenObserve.

Discovers every non-test ECS service across three DEV clusters:
  event-handler-dev-ecs-cluster
  internal-dev-ecs-cluster
  external-dev-ecs-cluster

Derives log-group names, fetches via FilterLogEvents (free — zero Logs Insights scan cost),
parses all four Velaris log formats (A/B/C/D), pushes to OpenObserve in batches.
Also auto-rewrites metrics/services.json with the full discovered service list
plus real DEV RDS/ASG identifiers.

Usage
-----
    python ingestion/fetch_and_ingest.py                 # 7-day window
    python ingestion/fetch_and_ingest.py --hours 48
    python ingestion/fetch_and_ingest.py --clear         # delete OZ stream first
    python ingestion/fetch_and_ingest.py --clear-metrics # also wipe SQLite metrics
    python ingestion/fetch_and_ingest.py --clear --clear-metrics --hours 168

AWS credentials
---------------
    export AWS_PROFILE=dev
    AWS_DEFAULT_REGION defaults to eu-west-1
"""
import argparse
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
import requests
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')

OZ_URL     = os.getenv('OPENOBSERVE_URL',    'http://localhost:5080')
OZ_USER    = os.getenv('OPENOBSERVE_USER',   'admin@velaris.local')
OZ_PASS    = os.getenv('OPENOBSERVE_PASS',   'Admin1234!')
OZ_ORG     = os.getenv('OPENOBSERVE_ORG',    'default')
OZ_STREAM  = os.getenv('OPENOBSERVE_STREAM', 'velaris_logs')
DB_PATH    = os.getenv('DB_PATH',            str(Path(__file__).parent.parent / 'db' / 'incidents.db'))
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'eu-west-2')

CLUSTERS = [
    'event-handler-dev-ecs-cluster',
    'internal-dev-ecs-cluster',
    'external-dev-ecs-cluster',
]

# Substrings that identify test/throwaway services — skip these
_TEST_KEYWORDS = ('test', 'pradeepa', 'zaptest', 'axiom-test')

BATCH_SIZE = 500
MAX_EVENTS = 10_000   # per log group — keeps memory bounded
_API_SLEEP = 0.15     # FilterLogEvents ~5 TPS limit

# Real DEV infrastructure identifiers
_DEV_RDS_ID  = 'dev-db-1'
_DEV_ASG_MAP = {
    'event-handler-cluster': 'event-handler-dev-cluster-AutoScalingGroup',
    'internal-cluster':      'internal-dev-ecs-cluster-ecs-cluster-AutoScalingGroup',
    'external-cluster':      'external-dev-ecs-cluster-ecs-cluster-AutoScalingGroup',
}

_SERVICES_JSON = Path(__file__).parent.parent / 'metrics' / 'services.json'

# ── Regex helpers ─────────────────────────────────────────────────────────────

_ANSI_RE  = re.compile(r'\x1b\[[0-9;]*m')
_LEVEL_RE = re.compile(r'^(info|error|warn|debug|trace)', re.IGNORECASE)
_HTTP_RE  = re.compile(
    r'(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(/\S*)'
    r'(?:\s+(\d{3})\s+(\d+|-)\s+-\s+([\d.]+)\s+ms)?'
)
# Indented stack-trace lines / bare brace objects — not useful to index
_NOISE_RE = re.compile(r"^\s{2,}|^[{}]$|^\s*['\"]?\s*at\s+\w")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s)


def _extract_http(text: str) -> dict:
    m = _HTTP_RE.search(text)
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


# ── Log format parsers ────────────────────────────────────────────────────────

def _parse_format_a(clean: str, record: dict) -> dict | None:
    """token-ms: 'info: [action] METHOD /path [status bytes - dur ms] [{dd}]'"""
    m = _LEVEL_RE.match(clean)
    if not m:
        return None
    record['level'] = m.group(1).lower()
    rest = clean[clean.index(':') + 1:].strip()

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
    m = _LEVEL_RE.match(parts[0])
    record['level'] = m.group(1).lower() if m else 'info'
    record['correlation_id'] = (
        parts[1] if len(parts) > 1 and parts[1] not in ('NO_CORRELATION', '') else None
    )
    record['tenant'] = (
        parts[2] if len(parts) > 2 and parts[2] not in ('NO_TENANT', '') else None
    )

    if len(parts) == 6:
        record['direction'] = parts[4]
        tail = parts[5]
        if '\t' in tail:
            op, msg = tail.split('\t', 1)
            record['operation'] = op.rstrip(':')
            record['message']   = msg
        else:
            record['message'] = tail
    else:
        tail = parts[3] if len(parts) > 3 else ''
        record['message'] = tail.split('\t', 1)[1] if '\t' in tail else tail

    return record


def _parse_format_d(clean: str, record: dict) -> dict | None:
    """JSON format: {"level":"error","message":"...", ...}"""
    try:
        obj = json.loads(clean)
        if not isinstance(obj, dict):
            return None
        record['level']   = str(obj.get('level', 'info')).lower()
        record['message'] = str(obj.get('message', obj.get('msg', '')))[:1000]
        for field in ('service', 'correlation_id', 'tenant', 'trace_id', 'span_id'):
            val = obj.get(field) or obj.get(field.replace('_', '-'))
            if val:
                record[field] = str(val)
        if 'stack' in obj:
            record['stack'] = str(obj['stack'])[:500]
        return record
    except (json.JSONDecodeError, ValueError):
        return None


def parse_event(raw_msg: str, epoch_ms: int, fallback_service: str) -> dict | None:
    clean = _strip_ansi(str(raw_msg)).strip()
    if not clean or _NOISE_RE.match(clean):
        return None

    record: dict = {'_timestamp': epoch_ms * 1_000}  # OpenObserve expects microseconds

    if clean.startswith('{'):
        result = _parse_format_d(clean, record)
    else:
        pipe_pos  = clean.find('|')
        colon_pos = clean.find(':')
        if 0 < pipe_pos < 10:
            result = _parse_format_bc(clean, record)
        elif 0 < colon_pos < 10:
            result = _parse_format_a(clean, record)
        else:
            result = None

    if result is None:
        return None

    record.update(_extract_http(record.get('message', '')))

    if not record.get('service'):
        record['service'] = fallback_service

    record['is_error']   = record.get('level') == 'error'
    record['is_warning'] = record.get('level') == 'warn'

    if 'message' in record:
        record['message'] = record['message'][:1000]

    return record


# ── Service discovery ─────────────────────────────────────────────────────────

def _is_test_service(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in _TEST_KEYWORDS)


def _derive_log_group(service_name: str) -> str:
    base = re.sub(r'(-ecs-service|-service)$', '', service_name)
    return f'{base}-ecs-cluster-task-LogsGroup'


def _derive_short_name(service_name: str, cluster: str) -> str:
    """Human-readable key used as log_service in metrics/services.json."""
    name = re.sub(r'(-ecs-service|-service)$', '', service_name)
    if 'event-handler' in cluster:
        name = re.sub(r'^dev-event-handler-', '', name)
    elif 'internal' in cluster:
        name = re.sub(r'^dev-internal-', '', name)
    elif 'external' in cluster:
        name = re.sub(r'^dev-external-', 'ext-', name)
    return name


def list_cluster_services(ecs_client, cluster: str) -> list[str]:
    names = []
    paginator = ecs_client.get_paginator('list_services')
    for page in paginator.paginate(cluster=cluster):
        for arn in page['serviceArns']:
            name = arn.split('/')[-1]
            if not _is_test_service(name):
                names.append(name)
    return names


# ── Log fetching ──────────────────────────────────────────────────────────────

def find_log_group(logs_client, service_name: str) -> str | None:
    """Return the actual log group name, or None if not found."""
    candidate = _derive_log_group(service_name)
    try:
        resp = logs_client.describe_log_groups(logGroupNamePrefix=candidate, limit=1)
        groups = resp.get('logGroups', [])
        return groups[0]['logGroupName'] if groups else None
    except ClientError:
        return None


def fetch_events(logs_client, log_group: str, start_ms: int, end_ms: int) -> list[dict]:
    events: list[dict] = []
    kwargs: dict = dict(logGroupName=log_group, startTime=start_ms, endTime=end_ms, limit=10_000)
    while len(events) < MAX_EVENTS:
        try:
            resp = logs_client.filter_log_events(**kwargs)
        except ClientError as exc:
            code = exc.response['Error']['Code']
            print(f'[WARN] {code}', end=' ')
            break
        batch = resp.get('events', [])
        events.extend(batch)
        next_token = resp.get('nextToken')
        if not next_token or not batch:
            break
        kwargs['nextToken'] = next_token
        time.sleep(_API_SLEEP)
    return events[:MAX_EVENTS]


# ── OpenObserve helpers ───────────────────────────────────────────────────────

def clear_oz_stream(session: requests.Session) -> None:
    url = f'{OZ_URL}/api/{OZ_ORG}/streams/{OZ_STREAM}'
    try:
        resp = session.delete(url, timeout=15)
        print(f'  OZ stream "{OZ_STREAM}" cleared (HTTP {resp.status_code})')
    except requests.RequestException as exc:
        print(f'  [WARN] Could not clear OZ stream: {exc}')


def push_batch(records: list, session: requests.Session) -> None:
    url = f'{OZ_URL}/api/{OZ_ORG}/{OZ_STREAM}/_json'
    resp = session.post(url, json=records, timeout=30)
    resp.raise_for_status()


# ── SQS queue discovery ───────────────────────────────────────────────────────

def _normalize(s: str) -> str:
    """Strip common suffixes/prefixes and punctuation for fuzzy matching."""
    s = s.lower()
    for strip in ('.fifo', '-queue', '-sqs', '-events', '-event', '-dev', 'dev-'):
        s = s.replace(strip, '')
    return re.sub(r'[-_.]', '', s)


def discover_sqs_queues(sqs_client, short_names: list[str]) -> list[dict]:
    """List all SQS queues and match each one to a service by normalized name."""
    all_urls: list[str] = []
    kwargs: dict = {'MaxResults': 1000}
    while True:
        try:
            resp = sqs_client.list_queues(**kwargs)
        except ClientError as exc:
            print(f'  [WARN] SQS list_queues failed: {exc}')
            break
        all_urls.extend(resp.get('QueueUrls', []))
        next_token = resp.get('NextToken')
        if not next_token:
            break
        kwargs['NextToken'] = next_token

    # queue_name → queue_name (last URL segment)
    queues = [(url.split('/')[-1]) for url in all_urls]
    print(f'  Found {len(queues)} SQS queues total')

    matched: list[dict] = []
    used: set[str] = set()
    for short in short_names:
        norm_short = _normalize(short)
        best: str | None = None
        best_score = 0
        for qname in queues:
            if qname in used:
                continue
            norm_q = _normalize(qname)
            if norm_short in norm_q or norm_q in norm_short:
                # prefer longer overlap (more specific match)
                score = len(set(norm_short) & set(norm_q))
                if score > best_score:
                    best_score = score
                    best = qname
        if best:
            matched.append({'queue_name': best, 'log_service': short})
            used.add(best)

    return matched


# ── metrics/services.json builder ────────────────────────────────────────────

def _build_services_config(discovered: list[dict], sqs_queues: list[dict]) -> dict:
    seen: set[str] = set()
    ecs_entries = []
    for svc in discovered:
        sn = svc['short_name']
        if sn in seen:
            continue
        seen.add(sn)
        ecs_entries.append({
            'cluster':     svc['cluster'],
            'service':     svc['service'],
            'log_service': sn,
            'metrics':     ['ecs_cpu', 'ecs_memory'],
        })

    return {
        'comment': (
            'Auto-generated by fetch_and_ingest.py. '
            'Adjust asg_name / db_identifier for your environment.'
        ),
        'ecs_services': ecs_entries,
        'sqs_queues': sqs_queues,
        'rds_instances': [
            {'db_identifier': _DEV_RDS_ID, 'log_service': 'rds_main'},
        ],
        'asg_groups': [
            {'asg_name': asg, 'log_service': svc_key}
            for svc_key, asg in _DEV_ASG_MAP.items()
        ],
    }


# ── main ──────────────────────────────────────────────────────────────────────

def main(hours: int, clear: bool, clear_metrics: bool) -> None:
    end_dt   = datetime.now(tz=timezone.utc)
    start_dt = end_dt - timedelta(hours=hours)
    start_ms = int(start_dt.timestamp() * 1000)
    end_ms   = int(end_dt.timestamp() * 1000)

    print(f'Window : {start_dt:%Y-%m-%d %H:%M} -> {end_dt:%Y-%m-%d %H:%M} UTC ({hours}h)')
    print(f'Stream : {OZ_URL}  org={OZ_ORG}  stream={OZ_STREAM}')

    session = requests.Session()
    session.auth = (OZ_USER, OZ_PASS)
    session.headers['Content-Type'] = 'application/json'

    if clear:
        clear_oz_stream(session)

    if clear_metrics:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute('DELETE FROM metrics')
            conn.commit()
            print('  SQLite metrics table cleared.')
        except sqlite3.OperationalError:
            pass  # table doesn't exist yet — fine
        finally:
            conn.close()

    ecs_client  = boto3.client('ecs',  region_name=AWS_REGION)
    logs_client = boto3.client('logs', region_name=AWS_REGION)
    sqs_client  = boto3.client('sqs',  region_name=AWS_REGION)

    # ── discover services ─────────────────────────────────────────────────────
    print('\n[1/3] Discovering ECS services...')
    all_services: list[dict] = []
    for cluster in CLUSTERS:
        try:
            names = list_cluster_services(ecs_client, cluster)
        except ClientError as exc:
            print(f'  [ERROR] {cluster}: {exc}')
            continue
        print(f'  {cluster}: {len(names)} services')
        for name in names:
            all_services.append({
                'cluster':    cluster,
                'service':    name,
                'short_name': _derive_short_name(name, cluster),
            })

    print(f'  Total: {len(all_services)} services')

    print('\n  Discovering SQS queues...')
    short_names  = [s['short_name'] for s in all_services]
    sqs_queues   = discover_sqs_queues(sqs_client, short_names)
    print(f'  Matched {len(sqs_queues)} SQS queues to services')

    # ── update metrics/services.json ──────────────────────────────────────────
    print('\n[2/3] Updating metrics/services.json...')
    cfg = _build_services_config(all_services, sqs_queues)
    _SERVICES_JSON.write_text(json.dumps(cfg, indent=2))
    print(f'  Written {len(cfg["ecs_services"])} ECS services, '
          f'{len(cfg["sqs_queues"])} SQS queues, '
          f'{len(cfg["asg_groups"])} ASGs, '
          f'{len(cfg["rds_instances"])} RDS instance(s)')

    # ── fetch + ingest logs ───────────────────────────────────────────────────
    print(f'\n[3/3] Fetching logs (FilterLogEvents, max {MAX_EVENTS:,}/group)...')
    total_events   = 0
    total_ingested = 0
    total_bytes    = 0
    skipped_groups = 0

    for i, svc in enumerate(all_services, 1):
        short = svc['short_name']
        print(f'  [{i:3d}/{len(all_services)}] {short}', end=' ... ', flush=True)

        log_group = find_log_group(logs_client, svc['service'])
        if not log_group:
            print('no log group found, skipping')
            skipped_groups += 1
            time.sleep(_API_SLEEP)
            continue

        events = fetch_events(logs_client, log_group, start_ms, end_ms)
        if not events:
            print('0 events')
            time.sleep(_API_SLEEP)
            continue

        records: list[dict] = []
        for ev in events:
            msg = ev.get('message', '')
            total_bytes += len(msg.encode('utf-8', errors='replace'))
            rec = parse_event(msg, ev['timestamp'], short)
            if rec:
                records.append(rec)

        sent = 0
        try:
            for j in range(0, len(records), BATCH_SIZE):
                push_batch(records[j : j + BATCH_SIZE], session)
                sent += len(records[j : j + BATCH_SIZE])
        except requests.HTTPError as exc:
            print(f'PUSH FAILED ({exc.response.status_code})')
            continue

        total_events   += len(events)
        total_ingested += sent
        print(f'{len(events):,} events -> {sent:,} ingested')
        time.sleep(_API_SLEEP)

    # ── summary ───────────────────────────────────────────────────────────────
    mb = total_bytes / (1024 * 1024)
    gb = mb / 1024
    print(f'\n{"=" * 60}')
    print(f'Services processed   : {len(all_services) - skipped_groups}/{len(all_services)}')
    print(f'Log groups not found : {skipped_groups}')
    print(f'Total log events     : {total_events:,}')
    print(f'Records ingested     : {total_ingested:,}')
    print(f'Data received        : {mb:.2f} MB  ({gb:.4f} GB)')
    print(f'FilterLogEvents cost : $0.00  (no Logs Insights scan charge)')
    print(f'\nNext step: python metrics/fetch_metrics.py --hours {hours}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description='Fetch real DEV logs from all ECS clusters and ingest into OpenObserve'
    )
    ap.add_argument(
        '--hours', type=int, default=168,
        help='Lookback window in hours (default: 168 = 7 days)',
    )
    ap.add_argument(
        '--clear', action='store_true',
        help='Delete the OZ stream before ingesting (removes existing data)',
    )
    ap.add_argument(
        '--clear-metrics', action='store_true',
        help='Wipe the SQLite metrics table before running',
    )
    args = ap.parse_args()
    main(args.hours, args.clear, args.clear_metrics)
