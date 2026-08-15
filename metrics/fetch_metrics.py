#!/usr/bin/env python3
"""
CloudWatch metrics fetcher — pulls ECS CPU/memory, SQS depth, RDS connections
into the local SQLite metrics table.

Reads service config from metrics/services.json so adding new services only
requires editing JSON, not Python.

Usage
-----
    python metrics/fetch_metrics.py                   # last 6 hours
    python metrics/fetch_metrics.py --hours 24        # last 24 hours
    python metrics/fetch_metrics.py --hours 720       # last 30 days (baseline)

AWS credentials
---------------
Set via environment variables or ~/.aws/credentials:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_DEFAULT_REGION  (default: eu-west-1)
"""
import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')

DB_PATH     = os.getenv('DB_PATH',         str(Path(__file__).parent.parent / 'db' / 'incidents.db'))
AWS_REGION  = os.getenv('AWS_DEFAULT_REGION', 'eu-west-2')
CONFIG_PATH = Path(__file__).parent / 'services.json'

PERIOD_SECONDS = 300  # 5-minute granularity — auto-increased for long windows


def _cw_client():
    return boto3.client('cloudwatch', region_name=AWS_REGION)


def _safe_period(hours: int) -> int:
    """Return the smallest multiple-of-60 period that keeps datapoints <= 1440."""
    import math
    min_period = math.ceil((hours * 3600) / 1440)
    return max(PERIOD_SECONDS, math.ceil(min_period / 60) * 60)


def _fetch_metric(
    cw,
    namespace: str,
    metric_name: str,
    dimensions: list[dict],
    stat: str,
    start: datetime,
    end: datetime,
    period: int = PERIOD_SECONDS,
) -> list[tuple[str, float]]:
    """Return list of (iso_timestamp, value) pairs."""
    try:
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=[stat],
        )
    except (ClientError, NoCredentialsError) as exc:
        print(f'  [WARN] CloudWatch error for {metric_name}: {exc}')
        return []

    results = []
    for dp in resp.get('Datapoints', []):
        ts  = dp['Timestamp'].astimezone(timezone.utc).replace(tzinfo=None).isoformat()
        val = dp.get(stat, 0.0)
        results.append((ts, val))
    return sorted(results)


def fetch_ecs_metrics(cw, service_cfg: dict, start: datetime, end: datetime, period: int = PERIOD_SECONDS) -> list[tuple]:
    """Fetch ECS CPUUtilization and MemoryUtilization for one service."""
    cluster = service_cfg['cluster']
    svc     = service_cfg['service']
    log_svc = service_cfg['log_service']
    dims    = [
        {'Name': 'ClusterName', 'Value': cluster},
        {'Name': 'ServiceName', 'Value': svc},
    ]
    rows = []
    for cw_name, local_name in [('CPUUtilization', 'ecs_cpu'), ('MemoryUtilization', 'ecs_memory')]:
        if local_name not in service_cfg.get('metrics', []):
            continue
        pts = _fetch_metric(cw, 'AWS/ECS', cw_name, dims, 'Average', start, end, period)
        for ts, val in pts:
            rows.append((log_svc, local_name, ts, round(val, 4)))
        print(f'    ECS {log_svc}/{local_name}: {len(pts)} datapoints')
    return rows


def fetch_sqs_metrics(cw, queue_cfg: dict, start: datetime, end: datetime, period: int = PERIOD_SECONDS) -> list[tuple]:
    log_svc    = queue_cfg['log_service']
    queue_name = queue_cfg['queue_name']
    dims       = [{'Name': 'QueueName', 'Value': queue_name}]
    pts = _fetch_metric(
        cw, 'AWS/SQS', 'ApproximateNumberOfMessagesVisible',
        dims, 'Maximum', start, end, period,
    )
    rows = [(log_svc, 'sqs_depth', ts, round(val, 0)) for ts, val in pts]
    print(f'    SQS {log_svc}/sqs_depth: {len(pts)} datapoints')
    return rows


def fetch_asg_metrics(asg_client, asg_cfg: dict) -> list[tuple]:
    """Fetch ASG capacity as a percentage of MaxSize (snapshot, not time-series)."""
    log_svc  = asg_cfg['log_service']
    asg_name = asg_cfg['asg_name']
    try:
        resp  = asg_client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = resp.get('AutoScalingGroups', [])
        if not groups:
            print(f'    ASG {asg_name}: not found')
            return []
        g        = groups[0]
        max_size = g['MaxSize']
        in_svc   = sum(1 for i in g['Instances'] if i['LifecycleState'] == 'InService')
        pct      = round((in_svc / max_size) * 100, 1) if max_size else 0.0
        ts       = datetime.now(tz=timezone.utc).replace(tzinfo=None).isoformat()
        print(f'    ASG {log_svc}/asg_capacity: {in_svc}/{max_size} ({pct}%)')
        return [(log_svc, 'asg_capacity', ts, pct)]
    except (ClientError, NoCredentialsError) as exc:
        print(f'  [WARN] ASG error for {asg_name}: {exc}')
        return []


def fetch_rds_metrics(cw, rds_cfg: dict, start: datetime, end: datetime, period: int = PERIOD_SECONDS) -> list[tuple]:
    log_svc = rds_cfg['log_service']
    db_id   = rds_cfg['db_identifier']
    dims    = [{'Name': 'DBInstanceIdentifier', 'Value': db_id}]
    pts = _fetch_metric(
        cw, 'AWS/RDS', 'DatabaseConnections',
        dims, 'Average', start, end, period,
    )
    rows = [(log_svc, 'rds_connections', ts, round(val, 1)) for ts, val in pts]
    print(f'    RDS {log_svc}/rds_connections: {len(pts)} datapoints')
    return rows


def upsert_metrics(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    conn.executemany(
        """INSERT OR REPLACE INTO metrics (service, metric_name, timestamp, value)
           VALUES (?,?,?,?)""",
        rows,
    )
    conn.commit()


def main(hours: int) -> None:
    end_dt   = datetime.now(tz=timezone.utc)
    start_dt = end_dt - timedelta(hours=hours)
    period   = _safe_period(hours)
    print(f'Fetching metrics: {start_dt.strftime("%Y-%m-%d %H:%M")} -> {end_dt.strftime("%Y-%m-%d %H:%M")} UTC')
    print(f'Period: {period}s ({period // 60}-minute granularity)')

    config = json.loads(CONFIG_PATH.read_text())
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            service     TEXT    NOT NULL,
            metric_name TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            value       REAL    NOT NULL
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_metrics_unique
            ON metrics(service, metric_name, timestamp)
    """)

    try:
        cw  = _cw_client()
        asg = boto3.client('autoscaling', region_name=AWS_REGION)
    except Exception as exc:
        print(f'Failed to create AWS clients: {exc}')
        return

    all_rows: list[tuple] = []

    print('Fetching ECS metrics...')
    for svc_cfg in config.get('ecs_services', []):
        all_rows.extend(fetch_ecs_metrics(cw, svc_cfg, start_dt, end_dt, period))

    print('Fetching SQS metrics...')
    for q_cfg in config.get('sqs_queues', []):
        all_rows.extend(fetch_sqs_metrics(cw, q_cfg, start_dt, end_dt, period))

    print('Fetching RDS metrics...')
    for rds_cfg in config.get('rds_instances', []):
        all_rows.extend(fetch_rds_metrics(cw, rds_cfg, start_dt, end_dt, period))

    print('Fetching ASG capacity...')
    for asg_cfg in config.get('asg_groups', []):
        all_rows.extend(fetch_asg_metrics(asg, asg_cfg))

    if all_rows:
        upsert_metrics(conn, all_rows)
        print(f'Upserted {len(all_rows)} metric rows into {DB_PATH}')
    else:
        print('No metric data retrieved.')

    conn.close()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Fetch CloudWatch metrics into SQLite')
    ap.add_argument('--hours', type=int, default=6, help='How many hours back to fetch (default: 6)')
    args = ap.parse_args()
    main(args.hours)
