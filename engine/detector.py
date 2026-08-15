#!/usr/bin/env python3
"""
Z-score anomaly detector for Velaris.io log data.

For each 5-minute analysis window the detector:
  1. Queries OpenObserve for per-service error rates and mean latency
  2. Queries the historical baseline (same hour-of-day, last 30 days)
  3. Computes Z-scores for error rate and latency per service
  4. Matches anomalies against user-defined diagnosis rules
  5. Writes incident records to SQLite

Usage
-----
    # Analyse the last 5 minutes (live mode)
    python engine/detector.py

    # Analyse a specific historical window (evaluation / replay mode)
    python engine/detector.py --at "2026-04-18 14:15:00"
"""
import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean, stdev

import requests
from dotenv import load_dotenv

from models import get_db, init_db
from notifications import notify_incident

load_dotenv(Path(__file__).parent.parent / '.env')

OZ_URL    = os.getenv('OPENOBSERVE_URL',    'http://localhost:5080')
OZ_USER   = os.getenv('OPENOBSERVE_USER',   'admin@velaris.local')
OZ_PASS   = os.getenv('OPENOBSERVE_PASS',   'Admin1234!')
OZ_ORG    = os.getenv('OPENOBSERVE_ORG',    'default')
OZ_STREAM = os.getenv('OPENOBSERVE_STREAM', 'velaris_logs')
_db_raw   = os.getenv('DB_PATH', '')
DB_PATH   = str(
    (Path(__file__).parent.parent / _db_raw) if _db_raw and not Path(_db_raw).is_absolute()
    else Path(_db_raw) if _db_raw
    else Path(__file__).parent.parent / 'db' / 'incidents.db'
)

Z_THRESHOLD      = 3.0    # standard deviations above mean → anomaly
WINDOW_MINUTES   = 5      # analysis window size
BASELINE_DAYS    = 30     # how many days of history to use for baseline
MIN_BASELINE_OBS = 3      # skip baseline if fewer data points than this


# ---------------------------------------------------------------------------
# OpenObserve helpers
# ---------------------------------------------------------------------------

def _session() -> requests.Session:
    s = requests.Session()
    s.auth = (OZ_USER, OZ_PASS)
    s.headers['Content-Type'] = 'application/json'
    return s


def oz_query(sql: str, start_us: int, end_us: int, size: int = 10_000) -> list[dict]:
    """Run a SQL query against OpenObserve and return the hits list."""
    payload = {
        'query': {
            'sql':        sql,
            'start_time': start_us,
            'end_time':   end_us,
            'from':       0,
            'size':       size,
        }
    }
    url  = f'{OZ_URL}/api/{OZ_ORG}/_search'
    resp = _session().post(url, json=payload, timeout=30)
    resp.raise_for_status()
    body = resp.json()
    # OpenObserve returns hits directly as a list under 'hits'
    hits = body.get('hits', [])
    if isinstance(hits, dict):
        hits = hits.get('hits', [])
    return hits


def dt_to_us(dt: datetime) -> int:
    return int(dt.timestamp() * 1_000_000)


# ---------------------------------------------------------------------------
# Step 1 — Query current analysis window
# ---------------------------------------------------------------------------

def query_current_window(window_end: datetime) -> list[dict]:
    """
    Return per-service aggregates for the WINDOW_MINUTES before window_end.
    Each row: {service, total, errors, avg_duration_ms, sample_errors}
    """
    window_start = window_end - timedelta(minutes=WINDOW_MINUTES)

    sql = f"""
        SELECT
            service,
            COUNT(*)                                                                AS total,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)                   AS errors,
            AVG(duration_ms)                                                        AS avg_duration
        FROM "{OZ_STREAM}"
        WHERE status_code IS NOT NULL
          AND service IS NOT NULL
        GROUP BY service
    """

    rows = oz_query(sql, dt_to_us(window_start), dt_to_us(window_end))

    # Fetch a sample of recent error messages per service for rule matching
    err_sql = f"""
        SELECT service, message
        FROM "{OZ_STREAM}"
        WHERE (is_error = true OR status_code >= 400)
          AND service IS NOT NULL
        LIMIT 200
    """
    err_rows = oz_query(err_sql, dt_to_us(window_start), dt_to_us(window_end), size=200)

    errors_by_service: dict[str, list[str]] = {}
    for r in err_rows:
        svc = r.get('service', '')
        errors_by_service.setdefault(svc, []).append(r.get('message', ''))

    result = []
    for row in rows:
        svc   = row.get('service') or ''
        total = int(row.get('total') or 0)
        errs  = int(row.get('errors') or 0)
        if total == 0 or not svc:
            continue
        result.append({
            'service':        svc,
            'total':          total,
            'errors':         errs,
            'error_rate':     errs / total,
            'avg_duration':   float(row.get('avg_duration') or 0.0),
            'sample_errors':  errors_by_service.get(svc, [])[:10],
        })

    return result


# ---------------------------------------------------------------------------
# Step 2 — Query historical baseline
# ---------------------------------------------------------------------------

def query_baseline(window_end: datetime) -> dict[str, dict]:
    """
    Return per-service baseline stats using all hourly buckets across
    the available history window.  With only 7 days of real data the
    same-hour-of-day filter would leave < MIN_BASELINE_OBS data points
    per service, so we use the full rolling window instead.

    Returns: {service: {mean_error_rate, std_error_rate, mean_duration, std_duration}}
    """
    baseline_end   = window_end - timedelta(minutes=WINDOW_MINUTES)
    baseline_start = window_end - timedelta(days=BASELINE_DAYS)

    # Hourly aggregates over the full baseline period (no hour-of-day filter)
    sql = f"""
        SELECT
            service,
            histogram(_timestamp, '1 hour')                                        AS hour_bucket,
            COUNT(*)                                                                AS total,
            SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)                   AS errors,
            AVG(duration_ms)                                                        AS avg_duration
        FROM "{OZ_STREAM}"
        WHERE status_code IS NOT NULL
          AND service IS NOT NULL
        GROUP BY service, histogram(_timestamp, '1 hour')
    """

    rows = oz_query(sql, dt_to_us(baseline_start), dt_to_us(baseline_end), size=50_000)

    # Accumulate all hourly buckets per service
    buckets: dict[str, list[dict]] = {}
    for row in rows:
        svc   = row.get('service') or ''
        total = int(row.get('total') or 0)
        if total == 0 or not svc:
            continue

        errs  = int(row.get('errors') or 0)
        buckets.setdefault(svc, []).append({
            'error_rate':   errs / total,
            'avg_duration': float(row.get('avg_duration') or 0.0),
        })

    baseline: dict[str, dict] = {}
    for svc, obs in buckets.items():
        if len(obs) < MIN_BASELINE_OBS:
            continue
        er   = [o['error_rate']   for o in obs]
        dur  = [o['avg_duration'] for o in obs]
        baseline[svc] = {
            'mean_error_rate':  mean(er),
            'std_error_rate':   stdev(er) if len(er) > 1 else 0.0,
            'mean_duration':    mean(dur),
            'std_duration':     stdev(dur) if len(dur) > 1 else 0.0,
            'n_observations':   len(obs),
        }

    return baseline


# ---------------------------------------------------------------------------
# Step 3 — Compute Z-scores
# ---------------------------------------------------------------------------

def compute_z(value: float, mu: float, sigma: float) -> float:
    if sigma < 1e-9:
        return 0.0
    return (value - mu) / sigma


# ---------------------------------------------------------------------------
# Step 4 — Match diagnosis rules (with optional metric condition)
# ---------------------------------------------------------------------------

def get_recent_metric(
    db: sqlite3.Connection,
    service: str,
    metric_name: str,
    at_time: datetime | None = None,
) -> float | None:
    """
    Return the most recent metric value for (service, metric_name) within
    60 minutes before at_time (default: now).

    For RDS connections the service key is 'rds_main' regardless of the
    triggering log service.
    """
    ref    = at_time or datetime.now()
    cutoff = (ref - timedelta(minutes=60)).isoformat()
    upper  = ref.isoformat()

    lookup_service = 'rds_main' if metric_name == 'rds_connections' else service

    row = db.execute(
        """SELECT value FROM metrics
           WHERE service = ? AND metric_name = ? AND timestamp >= ? AND timestamp <= ?
           ORDER BY timestamp DESC LIMIT 1""",
        (lookup_service, metric_name, cutoff, upper),
    ).fetchone()
    return float(row[0]) if row else None


def _metric_condition_met(
    db: sqlite3.Connection,
    service: str,
    rule: sqlite3.Row,
    at_time: datetime | None = None,
) -> bool:
    """Return True if the rule has no metric condition, or the condition is satisfied."""
    metric_name = rule['metric_name']
    if not metric_name:
        return True

    operator  = rule['metric_operator']  or '>'
    threshold = rule['metric_threshold']
    if threshold is None:
        return True

    value = get_recent_metric(db, service, metric_name, at_time)
    if value is None:
        return False  # metric data absent — don't fire the metric-specific rule

    ops = {'>': value > threshold, '>=': value >= threshold,
           '<': value < threshold, '<=': value <= threshold, '=': value == threshold}
    return ops.get(operator, False)


def match_rule(
    db: sqlite3.Connection,
    service: str,
    anomaly_type: str,
    z_errors: float,
    z_latency: float,
    sample_errors: list[str],
    at_time: datetime | None = None,
) -> sqlite3.Row | None:
    """
    Find the most specific enabled rule that matches this anomaly.
    Service-specific rules take priority over catch-all rules.
    Rules with metric conditions are tried before those without (more specific).
    """
    z_max = max(z_errors, z_latency)

    rules = db.execute(
        """SELECT * FROM diagnosis_rules
           WHERE enabled = 1
             AND min_z_score <= ?
             AND (check_errors  = 0 OR ? > 0)
             AND (check_latency = 0 OR ? > 0)
           ORDER BY
               CASE WHEN service IS NOT NULL THEN 0 ELSE 1 END,
               CASE WHEN metric_name IS NOT NULL THEN 0 ELSE 1 END,
               min_z_score DESC""",
        (z_max, z_errors, z_latency),
    ).fetchall()

    combined_errors = ' '.join(sample_errors).lower()

    for rule in rules:
        # Service filter
        if rule['service'] and rule['service'] != service:
            continue

        # Log content filter
        needle = rule['log_contains']
        if needle and needle.lower() not in combined_errors:
            continue

        # Anomaly type alignment
        if rule['check_errors'] and 'error' not in anomaly_type and 'both' not in anomaly_type:
            continue
        if rule['check_latency'] and 'latency' not in anomaly_type and 'both' not in anomaly_type:
            continue

        # Metric condition
        if not _metric_condition_met(db, service, rule, at_time):
            continue

        return rule  # first (most specific) match wins

    return None


# ---------------------------------------------------------------------------
# Step 5 — Write incident to SQLite
# ---------------------------------------------------------------------------

def record_incident(
    db: sqlite3.Connection,
    window_end: datetime,
    service: str,
    error_rate: float,
    mean_duration: float,
    z_errors: float,
    z_latency: float,
    anomaly_type: str,
    sample_errors: list[str],
    rule: sqlite3.Row | None,
) -> int:
    window_start = window_end - timedelta(minutes=WINDOW_MINUTES)
    cur = db.execute(
        """INSERT INTO incidents
               (detected_at, service, window_start, window_end,
                error_rate, mean_duration_ms,
                z_score_errors, z_score_latency, anomaly_type,
                sample_errors,
                diagnosis_rule_id, diagnosis_label, playbook)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            datetime.utcnow().isoformat(),  # when the analysis ran (not the historical window)
            service,
            window_start.isoformat(),
            window_end.isoformat(),
            round(error_rate, 4),
            round(mean_duration, 2),
            round(z_errors,  2),
            round(z_latency, 2),
            anomaly_type,
            json.dumps(sample_errors),
            rule['id']        if rule else None,
            rule['diagnosis'] if rule else 'No matching rule - manual investigation required',
            rule['playbook']  if rule else '',
        ),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Main detection loop
# ---------------------------------------------------------------------------

def run_detection(
    at_time: datetime | None = None,
    cached_baseline: dict | None = None,
    notify: bool = True,
) -> list[dict]:
    """
    Run one detection pass at the given time (default: now).
    cached_baseline: pre-fetched baseline dict (used by replay to avoid redundant OZ queries).
    notify: fire real alert_channels notifications for each incident found (disabled during
    historical --replay-hours backfills so they don't flood Slack/Discord with old incidents).
    Returns a list of incident summaries for the caller.
    """
    window_end = at_time or datetime.now()
    print(f'[detector] Analysing window ending at {window_end.strftime("%Y-%m-%d %H:%M:%S")}')

    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db(DB_PATH)
    db = get_db(DB_PATH)

    current  = query_current_window(window_end)
    baseline = cached_baseline if cached_baseline is not None else query_baseline(window_end)

    if not current:
        print('[detector] No data in current window — nothing to analyse')
        return []

    found: list[dict] = []

    for svc_data in current:
        svc    = svc_data['service']
        bl     = baseline.get(svc)

        if bl is None:
            print(f'  [{svc}] insufficient baseline — skipping')
            continue

        z_err = compute_z(svc_data['error_rate'], bl['mean_error_rate'],  bl['std_error_rate'])
        z_lat = compute_z(svc_data['avg_duration'], bl['mean_duration'],   bl['std_duration'])

        err_anomaly = z_err  > Z_THRESHOLD
        lat_anomaly = z_lat  > Z_THRESHOLD

        if not err_anomaly and not lat_anomaly:
            print(f'  [{svc}] OK  (z_err={z_err:.1f}, z_lat={z_lat:.1f})')
            continue

        anomaly_type = (
            'both'       if err_anomaly and lat_anomaly else
            'error_rate' if err_anomaly                 else
            'latency'
        )

        rule = match_rule(db, svc, anomaly_type, z_err, z_lat, svc_data['sample_errors'], window_end)
        inc_id = record_incident(
            db, window_end, svc,
            svc_data['error_rate'], svc_data['avg_duration'],
            z_err, z_lat, anomaly_type,
            svc_data['sample_errors'], rule,
        )

        diagnosis_text = rule['diagnosis'] if rule else 'No matching rule - manual investigation required'
        if notify:
            notify_incident(
                db, inc_id, svc, anomaly_type, diagnosis_text,
                rule['id'] if rule else None,
                z_err, z_lat, svc_data['error_rate'], svc_data['avg_duration'],
            )

        summary = {
            'incident_id':    inc_id,
            'service':        svc,
            'anomaly_type':   anomaly_type,
            'z_score_errors': round(z_err,  2),
            'z_score_latency':round(z_lat,  2),
            'error_rate':     round(svc_data['error_rate'],   4),
            'avg_duration_ms':round(svc_data['avg_duration'], 2),
            'diagnosis':      rule['diagnosis'] if rule else 'No matching rule',
        }
        found.append(summary)
        print(
            f'  [{svc}] ANOMALY  type={anomaly_type}  '
            f'z_err={z_err:.1f}  z_lat={z_lat:.1f}  '
            f'-> "{summary["diagnosis"]}"'
        )

    db.close()
    print(f'[detector] Done - {len(found)} anomaly(ies) detected')
    return found


def main() -> None:
    ap = argparse.ArgumentParser(description='Velaris log anomaly detector')
    ap.add_argument(
        '--at',
        metavar='DATETIME',
        help='Analyse window ending at this time, e.g. "2026-04-18 14:15:00"',
    )
    ap.add_argument(
        '--replay-hours',
        type=int,
        metavar='N',
        help='Replay detection over the last N hours in 15-min steps (e.g. 168 for 7 days)',
    )
    ap.add_argument(
        '--clear-incidents',
        action='store_true',
        help='Delete all existing incidents before replaying',
    )
    args = ap.parse_args()

    if args.replay_hours:
        # Sweep backwards through history, caching baseline per hour-of-day so we
        # only fire 24 expensive OZ baseline queries instead of one per window.
        now   = datetime.now()
        step  = timedelta(minutes=15)
        start = now - timedelta(hours=args.replay_hours)

        baseline_cache: dict[int, dict] = {}
        windows: list[datetime] = []
        t = start + step
        while t <= now:
            windows.append(t)
            t += step

        if args.clear_incidents:
            Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
            init_db(DB_PATH)
            _db = get_db(DB_PATH)
            _db.execute('DELETE FROM incidents')
            _db.commit()
            _db.close()
            print('[replay] Cleared existing incidents.')

        print(f'[replay] {len(windows)} windows over {args.replay_hours}h — '
              f'pre-fetching baseline (single pass)...')
        shared_baseline = query_baseline(now)
        print(f'  baseline: {len(shared_baseline)} services with sufficient history')

        total_incidents = 0
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        init_db(DB_PATH)
        for w in windows:
            found = run_detection(at_time=w, cached_baseline=shared_baseline, notify=False)
            total_incidents += len(found)

        print(f'\n[replay] Complete — {total_incidents} incident(s) recorded across {len(windows)} windows')
    else:
        at_time = None
        if args.at:
            at_time = datetime.strptime(args.at, '%Y-%m-%d %H:%M:%S')
        run_detection(at_time)


if __name__ == '__main__':
    main()
