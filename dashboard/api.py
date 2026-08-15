#!/usr/bin/env python3
"""
FastAPI backend for the Velaris Analytics dashboard.

Endpoints
---------
  GET  /                           Serve index.html
  GET  /api/health                 OZ + DB connectivity
  GET  /api/kpis                   KPI summary cards
  GET  /api/incidents              Incident list (mapped to design format)
  PATCH /api/incidents/{id}        Update incident status
  GET  /api/rules                  Rules list
  POST /api/rules                  Create rule
  PUT  /api/rules/{id}             Update rule
  DELETE /api/rules/{id}           Delete rule
  GET  /api/services               Distinct services from OZ (falls back to DB)
  GET  /api/timeseries             Error-rate / latency / volume from OZ
  GET  /api/metrics                CloudWatch metrics from SQLite

Run
---
    uvicorn dashboard.api:app --reload --port 8501
    # or from project root:
    python -m uvicorn dashboard.api:app --reload --port 8501
"""
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

load_dotenv(Path(__file__).parent.parent / '.env')

DB_PATH   = os.getenv('DB_PATH',            str(Path(__file__).parent.parent / 'db' / 'incidents.db'))
OZ_URL    = os.getenv('OPENOBSERVE_URL',    'http://localhost:5080')
OZ_USER   = os.getenv('OPENOBSERVE_USER',   'admin@velaris.local')
OZ_PASS   = os.getenv('OPENOBSERVE_PASS',   'Admin1234!')
OZ_ORG    = os.getenv('OPENOBSERVE_ORG',    'default')
OZ_STREAM = os.getenv('OPENOBSERVE_STREAM', 'velaris_logs')

STATIC_DIR   = Path(__file__).parent / 'static'
TOP_N_SERIES = 20  # max services shown in timeseries charts

@asynccontextmanager
async def lifespan(_app: FastAPI):
    from engine.models import init_db
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db(DB_PATH)
    yield

app = FastAPI(title='Velaris Analytics API', lifespan=lifespan)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


# ---------------------------------------------------------------------------
# Time range helpers
# ---------------------------------------------------------------------------

def _range_to_datetimes(range_str: str) -> tuple[datetime, datetime]:
    now = datetime.now()
    if range_str == 'eval':
        return datetime(2026, 4, 18, 0, 0), datetime(2026, 4, 19, 0, 0)
    mapping = {
        '15m': timedelta(minutes=15), '1h': timedelta(hours=1),
        '4h':  timedelta(hours=4),   '24h': timedelta(hours=24),
        '7d':  timedelta(days=7),    '30d': timedelta(days=30),
        '90d': timedelta(days=90),   '180d': timedelta(days=180),
        '360d': timedelta(days=360),
    }
    return now - mapping.get(range_str, timedelta(hours=4)), now


def _time_ago(iso_str: str) -> str:
    if not iso_str:
        return ''
    try:
        dt = datetime.fromisoformat(iso_str)
        diff = datetime.now() - dt
        s = diff.total_seconds()
        if s < 60:    return f'{int(s)}s ago'
        if s < 3600:  return f'{int(s // 60)}m ago'
        if s < 86400: return f'{int(s // 3600)}h ago'
        return f'{int(diff.days)}d ago'
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Data mappers (DB row -> design-format dict)
# ---------------------------------------------------------------------------

def _map_incident(row: sqlite3.Row) -> dict[str, Any]:
    atype = row['anomaly_type']
    type_map = {'both': 'both', 'error_rate': 'error', 'latency': 'latency'}
    sev_map  = {'both': 'critical', 'error_rate': 'high', 'latency': 'medium'}

    steps: list[list[str]] = []
    for line in (row['playbook'] or '').split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split('. ', 1)
        steps.append([parts[1] if len(parts) == 2 else line, ''])

    samples: list[list[str]] = []
    try:
        for msg in json.loads(row['sample_errors'] or '[]')[:5]:
            samples.append(['--:--', 'ERROR', str(msg)[:120]])
    except Exception:
        pass

    z_err  = float(row['z_score_errors']   or 0)
    z_lat  = float(row['z_score_latency']  or 0)
    er     = float(row['error_rate']       or 0)
    dur    = float(row['mean_duration_ms'] or 0)

    return {
        'id':           f"INC-{row['id']:05d}",
        'db_id':        row['id'],
        'service':      row['service'],
        'type':         type_map.get(atype, atype),
        'status':       row['status'],
        'anomalyLabels': (
            ['error_rate', 'latency'] if atype == 'both' else
            ['error_rate']            if atype == 'error_rate' else
            ['latency']
        ),
        'severity': sev_map.get(atype, 'medium'),
        'detected': (row['detected_at'] or '')[:16],
        'age':      _time_ago(row['detected_at']),
        'diagnosis': row['diagnosis_label'] or 'No diagnosis',
        'metrics': {
            'err':  f'{er * 100:.1f}%',
            'errZ': f'{z_err:.1f}σ',
            'lat':  f'{dur:.0f}ms',
            'latZ': f'{z_lat:.1f}σ',
        },
        'playbook': steps,
        'samples':  samples,
    }


def _map_rule(row: sqlite3.Row) -> dict[str, Any]:
    metric = None
    if row['metric_name']:
        metric = {
            'name':  row['metric_name'],
            'op':    row['metric_operator'] or '>',
            'value': float(row['metric_threshold'] or 0),
        }
    return {
        'id':        str(row['id']),
        'name':      row['name'],
        'service':   row['service'] or '',
        'z':         float(row['min_z_score']),
        'checks':    {'errors': bool(row['check_errors']), 'latency': bool(row['check_latency'])},
        'keyword':   row['log_contains'] or '',
        'metric':    metric,
        'diagnosis': row['diagnosis'],
        'playbook':  row['playbook'],
        'enabled':   bool(row['enabled']),
    }


# ---------------------------------------------------------------------------
# OpenObserve helper
# ---------------------------------------------------------------------------

def _oz_session() -> requests.Session:
    s = requests.Session()
    s.auth = (OZ_USER, OZ_PASS)
    s.headers['Content-Type'] = 'application/json'
    return s


def _oz_query(sql: str, start: datetime, end: datetime, size: int = 50_000) -> list[dict]:
    payload = {
        'query': {
            'sql':        sql,
            'start_time': int(start.timestamp() * 1_000_000),
            'end_time':   int(end.timestamp()   * 1_000_000),
            'from':       0,
            'size':       size,
        }
    }
    resp = _oz_session().post(f'{OZ_URL}/api/{OZ_ORG}/_search', json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json().get('hits', [])


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.get('/api/health')
def health():
    oz_ok = False
    try:
        # OpenObserve healthcheck — try /healthz then fall back to the UI root
        for path in ('/healthz', '/'):
            try:
                r = requests.get(f'{OZ_URL}{path}', timeout=2)
                if r.status_code < 500:
                    oz_ok = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    return {'status': 'ok', 'openobserve': oz_ok}


@app.get('/api/kpis')
def get_kpis(range: str = '7d'):
    start, end = _range_to_datetimes(range)
    db = get_db()
    si, ei = start.isoformat(), end.isoformat()

    open_n  = db.execute("SELECT COUNT(*) FROM incidents WHERE status='open'        AND detected_at>=? AND detected_at<=?", [si, ei]).fetchone()[0]
    ack_n   = db.execute("SELECT COUNT(*) FROM incidents WHERE status='acknowledged' AND detected_at>=? AND detected_at<=?", [si, ei]).fetchone()[0]
    res_n   = db.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'    AND detected_at>=? AND detected_at<=?", [si, ei]).fetchone()[0]
    total_n = open_n + ack_n + res_n
    crit_n  = db.execute("SELECT COUNT(*) FROM incidents WHERE anomaly_type='both'        AND detected_at>=? AND detected_at<=?", [si, ei]).fetchone()[0]
    med_n   = db.execute("SELECT COUNT(*) FROM incidents WHERE anomaly_type='latency'     AND detected_at>=? AND detected_at<=?", [si, ei]).fetchone()[0]
    rules_n = db.execute("SELECT COUNT(*) FROM diagnosis_rules WHERE enabled=1").fetchone()[0]
    db.close()
    try:
        cfg   = json.loads((Path(__file__).parent.parent / 'metrics' / 'services.json').read_text())
        svc_n = len(cfg.get('ecs_services', []))
    except Exception:
        svc_n = 0

    return {
        'open':        open_n,
        'total':       total_n,
        'resolved':    res_n,
        'acknowledged':ack_n,
        'critical':    crit_n,
        'medium':      med_n,
        'services':    svc_n,
        'rules':       rules_n,
        'threshold':   '3.0σ',
    }


@app.get('/api/incidents')
def get_incidents(range: str = '7d'):
    start, end = _range_to_datetimes(range)
    db = get_db()
    rows = db.execute(
        'SELECT * FROM incidents WHERE detected_at>=? AND detected_at<=? ORDER BY detected_at DESC',
        [start.isoformat(), end.isoformat()],
    ).fetchall()
    result = [_map_incident(r) for r in rows]
    db.close()
    return result


class StatusUpdate(BaseModel):
    status: str


@app.patch('/api/incidents/{incident_id}')
def update_incident(incident_id: int, body: StatusUpdate):
    db = get_db()
    row = db.execute('SELECT * FROM incidents WHERE id=?', [incident_id]).fetchone()
    if not row:
        raise HTTPException(404, 'Incident not found')
    if body.status not in ('open', 'acknowledged', 'resolved'):
        raise HTTPException(400, 'Invalid status')
    db.execute('UPDATE incidents SET status=? WHERE id=?', [body.status, incident_id])
    db.commit()
    updated = db.execute('SELECT * FROM incidents WHERE id=?', [incident_id]).fetchone()
    result = _map_incident(updated)
    db.close()
    return result


@app.get('/api/rules')
def get_rules():
    db = get_db()
    rows = db.execute('SELECT * FROM diagnosis_rules ORDER BY id').fetchall()
    result = [_map_rule(r) for r in rows]
    db.close()
    return result


class RuleBody(BaseModel):
    name:      str
    service:   Optional[str]  = None
    keyword:   Optional[str]  = None
    z:         float          = 3.0
    checks:    dict           = {'errors': True, 'latency': False}
    metric:    Optional[dict] = None
    diagnosis: str
    playbook:  str            = ''
    enabled:   bool           = True


def _rule_params(r: RuleBody) -> tuple:
    mn = r.metric['name']  if r.metric else None
    mo = r.metric['op']    if r.metric else None
    mt = r.metric['value'] if r.metric else None
    return (
        r.name, r.service or None, r.keyword or None, r.z,
        int(r.checks.get('errors', True)), int(r.checks.get('latency', False)),
        mn, mo, mt, r.diagnosis, r.playbook, int(r.enabled),
    )


@app.post('/api/rules', status_code=201)
def create_rule(body: RuleBody):
    db = get_db()
    cur = db.execute(
        """INSERT INTO diagnosis_rules
               (name,service,log_contains,min_z_score,check_errors,check_latency,
                metric_name,metric_operator,metric_threshold,diagnosis,playbook,enabled)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        _rule_params(body),
    )
    db.commit()
    row = db.execute('SELECT * FROM diagnosis_rules WHERE id=?', [cur.lastrowid]).fetchone()
    result = _map_rule(row)
    db.close()
    return result


@app.put('/api/rules/{rule_id}')
def update_rule(rule_id: int, body: RuleBody):
    db = get_db()
    if not db.execute('SELECT id FROM diagnosis_rules WHERE id=?', [rule_id]).fetchone():
        raise HTTPException(404, 'Rule not found')
    db.execute(
        """UPDATE diagnosis_rules SET
               name=?,service=?,log_contains=?,min_z_score=?,check_errors=?,check_latency=?,
               metric_name=?,metric_operator=?,metric_threshold=?,diagnosis=?,playbook=?,enabled=?
           WHERE id=?""",
        _rule_params(body) + (rule_id,),
    )
    db.commit()
    row = db.execute('SELECT * FROM diagnosis_rules WHERE id=?', [rule_id]).fetchone()
    result = _map_rule(row)
    db.close()
    return result


@app.delete('/api/rules/{rule_id}')
def delete_rule(rule_id: int):
    db = get_db()
    if not db.execute('SELECT id FROM diagnosis_rules WHERE id=?', [rule_id]).fetchone():
        raise HTTPException(404, 'Rule not found')
    db.execute('DELETE FROM diagnosis_rules WHERE id=?', [rule_id])
    db.commit()
    db.close()
    return {'ok': True}


# ---------------------------------------------------------------------------
# Alert channels
# ---------------------------------------------------------------------------

_CHANNEL_META = {
    'slack':   {'logoBg': '#1F1A2E', 'lightLogoBg': '#FBE9EE', 'accent': '#E01E5A'},
    'discord': {'logoBg': '#1A1F2E', 'lightLogoBg': '#EAEBFB', 'accent': '#5865F2'},
    'webhook': {'logoBg': '#1A1D27', 'lightLogoBg': '#F0F0F0', 'accent': '#94A3B8'},
}


def _map_channel(row: sqlite3.Row) -> dict[str, Any]:
    cfg      = json.loads(row['config']     or '{}')
    sevs     = json.loads(row['severities'] or '["critical","high"]')
    rule_ids = json.loads(row['rule_ids']   or '[]')
    meta     = _CHANNEL_META.get(row['type'], _CHANNEL_META['webhook'])

    t = row['type']
    if t == 'slack':
        ch = cfg.get('channel', '')
        target = f"#{ch}" if ch else '(no channel set)'
    elif t == 'discord':
        mention = cfg.get('mention', '')
        target = mention if mention else '(no mention set)'
    elif t == 'email':
        target = cfg.get('to', '') or '(no recipients)'
    else:
        url = cfg.get('url', '')
        target = (url[:50] + '…') if len(url) > 50 else url if url else '(no URL set)'

    sev_str   = ' · '.join(f'severity {s}' for s in sevs) if sevs else 'all severities'
    rules_str = 'All rules' if row['all_rules'] else f'{len(rule_ids)} rules'
    triggers  = f"{sev_str} · {rules_str}"

    return {
        'id':          str(row['id']),
        'db_id':       row['id'],
        'type':        row['type'],
        'name':        row['name'],
        'config':      cfg,
        'severities':  sevs,
        'allRules':    bool(row['all_rules']),
        'ruleIds':     rule_ids,
        'active':      bool(row['active']),
        'alertsCount': row['alerts_count'] or 0,
        'lastAlerted': _time_ago(row['last_alerted']) if row['last_alerted'] else 'Never',
        'target':      target,
        'triggers':    triggers,
        **meta,
    }


class ChannelBody(BaseModel):
    type:       str
    name:       str
    config:     dict       = {}
    severities: list[str]  = ['critical', 'high']
    all_rules:  bool       = True
    rule_ids:   list[int]  = []
    active:     bool       = True


class ChannelPatch(BaseModel):
    active:     Optional[bool]       = None
    name:       Optional[str]        = None
    config:     Optional[dict]       = None
    severities: Optional[list[str]]  = None
    all_rules:  Optional[bool]       = None
    rule_ids:   Optional[list[int]]  = None


@app.get('/api/channels')
def get_channels():
    db = get_db()
    rows = db.execute('SELECT * FROM alert_channels ORDER BY id').fetchall()
    result = [_map_channel(r) for r in rows]
    db.close()
    return result


@app.post('/api/channels', status_code=201)
def create_channel(body: ChannelBody):
    db = get_db()
    cur = db.execute(
        """INSERT INTO alert_channels (type, name, config, severities, all_rules, rule_ids, active)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [body.type, body.name, json.dumps(body.config),
         json.dumps(body.severities), int(body.all_rules),
         json.dumps(body.rule_ids), int(body.active)],
    )
    db.commit()
    row = db.execute('SELECT * FROM alert_channels WHERE id=?', [cur.lastrowid]).fetchone()
    result = _map_channel(row)
    db.close()
    return result


@app.patch('/api/channels/{channel_id}')
def patch_channel(channel_id: int, body: ChannelPatch):
    db = get_db()
    if not db.execute('SELECT id FROM alert_channels WHERE id=?', [channel_id]).fetchone():
        raise HTTPException(404, 'Channel not found')

    updates: dict[str, Any] = {}
    if body.active     is not None: updates['active']     = int(body.active)
    if body.name       is not None: updates['name']       = body.name
    if body.config     is not None: updates['config']     = json.dumps(body.config)
    if body.severities is not None: updates['severities'] = json.dumps(body.severities)
    if body.all_rules  is not None: updates['all_rules']  = int(body.all_rules)
    if body.rule_ids   is not None: updates['rule_ids']   = json.dumps(body.rule_ids)

    if updates:
        set_clause = ', '.join(f'{k}=?' for k in updates)
        db.execute(f'UPDATE alert_channels SET {set_clause} WHERE id=?',
                   list(updates.values()) + [channel_id])
        db.commit()

    row = db.execute('SELECT * FROM alert_channels WHERE id=?', [channel_id]).fetchone()
    result = _map_channel(row)
    db.close()
    return result


@app.delete('/api/channels/{channel_id}')
def delete_channel(channel_id: int):
    db = get_db()
    if not db.execute('SELECT id FROM alert_channels WHERE id=?', [channel_id]).fetchone():
        raise HTTPException(404, 'Channel not found')
    db.execute('DELETE FROM alert_channels WHERE id=?', [channel_id])
    db.commit()
    db.close()
    return {'ok': True}


@app.post('/api/channels/test')
def test_channel(body: ChannelBody):
    """Fire a real test notification to the configured destination."""
    cfg = body.config
    t   = body.type
    msg = (
        '🚨 Test alert from Velaris Analytics\n'
        'Service: example-service  |  Severity: critical\n'
        'This confirms your alert channel is working correctly.'
    )

    try:
        if t == 'slack':
            url = cfg.get('webhook_url', '')
            if not url:
                return {'ok': False, 'message': 'No webhook URL configured'}
            mention = cfg.get('mention', '')
            text    = f'{mention} {msg}' if mention else msg
            r = requests.post(url, json={'text': text}, timeout=10)
            r.raise_for_status()
            return {'ok': True, 'message': 'Test alert delivered to Slack'}

        elif t == 'discord':
            url = cfg.get('webhook_url', '')
            if not url:
                return {'ok': False, 'message': 'No webhook URL configured'}
            mention  = cfg.get('mention', '')
            content  = f'{mention} {msg}' if mention else msg
            username = cfg.get('username', 'Velaris')
            r = requests.post(url, json={'content': content, 'username': username}, timeout=10)
            r.raise_for_status()
            return {'ok': True, 'message': 'Test alert delivered to Discord'}

        elif t == 'webhook':
            url = cfg.get('url', '')
            if not url:
                return {'ok': False, 'message': 'No URL configured'}
            method  = cfg.get('method', 'POST').upper()
            secret  = cfg.get('secret', '')
            headers_raw = cfg.get('headers', '')
            payload = json.dumps({
                'event':    'test_alert',
                'service':  'example-service',
                'severity': 'critical',
                'message':  'Test alert from Velaris Analytics',
            }).encode()
            headers: dict[str, str] = {'Content-Type': 'application/json'}
            if secret:
                sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
                headers['X-Velaris-Signature'] = f'sha256={sig}'
            for line in (headers_raw or '').splitlines():
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            r = requests.request(method, url, data=payload, headers=headers, timeout=10)
            r.raise_for_status()
            return {'ok': True, 'message': f'Test alert delivered to webhook (HTTP {r.status_code})'}

        else:
            return {'ok': False, 'message': f'Unknown channel type: {t}'}

    except requests.exceptions.ConnectionError:
        return {'ok': False, 'message': 'Connection refused — check the URL is correct and reachable'}
    except requests.exceptions.Timeout:
        return {'ok': False, 'message': 'Request timed out — destination did not respond within 10s'}
    except requests.exceptions.HTTPError as exc:
        return {'ok': False, 'message': f'Destination returned HTTP {exc.response.status_code}'}
    except Exception as exc:
        return {'ok': False, 'message': str(exc)}


@app.get('/api/services')
def get_services(range: str = '7d'):
    start, end = _range_to_datetimes(range)
    try:
        rows = _oz_query(
            f'SELECT DISTINCT service FROM "{OZ_STREAM}" WHERE service IS NOT NULL',
            start, end, size=200,
        )
        svcs = sorted({r['service'] for r in rows if r.get('service')})
        return [{'id': s, 'name': s, 'status': 'up'} for s in svcs]
    except Exception:
        db = get_db()
        svcs = [r[0] for r in db.execute('SELECT DISTINCT service FROM incidents ORDER BY service').fetchall()]
        db.close()
        return [{'id': s, 'name': s, 'status': 'up'} for s in svcs]


@app.get('/api/timeseries')
def get_timeseries(range: str = '4h'):
    # TODO: bucket size is fixed at 5 minutes and labels are 'HH:MM' with no date,
    # so for ranges > 24h (7d/30d/90d/180d/360d) buckets from different days with the
    # same HH:MM collide/overwrite in `buckets` below — charts only show the last day's
    # data, not an aggregate over the full range. Needs a range-scaled bucket size
    # (e.g. daily buckets for 90d+) and a label that includes the date.
    start, end = _range_to_datetimes(range)
    try:
        sql = f"""
            SELECT histogram(_timestamp,'5 minute') AS bucket, service,
                   COUNT(*) AS total,
                   SUM(CASE WHEN status_code>=400 THEN 1 ELSE 0 END) AS errors,
                   AVG(duration_ms) AS avg_latency
            FROM "{OZ_STREAM}"
            WHERE status_code IS NOT NULL AND service IS NOT NULL
            GROUP BY bucket, service ORDER BY bucket
        """
        rows = _oz_query(sql, start, end, size=50_000)

        buckets: dict[tuple, dict] = {}
        services: set[str] = set()
        for row in rows:
            raw = row.get('bucket')
            try:
                ts = datetime.fromtimestamp(int(raw) / 1_000_000, tz=timezone.utc).strftime('%H:%M')
            except Exception:
                try:
                    ts = datetime.fromisoformat(str(raw).replace('Z', '+00:00')).strftime('%H:%M')
                except Exception:
                    continue
            svc   = row.get('service', '')
            total = int(row.get('total') or 0)
            if total == 0:
                continue
            errs  = int(row.get('errors') or 0)
            services.add(svc)
            buckets[(ts, svc)] = {
                'error_rate': round(errs / total * 100, 3),
                'latency':    round(float(row.get('avg_latency') or 0), 1),
                'volume':     total,
            }

        labels = sorted({k[0] for k in buckets})
        # Rank services by total request volume, keep top N so charts stay readable
        svc_volume = {}
        for (_, svc), data in buckets.items():
            svc_volume[svc] = svc_volume.get(svc, 0) + data['volume']
        svc_list = sorted(
            sorted(svc_volume, key=svc_volume.get, reverse=True)[:TOP_N_SERIES]
        )
        return {
            'labels':    labels,
            'errorRate': [{'service': s, 'data': [buckets.get((l, s), {}).get('error_rate', 0) for l in labels]} for s in svc_list],
            'latency':   [{'service': s, 'data': [buckets.get((l, s), {}).get('latency',    0) for l in labels]} for s in svc_list],
            'volume':    [{'service': s, 'data': [buckets.get((l, s), {}).get('volume',     0) for l in labels]} for s in svc_list],
        }
    except Exception as exc:
        return {'labels': [], 'errorRate': [], 'latency': [], 'volume': [], 'error': str(exc)}


@app.get('/api/metrics')
def get_metrics(range: str = '4h'):
    start, end = _range_to_datetimes(range)
    db = get_db()
    rows = db.execute(
        'SELECT service, metric_name, timestamp, value FROM metrics '
        'WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp',
        [start.isoformat(), end.isoformat()],
    ).fetchall()
    db.close()

    # Build {(service, metric_name): {ts: value}} with O(1) lookup
    by_key: dict[tuple, dict[str, float]] = {}
    for r in rows:
        ts = (r['timestamp'] or '')[:16].replace('T', ' ')
        by_key.setdefault((r['service'], r['metric_name']), {})[ts] = r['value']

    result: dict[str, Any] = {}
    metric_names = {k[1] for k in by_key}
    for mn in metric_names:
        series = [(k[0], v) for k, v in by_key.items() if k[1] == mn]
        # For noisy metrics (many queues/services) keep top N by data-point count
        if len(series) > TOP_N_SERIES:
            series = sorted(series, key=lambda x: len(x[1]), reverse=True)[:TOP_N_SERIES]
        all_ts = sorted({ts for _, pts in series for ts in pts})
        result[mn] = {
            'labels': all_ts,
            'datasets': [
                {'service': svc, 'data': [pts.get(ts) for ts in all_ts]}
                for svc, pts in sorted(series)
            ],
        }
    return result


# ---------------------------------------------------------------------------
# Static file serving — MUST be last so API routes take priority
# ---------------------------------------------------------------------------

app.mount('/static', StaticFiles(directory=STATIC_DIR), name='static')


@app.get('/{full_path:path}')
def serve_spa(full_path: str):
    return FileResponse(STATIC_DIR / 'index.html')
