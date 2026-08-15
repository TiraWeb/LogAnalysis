"""
Sends real notifications to configured alert_channels when the detector
records an incident. Mirrors the Slack/Discord/webhook delivery logic in
dashboard/api.py's /api/channels/test endpoint.
"""
import hashlib
import hmac
import json
import sqlite3
from datetime import datetime

import requests

SEVERITY_MAP = {'both': 'critical', 'error_rate': 'high', 'latency': 'medium'}


def _send_slack(cfg: dict, text: str) -> bool:
    url = cfg.get('webhook_url', '')
    if not url:
        return False
    mention = cfg.get('mention', '')
    payload = {'text': f'{mention} {text}' if mention else text}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    return True


def _send_discord(cfg: dict, text: str) -> bool:
    url = cfg.get('webhook_url', '')
    if not url:
        return False
    mention = cfg.get('mention', '')
    content = f'{mention} {text}' if mention else text
    r = requests.post(
        url, json={'content': content, 'username': cfg.get('username', 'Velaris')}, timeout=10
    )
    r.raise_for_status()
    return True


def _send_webhook(cfg: dict, event: dict) -> bool:
    url = cfg.get('url', '')
    if not url:
        return False
    method = cfg.get('method', 'POST').upper()
    secret = cfg.get('secret', '')
    payload = json.dumps(event).encode()
    headers = {'Content-Type': 'application/json'}
    if secret:
        sig = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        headers['X-Velaris-Signature'] = f'sha256={sig}'
    for line in (cfg.get('headers', '') or '').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
    r = requests.request(method, url, data=payload, headers=headers, timeout=10)
    r.raise_for_status()
    return True


def notify_incident(
    db: sqlite3.Connection,
    incident_id: int,
    service: str,
    anomaly_type: str,
    diagnosis: str,
    rule_id: int | None,
    z_errors: float,
    z_latency: float,
    error_rate: float,
    mean_duration: float,
) -> None:
    """Fire real alerts to every active channel scoped to this incident's severity/rule."""
    severity = SEVERITY_MAP.get(anomaly_type, 'medium')

    channels = db.execute('SELECT * FROM alert_channels WHERE active = 1').fetchall()
    if not channels:
        return

    text = (
        f'\U0001f6a8 Incident INC-{incident_id:05d} — {service}\n'
        f'Severity: {severity}  |  Type: {anomaly_type}  |  '
        f'errZ={z_errors:.1f}σ  latZ={z_latency:.1f}σ  '
        f'err={error_rate * 100:.1f}%  lat={mean_duration:.0f}ms\n'
        f'Diagnosis: {diagnosis}'
    )
    event = {
        'event':            'incident_detected',
        'incident_id':      incident_id,
        'service':          service,
        'severity':         severity,
        'anomaly_type':     anomaly_type,
        'diagnosis':        diagnosis,
        'z_score_errors':   z_errors,
        'z_score_latency':  z_latency,
        'error_rate':       error_rate,
        'mean_duration_ms': mean_duration,
    }

    for ch in channels:
        try:
            severities = json.loads(ch['severities'] or '[]')
        except Exception:
            severities = []
        if severities and severity not in severities:
            continue

        if not ch['all_rules']:
            try:
                rule_ids = json.loads(ch['rule_ids'] or '[]')
            except Exception:
                rule_ids = []
            if rule_id is None or rule_id not in rule_ids:
                continue

        try:
            cfg = json.loads(ch['config'] or '{}')
        except Exception:
            cfg = {}

        try:
            if ch['type'] == 'slack':
                sent = _send_slack(cfg, text)
            elif ch['type'] == 'discord':
                sent = _send_discord(cfg, text)
            elif ch['type'] == 'webhook':
                sent = _send_webhook(cfg, event)
            else:
                sent = False

            if sent:
                db.execute(
                    'UPDATE alert_channels SET alerts_count = alerts_count + 1, last_alerted = ? WHERE id = ?',
                    (datetime.utcnow().isoformat(), ch['id']),
                )
                print(f'[notify] Sent {ch["type"]} alert to "{ch["name"]}" for incident {incident_id}')
        except Exception as exc:
            print(f'[notify] Failed to send to channel "{ch["name"]}" ({ch["type"]}): {exc}')

    db.commit()
