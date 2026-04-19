"""
Velaris.io Log Analytics Dashboard

Tabs:
  Overview   - KPI summary + time-series charts
  Incidents  - anomaly cards with status management and playbook viewer
  Rules      - full CRUD for diagnosis_rules (knowledge base)
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / '.env')

OZ_URL    = os.getenv('OPENOBSERVE_URL',    'http://localhost:5080')
OZ_USER   = os.getenv('OPENOBSERVE_USER',   'admin@velaris.local')
OZ_PASS   = os.getenv('OPENOBSERVE_PASS',   'Admin1234!')
OZ_ORG    = os.getenv('OPENOBSERVE_ORG',    'default')
OZ_STREAM = os.getenv('OPENOBSERVE_STREAM', 'velaris_logs')
DB_PATH   = os.getenv('DB_PATH',            str(Path(__file__).parent.parent / 'db' / 'incidents.db'))

st.set_page_config(
    page_title='Velaris Log Analytics',
    page_icon='📊',
    layout='wide',
    initial_sidebar_state='expanded',
)

# ---------------------------------------------------------------------------
# Global CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
/* ── Metric cards ─────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #1A1D27;
    border-radius: 10px;
    padding: 16px 20px;
    border: 1px solid rgba(255,255,255,0.07);
}
[data-testid="stMetricLabel"] { font-size: 0.75rem; font-weight: 600; letter-spacing: .05em; text-transform: uppercase; opacity: 0.6; }
[data-testid="stMetricValue"] { font-size: 1.65rem; font-weight: 700; }

/* ── Incident cards ───────────────────────────────────────── */
.inc-card {
    background: #1A1D27;
    border-radius: 10px;
    border-left: 5px solid #334155;
    padding: 16px 20px;
    margin-bottom: 12px;
    border-top: 1px solid rgba(255,255,255,0.06);
    border-right: 1px solid rgba(255,255,255,0.06);
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
.inc-card.sev-critical { border-left-color: #EF4444; }
.inc-card.sev-high     { border-left-color: #F97316; }
.inc-card.sev-medium   { border-left-color: #3B82F6; }

.inc-header  { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 4px; }
.inc-service { font-weight: 700; font-size: 1rem; color: #F1F5F9; }
.inc-time    { font-size: 0.78rem; color: #64748B; }
.inc-diag    { font-size: 0.82rem; color: #94A3B8; margin-top: 4px; }

/* ── Badges ───────────────────────────────────────────────── */
.badge {
    display: inline-block; padding: 2px 10px; border-radius: 99px;
    font-size: 0.68rem; font-weight: 700; letter-spacing: .05em; text-transform: uppercase;
}
.badge-open         { background: rgba(239,68,68,0.2);   color: #FCA5A5; }
.badge-acknowledged { background: rgba(245,158,11,0.2);  color: #FCD34D; }
.badge-resolved     { background: rgba(16,185,129,0.2);  color: #6EE7B7; }
.badge-both         { background: rgba(239,68,68,0.2);   color: #FCA5A5; }
.badge-error_rate   { background: rgba(249,115,22,0.2);  color: #FDBA74; }
.badge-latency      { background: rgba(99,102,241,0.2);  color: #A5B4FC; }

/* ── Rule cards ───────────────────────────────────────────── */
.rule-card {
    background: #1A1D27;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
    border: 1px solid rgba(255,255,255,0.07);
}
.rule-name   { font-weight: 700; color: #F1F5F9; font-size: 0.95rem; }
.rule-detail { font-size: 0.78rem; color: #64748B; margin-top: 3px; }
.rule-diag   { font-size: 0.8rem;  color: #94A3B8; margin-top: 6px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Colour palette shared by all Plotly charts
# ---------------------------------------------------------------------------

SVC_COLORS = ['#6366F1', '#F97316', '#10B981', '#3B82F6', '#EF4444', '#8B5CF6']
SVC_FILLS  = [
    'rgba(99,102,241,0.15)',  'rgba(249,115,22,0.15)',
    'rgba(16,185,129,0.15)',  'rgba(59,130,246,0.15)',
    'rgba(239,68,68,0.15)',   'rgba(139,92,246,0.15)',
]

_FONT   = dict(family='Inter, system-ui, sans-serif', color='#94A3B8', size=12)
_TICK   = dict(color='#64748B', size=11)
_AXIS_X = dict(showgrid=False, tickfont=_TICK, title_font=_FONT, linecolor='#2D3748')
_AXIS_Y = dict(gridcolor='#2D3748', gridwidth=1, zeroline=False, tickfont=_TICK, title_font=_FONT)

CHART_LAYOUT = dict(
    paper_bgcolor='#1A1D27',
    plot_bgcolor='#1A1D27',
    font=_FONT,
    legend=dict(orientation='h', y=-0.25, font=dict(size=11, color='#94A3B8')),
    margin=dict(t=16, b=8, l=8, r=8),
    xaxis=_AXIS_X,
    yaxis=_AXIS_Y,
    hoverlabel=dict(bgcolor='#0F1117', font_color='#F1F5F9', font_size=12),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@st.cache_resource
def _oz_session() -> requests.Session:
    s = requests.Session()
    s.auth = (OZ_USER, OZ_PASS)
    s.headers['Content-Type'] = 'application/json'
    return s


def oz_query(sql: str, start_dt: datetime, end_dt: datetime, size: int = 10_000) -> list[dict]:
    payload = {
        'query': {
            'sql':        sql,
            'start_time': int(start_dt.timestamp() * 1_000_000),
            'end_time':   int(end_dt.timestamp()   * 1_000_000),
            'from':       0,
            'size':       size,
        }
    }
    resp = _oz_session().post(f'{OZ_URL}/api/{OZ_ORG}/_search', json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json().get('hits', [])


@st.cache_resource
def get_db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def db() -> sqlite3.Connection:
    return get_db()


def badge(text: str, cls: str) -> str:
    return f'<span class="badge badge-{cls}">{text}</span>'


def severity_class(anomaly_type: str) -> str:
    return {'both': 'sev-critical', 'error_rate': 'sev-high', 'latency': 'sev-medium'}.get(anomaly_type, '')


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("""
    <div style="padding: 8px 0 20px">
        <div style="font-size:1.25rem;font-weight:800;color:#F1F5F9;letter-spacing:-.02em;">
            Velaris Analytics
        </div>
        <div style="font-size:0.72rem;color:#94A3B8;margin-top:2px;">
            Log anomaly detection platform
        </div>
    </div>
    """, unsafe_allow_html=True)

    range_opts = {
        'Last 30 min':       timedelta(minutes=30),
        'Last 1 hour':       timedelta(hours=1),
        'Last 6 hours':      timedelta(hours=6),
        'Last 24 hours':     timedelta(hours=24),
        'Last 7 days':       timedelta(days=7),
        'Last 30 days':      timedelta(days=30),
        'Eval day (Apr 18)': None,
    }
    selected_range = st.selectbox('Time range', list(range_opts.keys()), index=4)

    now = datetime.now()
    if selected_range == 'Eval day (Apr 18)':
        range_start = datetime(2026, 4, 18, 0, 0)
        range_end   = datetime(2026, 4, 19, 0, 0)
    else:
        range_end   = now
        range_start = now - range_opts[selected_range]

    st.caption(f'{range_start.strftime("%b %d %H:%M")}  →  {range_end.strftime("%b %d %H:%M")}')
    st.divider()

    @st.cache_data(ttl=120)
    def get_services(start: datetime, end: datetime) -> list[str]:
        try:
            rows = oz_query(
                f'SELECT DISTINCT service FROM "{OZ_STREAM}" WHERE service IS NOT NULL',
                start, end, size=200,
            )
            return sorted({r['service'] for r in rows if r.get('service')})
        except Exception:
            return []

    all_services     = get_services(range_start, range_end)
    selected_services = st.multiselect('Filter services', all_services, default=all_services)

    st.divider()
    try:
        _oz_session().get(f'{OZ_URL}/healthz', timeout=3).raise_for_status()
        st.markdown('<span style="color:#34D399;font-size:.8rem;">&#9679; OpenObserve connected</span>', unsafe_allow_html=True)
    except Exception:
        st.markdown('<span style="color:#F87171;font-size:.8rem;">&#9679; OpenObserve unreachable</span>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab_overview, tab_incidents, tab_rules = st.tabs(['📈  Overview', '🚨  Incidents', '📋  Rules'])


# ============================================================
# TAB 1 — OVERVIEW
# ============================================================

with tab_overview:

    # ── KPI summary row ──────────────────────────────────────
    open_count  = db().execute(
        "SELECT COUNT(*) FROM incidents WHERE status='open' AND detected_at >= ? AND detected_at <= ?",
        [range_start.isoformat(), range_end.isoformat()],
    ).fetchone()[0]

    total_count = db().execute(
        'SELECT COUNT(*) FROM incidents WHERE detected_at >= ? AND detected_at <= ?',
        [range_start.isoformat(), range_end.isoformat()],
    ).fetchone()[0]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric('Open Incidents',     open_count)
    k2.metric('Total Incidents',    total_count)
    k3.metric('Services Monitored', len(all_services))
    k4.metric('Detection Threshold', '3.0 σ')

    st.markdown('<div style="margin-top:8px"/>', unsafe_allow_html=True)

    # ── Time-series data ─────────────────────────────────────
    @st.cache_data(ttl=60)
    def load_timeseries(start: datetime, end: datetime) -> pd.DataFrame:
        sql = f"""
            SELECT
                histogram(_timestamp, '5 minute')                              AS bucket,
                service,
                COUNT(*)                                                        AS total,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)            AS errors,
                AVG(duration_ms)                                                AS avg_latency
            FROM "{OZ_STREAM}"
            WHERE status_code IS NOT NULL
              AND service IS NOT NULL
            GROUP BY bucket, service
            ORDER BY bucket
        """
        try:
            rows = oz_query(sql, start, end, size=50_000)
        except Exception as exc:
            st.error(f'OpenObserve query failed: {exc}')
            return pd.DataFrame()

        records = []
        for row in rows:
            raw = row.get('bucket')
            try:
                ts = datetime.fromtimestamp(int(raw) / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
            except (TypeError, ValueError):
                try:
                    ts = datetime.fromisoformat(str(raw).replace('Z', '+00:00')).replace(tzinfo=None)
                except ValueError:
                    continue
            t   = int(row.get('total') or 0)
            err = int(row.get('errors') or 0)
            records.append({
                'bucket':      ts,
                'service':     row.get('service', ''),
                'total':       t,
                'errors':      err,
                'error_rate':  err / t if t else 0,
                'avg_latency': float(row.get('avg_latency') or 0),
            })
        return pd.DataFrame(records)

    df_ts = load_timeseries(range_start, range_end)

    if df_ts.empty:
        st.info('No HTTP traffic data for this time range.')
    else:
        svcs = selected_services or df_ts['service'].unique().tolist()
        df_ts = df_ts[df_ts['service'].isin(svcs)]

        col1, col2 = st.columns(2)

        with col1:
            st.subheader('Error Rate (%)')
            fig_err = go.Figure()
            for i, svc in enumerate(df_ts['service'].unique()):
                d = df_ts[df_ts['service'] == svc]
                fig_err.add_trace(go.Scatter(
                    x=d['bucket'], y=(d['error_rate'] * 100).round(2),
                    mode='lines', name=svc,
                    line=dict(color=SVC_COLORS[i % len(SVC_COLORS)], width=2),
                    fill='tozeroy',
                    fillcolor=SVC_FILLS[i % len(SVC_FILLS)],
                    hovertemplate='<b>%{fullData.name}</b><br>%{x}<br>Error rate: %{y:.2f}%<extra></extra>',
                ))
            fig_err.update_layout(**CHART_LAYOUT, height=320, yaxis_title='Error rate %')
            st.plotly_chart(fig_err, use_container_width=True)

        with col2:
            st.subheader('Mean Latency (ms)')
            fig_lat = go.Figure()
            for i, svc in enumerate(df_ts['service'].unique()):
                d = df_ts[df_ts['service'] == svc]
                fig_lat.add_trace(go.Scatter(
                    x=d['bucket'], y=d['avg_latency'].round(1),
                    mode='lines', name=svc,
                    line=dict(color=SVC_COLORS[i % len(SVC_COLORS)], width=2),
                    hovertemplate='<b>%{fullData.name}</b><br>%{x}<br>Latency: %{y:.1f} ms<extra></extra>',
                ))
            fig_lat.update_layout(**CHART_LAYOUT, height=320, yaxis_title='Avg latency ms')
            st.plotly_chart(fig_lat, use_container_width=True)

        st.subheader('Request Volume')
        fig_vol = go.Figure()
        for i, svc in enumerate(df_ts['service'].unique()):
            d = df_ts[df_ts['service'] == svc]
            fig_vol.add_trace(go.Bar(
                x=d['bucket'], y=d['total'], name=svc,
                marker_color=SVC_COLORS[i % len(SVC_COLORS)],
                hovertemplate='<b>%{fullData.name}</b><br>%{x}<br>Requests: %{y}<extra></extra>',
            ))
        fig_vol.update_layout(**CHART_LAYOUT, barmode='stack', height=260, yaxis_title='Requests / 5 min')
        st.plotly_chart(fig_vol, use_container_width=True)


# ============================================================
# TAB 2 — INCIDENTS
# ============================================================

with tab_incidents:
    st.markdown('### Detected Incidents')

    c_filter, c_space = st.columns([2, 5])
    with c_filter:
        status_filter = st.multiselect(
            'Status filter',
            ['open', 'acknowledged', 'resolved'],
            default=['open', 'acknowledged'],
            label_visibility='collapsed',
        )

    placeholders = ','.join('?' * len(status_filter)) if status_filter else "'open'"
    rows = db().execute(
        f"""SELECT * FROM incidents
            WHERE detected_at >= ?
              AND detected_at <= ?
              {'AND status IN (' + placeholders + ')' if status_filter else ''}
            ORDER BY detected_at DESC""",
        [range_start.isoformat(), range_end.isoformat()] + list(status_filter),
    ).fetchall()

    if not rows:
        st.info('No incidents match the current filters.')
    else:
        for inc in rows:
            atype  = inc['anomaly_type']
            status = inc['status']
            sev_cls = severity_class(atype)

            # Card header rendered as HTML
            st.markdown(f"""
            <div class="inc-card {sev_cls}">
                <div class="inc-header">
                    <span class="inc-service">{inc['service']}</span>
                    {badge(atype.replace('_', ' '), atype)}
                    {badge(status, status)}
                    <span class="inc-time">detected {inc['detected_at'][:16]}</span>
                </div>
                <div class="inc-diag">{inc['diagnosis_label'] or 'No diagnosis'}</div>
            </div>
            """, unsafe_allow_html=True)

            # Interactive controls in an expander
            with st.expander(f'Details — #{inc["id"]}', expanded=False):
                c1, c2, c3, c4 = st.columns(4)
                c1.metric('Error Rate',  f"{float(inc['error_rate'] or 0)*100:.1f}%")
                c2.metric('Latency',     f"{float(inc['mean_duration_ms'] or 0):.0f} ms")
                c3.metric('Z (errors)',  f"{float(inc['z_score_errors'] or 0):.1f}")
                c4.metric('Z (latency)', f"{float(inc['z_score_latency'] or 0):.1f}")

                if inc['playbook']:
                    if st.toggle('Show playbook', key=f'pb_{inc["id"]}'):
                        st.code(inc['playbook'], language=None)

                if inc['sample_errors']:
                    try:
                        msgs = json.loads(inc['sample_errors'])
                        if msgs and st.toggle('Show sample errors', key=f'se_{inc["id"]}'):
                            for m in msgs[:5]:
                                st.text(m[:200])
                    except (json.JSONDecodeError, TypeError):
                        pass

                new_status = st.selectbox(
                    'Update status',
                    ['open', 'acknowledged', 'resolved'],
                    index=['open', 'acknowledged', 'resolved'].index(status),
                    key=f'status_{inc["id"]}',
                )
                if new_status != status and st.button('Save status', key=f'save_{inc["id"]}', type='primary'):
                    db().execute('UPDATE incidents SET status = ? WHERE id = ?', (new_status, inc['id']))
                    db().commit()
                    st.rerun()


# ============================================================
# TAB 3 — RULES
# ============================================================

with tab_rules:
    st.markdown('### Diagnosis Rules')
    st.caption(
        'Rules are evaluated in order: service-specific first, then catch-all. '
        'First match wins. Leave **Service** blank to match any service.'
    )

    rules = db().execute('SELECT * FROM diagnosis_rules ORDER BY id').fetchall()

    for rule in rules:
        svc_tag  = f'  ·  {rule["service"]}' if rule['service'] else '  ·  any service'
        dis_tag  = '  ·  DISABLED' if not rule['enabled'] else ''
        checks   = []
        if rule['check_errors']:  checks.append('errors')
        if rule['check_latency']: checks.append('latency')

        # Non-interactive summary rendered as HTML
        st.markdown(f"""
        <div class="rule-card">
            <div class="rule-name">{rule['name']}</div>
            <div class="rule-detail">
                {svc_tag}{dis_tag}
                &nbsp;&nbsp;·&nbsp;&nbsp; Z &ge; {rule['min_z_score']}
                &nbsp;&nbsp;·&nbsp;&nbsp; checks: {', '.join(checks) or 'none'}
                {f'&nbsp;&nbsp;·&nbsp;&nbsp; log contains: <code>{rule["log_contains"]}</code>' if rule['log_contains'] else ''}
            </div>
            <div class="rule-diag">{rule['diagnosis']}</div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander('Edit rule', expanded=False):
            with st.form(key=f'rule_form_{rule["id"]}'):
                c1, c2 = st.columns(2)
                name = c1.text_input('Rule name', value=rule['name'])
                svc  = c2.text_input('Service (blank = any)', value=rule['service'] or '')

                c3, c4 = st.columns(2)
                log_contains = c3.text_input('Log contains', value=rule['log_contains'] or '')
                min_z = c4.number_input('Min Z-score', value=float(rule['min_z_score']), step=0.5)

                c5, c6, c7 = st.columns(3)
                check_errors  = c5.checkbox('Check error rate', value=bool(rule['check_errors']))
                check_latency = c6.checkbox('Check latency',    value=bool(rule['check_latency']))
                enabled       = c7.checkbox('Enabled',          value=bool(rule['enabled']))

                diagnosis = st.text_input('Diagnosis label', value=rule['diagnosis'])
                playbook  = st.text_area('Playbook', value=rule['playbook'], height=140)

                col_save, col_del = st.columns(2)
                saved   = col_save.form_submit_button('Save changes', type='primary')
                deleted = col_del.form_submit_button('Delete rule')

            if saved:
                db().execute(
                    """UPDATE diagnosis_rules
                       SET name=?, service=?, log_contains=?, min_z_score=?,
                           check_errors=?, check_latency=?, enabled=?, diagnosis=?, playbook=?
                       WHERE id=?""",
                    (name, svc or None, log_contains or None, min_z,
                     int(check_errors), int(check_latency), int(enabled),
                     diagnosis, playbook, rule['id']),
                )
                db().commit()
                st.success('Rule updated.')
                st.rerun()

            if deleted:
                db().execute('DELETE FROM diagnosis_rules WHERE id = ?', (rule['id'],))
                db().commit()
                st.warning('Rule deleted.')
                st.rerun()

    # ── Add new rule ───────────────────────────────────────────
    st.divider()
    st.subheader('Add new rule')
    with st.form('new_rule_form'):
        c1, c2 = st.columns(2)
        new_name = c1.text_input('Rule name')
        new_svc  = c2.text_input('Service (blank = any)')

        c3, c4 = st.columns(2)
        new_log_contains = c3.text_input('Log contains (optional)')
        new_min_z = c4.number_input('Min Z-score', value=3.0, step=0.5)

        c5, c6, c7 = st.columns(3)
        new_check_errors  = c5.checkbox('Check error rate', value=True)
        new_check_latency = c6.checkbox('Check latency',    value=False)
        new_enabled       = c7.checkbox('Enabled',          value=True)

        new_diagnosis = st.text_input('Diagnosis label')
        new_playbook  = st.text_area('Playbook (step-by-step response)', height=130)

        if st.form_submit_button('Add rule', type='primary'):
            if not new_name or not new_diagnosis:
                st.error('Rule name and diagnosis label are required.')
            else:
                db().execute(
                    """INSERT INTO diagnosis_rules
                           (name, service, log_contains, min_z_score,
                            check_errors, check_latency, enabled, diagnosis, playbook)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (new_name, new_svc or None, new_log_contains or None, new_min_z,
                     int(new_check_errors), int(new_check_latency), int(new_enabled),
                     new_diagnosis, new_playbook),
                )
                db().commit()
                st.success(f'Rule "{new_name}" added.')
                st.rerun()
