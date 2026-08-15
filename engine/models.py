"""
SQLite schema and initialisation for the analytics engine.

Tables
------
diagnosis_rules   User-managed rules: conditions -> diagnosis + playbook
incidents         Detected anomaly records written by the detector
metrics           Time-series metric snapshots (CloudWatch / synthetic)
alert_channels    Configured notification destinations (Slack, Discord, etc.)
"""
import json
import sqlite3
from pathlib import Path
from typing import Any


def get_db(path: str | Path) -> sqlite3.Connection:
    db = sqlite3.connect(str(path), check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')   # safe for concurrent reads
    return db


def init_db(path: str | Path) -> None:
    db = get_db(path)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS diagnosis_rules (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            name             TEXT    NOT NULL,
            service          TEXT,
            log_contains     TEXT,
            min_z_score      REAL    NOT NULL DEFAULT 3.0,
            check_errors     INTEGER NOT NULL DEFAULT 1,
            check_latency    INTEGER NOT NULL DEFAULT 0,
            metric_name      TEXT,
            metric_operator  TEXT,
            metric_threshold REAL,
            diagnosis        TEXT    NOT NULL,
            playbook         TEXT    NOT NULL,
            enabled          INTEGER NOT NULL DEFAULT 1,
            created_at       TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at         TEXT    NOT NULL DEFAULT (datetime('now')),
            service             TEXT    NOT NULL,
            window_start        TEXT    NOT NULL,
            window_end          TEXT    NOT NULL,
            error_rate          REAL,
            mean_duration_ms    REAL,
            z_score_errors      REAL,
            z_score_latency     REAL,
            anomaly_type        TEXT    NOT NULL,
            sample_errors       TEXT,
            diagnosis_rule_id   INTEGER REFERENCES diagnosis_rules(id),
            diagnosis_label     TEXT,
            playbook            TEXT,
            status              TEXT    NOT NULL DEFAULT 'open'
                                        CHECK(status IN ('open','acknowledged','resolved'))
        );

        CREATE TABLE IF NOT EXISTS metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            service     TEXT    NOT NULL,
            metric_name TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            value       REAL    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_service
            ON incidents(service, detected_at);

        CREATE INDEX IF NOT EXISTS idx_incidents_status
            ON incidents(status);

        CREATE INDEX IF NOT EXISTS idx_metrics_svc_name_ts
            ON metrics(service, metric_name, timestamp);

        CREATE TABLE IF NOT EXISTS alert_channels (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            type         TEXT    NOT NULL,
            name         TEXT    NOT NULL,
            config       TEXT    NOT NULL DEFAULT '{}',
            severities   TEXT    NOT NULL DEFAULT '["critical","high"]',
            all_rules    INTEGER NOT NULL DEFAULT 1,
            rule_ids     TEXT    NOT NULL DEFAULT '[]',
            active       INTEGER NOT NULL DEFAULT 1,
            alerts_count INTEGER NOT NULL DEFAULT 0,
            last_alerted TEXT,
            created_at   TEXT    DEFAULT (datetime('now'))
        );
    """)
    _migrate(db)
    _seed_default_rules(db)
    _seed_default_channels(db)
    db.commit()
    db.close()


def _migrate(db: sqlite3.Connection) -> None:
    """Add columns/tables that may be missing in databases created before this migration."""
    migrations = [
        "ALTER TABLE diagnosis_rules ADD COLUMN metric_name      TEXT",
        "ALTER TABLE diagnosis_rules ADD COLUMN metric_operator  TEXT",
        "ALTER TABLE diagnosis_rules ADD COLUMN metric_threshold REAL",
        """CREATE TABLE IF NOT EXISTS alert_channels (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            type         TEXT    NOT NULL,
            name         TEXT    NOT NULL,
            config       TEXT    NOT NULL DEFAULT '{}',
            severities   TEXT    NOT NULL DEFAULT '["critical","high"]',
            all_rules    INTEGER NOT NULL DEFAULT 1,
            rule_ids     TEXT    NOT NULL DEFAULT '[]',
            active       INTEGER NOT NULL DEFAULT 1,
            alerts_count INTEGER NOT NULL DEFAULT 0,
            last_alerted TEXT,
            created_at   TEXT    DEFAULT (datetime('now'))
        )""",
        """CREATE TABLE IF NOT EXISTS metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            service     TEXT    NOT NULL,
            metric_name TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL,
            value       REAL    NOT NULL
        )""",
        """CREATE INDEX IF NOT EXISTS idx_metrics_svc_name_ts
            ON metrics(service, metric_name, timestamp)""",
    ]
    for stmt in migrations:
        try:
            db.execute(stmt)
        except Exception:
            pass  # column/table already exists


# ---------------------------------------------------------------------------
# Default rules — seeded once on first init (skipped if rules already exist)
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[dict[str, Any]] = [
    # ── Velaris real-world rules (from dev env log scan) ──────────────────────
    {
        'name':             'Any Service — Missing Module / Broken Deployment',
        'service':          None,
        'log_contains':     'Cannot find module',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Container image missing npm dependency — incomplete deployment',
        'playbook': (
            '1. Check ECS task logs for the exact missing module name\n'
            '2. Verify the Docker image built successfully in CI/CD (check CodePipeline)\n'
            '3. Check if a recent package.json change removed or renamed the dependency\n'
            '4. Force a new ECS deployment with a corrected image build\n'
            '5. If urgent, roll back to the previous task definition revision'
        ),
    },
    {
        'name':             'Any Service — DB Schema Out of Sync',
        'service':          None,
        'log_contains':     'does not exist',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Database schema mismatch — migration not applied to this environment',
        'playbook': (
            '1. Check the error for the specific column or relation that is missing\n'
            '2. List pending database migrations and identify the missing one\n'
            '3. Run outstanding migrations against the target schema\n'
            '4. Verify the migration completed successfully with a schema diff\n'
            '5. Restart affected ECS services after migration completes\n'
            '6. If error is tenant-specific, check per-tenant schema state (schema-per-tenant pattern)'
        ),
    },
    {
        'name':             'Event Handler — SQS Consumer Failure + Queue Depth',
        'service':          None,
        'log_contains':     'SqsConsumer Processing Error',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      'sqs_depth',
        'metric_operator':  '>',
        'metric_threshold': 30.0,
        'diagnosis':        'SQS consumer failing and queue depth rising — messages backing up in queue',
        'playbook': (
            '1. Check the SQS Dead Letter Queue (DLQ) for failed message samples\n'
            '2. Inspect the exact error — check for schema/format mismatch in the message body\n'
            '3. Check if a downstream service the handler calls is returning errors\n'
            '4. If message format changed, deploy updated consumer and replay messages from DLQ\n'
            '5. If queue depth is critical, temporarily scale up ECS task count for the listener\n'
            '6. Review SQS visibility timeout — may need increasing for slow operations'
        ),
    },
    {
        'name':             'Event Handler — SQS Consumer Failure',
        'service':          None,
        'log_contains':     'SqsConsumer Processing Error',
        'min_z_score':      3.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'SQS consumer processing errors — possible message schema or downstream failure',
        'playbook': (
            '1. Check the SQS Dead Letter Queue (DLQ) for failed message samples\n'
            '2. Inspect the exact error — check for schema/format mismatch in the message body\n'
            '3. Check if a downstream service the handler calls is returning errors\n'
            '4. If message format changed, deploy updated consumer and replay messages from DLQ\n'
            '5. Review SQS visibility timeout — may need increasing for slow operations'
        ),
    },
    {
        'name':             'Salesforce — Malformed Object ID',
        'service':          None,
        'log_contains':     'MALFORMED_ID',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Salesforce API rejecting requests — malformed object ID in payload',
        'playbook': (
            '1. Check logs for the specific Salesforce object type and ID that failed\n'
            '2. Verify the Salesforce org ID and object type mapping in tenant config\n'
            '3. Check if the Salesforce record was deleted (ID no longer valid in that org)\n'
            '4. Review recent changes to the CRM integration field mapping config\n'
            '5. Contact the affected tenant to confirm their Salesforce org is accessible'
        ),
    },
    {
        'name':             'Salesforce — Config Fetch Failure',
        'service':          None,
        'log_contains':     'Error fetching Salesforce configurations',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Salesforce configuration unavailable — triggerName or config object missing',
        'playbook': (
            '1. Identify the affected tenant from the correlation ID in the log line\n'
            '2. Verify the Salesforce integration is enabled for that tenant in the admin panel\n'
            '3. Check if the Salesforce custom object (Velaris_Error_Log__c) exists in the org\n'
            '4. Review trigger config — triggerName may reference a deleted or renamed trigger\n'
            '5. Re-save the Salesforce integration config in tenant settings to force a config reload'
        ),
    },
    {
        'name':             'Webhook — Persistent Delivery Failure',
        'service':          None,
        'log_contains':     'CLIENT_ERROR',
        'min_z_score':      2.5,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Outbound webhook delivery failing — endpoint returning 4xx errors',
        'playbook': (
            '1. Check logs for the specific webhook ID and HTTP error code (404 = deleted, 410 = gone)\n'
            '2. Identify the affected tenant from the correlation ID in the log\n'
            '3. Check if the webhook endpoint URL is still valid in the tenant config\n'
            '4. If 404/410, disable or update the stale webhook to prevent continued failures\n'
            '5. Check if the external service (HubSpot, Zapier, etc.) had an outage'
        ),
    },
    {
        'name':             'Any Service — Downstream 500 Error Cascade',
        'service':          None,
        'log_contains':     'RestClientException',
        'min_z_score':      3.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Service-to-service call chain failing — downstream dependency returning 500s',
        'playbook': (
            '1. Find the incident ID in the error log — search other services for the same incident ID\n'
            '2. Identify the originating service (the first 500 in the chain)\n'
            '3. Check ECS task status and recent deployments of the originating service\n'
            '4. Check RDS connections and CPU for a DB-related root cause\n'
            '5. If the originating service is healthy, check its own downstream dependencies\n'
            '6. Escalate to on-call if the cascade is affecting multiple tenants simultaneously'
        ),
    },
    {
        'name':             'ECS Cluster — ASG Near Capacity + Service Errors',
        'service':          None,
        'log_contains':     None,
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      'asg_capacity',
        'metric_operator':  '>=',
        'metric_threshold': 85.0,
        'diagnosis':        'Service errors coinciding with ASG near maximum capacity — likely task placement failure',
        'playbook': (
            '1. Check ECS cluster events in the console for TaskPlacementFailure entries\n'
            '2. Check ASG current/desired/max instance counts — is MaxSize reached?\n'
            '3. Check individual EC2 instances for available memory (ECS container insights)\n'
            '4. Increase ASG MaxSize in the AWS console to allow new instances to launch\n'
            '5. Review ECS task memory reservations — tasks may be over-provisioned\n'
            '6. Consider migrating the affected service to Fargate to remove EC2 capacity dependency'
        ),
    },
    {
        'name':             'ECS Cluster — ASG at High Capacity + Latency',
        'service':          None,
        'log_contains':     None,
        'min_z_score':      2.0,
        'check_errors':     0,
        'check_latency':    1,
        'metric_name':      'asg_capacity',
        'metric_operator':  '>=',
        'metric_threshold': 70.0,
        'diagnosis':        'Latency degradation with ASG near capacity — EC2 instances may lack free memory for new tasks',
        'playbook': (
            '1. Check ECS cluster events for TaskPlacementFailure or RESOURCE:MEMORY errors\n'
            '2. Check memory available on each EC2 instance (ECS container insights)\n'
            '3. Increase ASG desired count to add fresh instances with available memory\n'
            '4. Review task memory reservations — reduce if tasks are over-allocated\n'
            '5. If persistent, upgrade instance type (e.g. m5.large -> m5.xlarge)'
        ),
    },
    # ── Baseline synthetic-data rules ─────────────────────────────────────────
    {
        'name':             'Token Service — CPU Spike + Error Rate',
        'service':          'token-ms',
        'log_contains':     None,
        'min_z_score':      3.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      'ecs_cpu',
        'metric_operator':  '>',
        'metric_threshold': 10.0,
        'diagnosis':        'ECS CPU Spike + Error Rate Anomaly (token-ms)',
        'playbook': (
            '1. Check ECS task CPU in CloudWatch — compare to baseline\n'
            '2. Check userManagementService health endpoint for upstream failures\n'
            '3. Inspect DB connection pool status on shared RDS instance\n'
            '4. Check recent deployments on token-ms or its dependencies\n'
            '5. If CPU > 80%, consider scaling out ECS task count\n'
            '6. Escalate to platform team if issue persists > 10 min'
        ),
    },
    {
        'name':             'Token Service — Dependency Failure',
        'service':          'token-ms',
        'log_contains':     None,
        'min_z_score':      3.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Application Dependency Failure (token-ms -> userManagementService)',
        'playbook': (
            '1. Check userManagementService health endpoint\n'
            '2. Review internal API connectivity between token-ms and user-ms\n'
            '3. Inspect DB connection pool status on shared RDS instance\n'
            '4. Check recent deployments on token-ms or its dependencies\n'
            '5. Escalate to platform team if issue persists > 10 min'
        ),
    },
    {
        'name':             'Success Plan — DB Saturation',
        'service':          'success-plan-ms',
        'log_contains':     None,
        'min_z_score':      3.0,
        'check_errors':     0,
        'check_latency':    1,
        'metric_name':      'rds_connections',
        'metric_operator':  '>',
        'metric_threshold': 50.0,
        'diagnosis':        'RDS Connection Exhaustion + High Latency (success-plan-ms)',
        'playbook': (
            '1. Check RDS connection count in CloudWatch — is it near max_connections?\n'
            '2. Check pg_stat_activity for long-running or idle transactions\n'
            '3. Restart the ECS task to reset connection pool state\n'
            '4. If connections stay high, enable RDS Proxy to pool connections\n'
            '5. If memory > 90%, trigger vertical scaling or add a task replica'
        ),
    },
    {
        'name':             'Success Plan — High Latency',
        'service':          'success-plan-ms',
        'log_contains':     None,
        'min_z_score':      3.0,
        'check_errors':     0,
        'check_latency':    1,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Resource Contention / DB Saturation (success-plan-ms)',
        'playbook': (
            '1. Check ECS task memory utilisation in CloudWatch\n'
            '2. Review RDS connection count - look for connection pool exhaustion\n'
            '3. Check if a slow query is blocking the DB (pg_stat_activity)\n'
            '4. Consider restarting the ECS task to clear connection state\n'
            '5. If memory > 90%, trigger vertical scaling or add a task replica'
        ),
    },
    {
        'name':             'Event Handler — SQS Queue Depth',
        'service':          'crm-event-handler',
        'log_contains':     'SQS',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      'sqs_depth',
        'metric_operator':  '>',
        'metric_threshold': 30.0,
        'diagnosis':        'SQS Queue Backlog + Permission Failure (crm-event-handler)',
        'playbook': (
            '1. Check SQS queue depth in CloudWatch — messages accumulating?\n'
            '2. Check IAM role attached to the ECS task for sqs:SendMessage permission\n'
            '3. Verify the SQS queue ARN in the service environment variables\n'
            '4. Check if the FIFO queue deduplication ID is conflicting\n'
            '5. Contact platform team to update IAM policy if AccessDenied persists'
        ),
    },
    {
        'name':             'Event Handler — SQS / IAM Failure',
        'service':          None,
        'log_contains':     'SQS',
        'min_z_score':      2.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'SQS Permission or Connectivity Failure (event-handler)',
        'playbook': (
            '1. Check IAM role attached to the ECS task for sqs:SendMessage permission\n'
            '2. Verify the SQS queue ARN in the service environment variables\n'
            '3. Check if the FIFO queue deduplication ID is conflicting\n'
            '4. Review SQS CloudWatch metrics: NumberOfMessagesSent, ApproximateAgeOfOldestMessage\n'
            '5. Contact platform team to update IAM policy if AccessDenied persists'
        ),
    },
    {
        'name':             'Any Service — DB Connection Error',
        'service':          None,
        'log_contains':     'connection',
        'min_z_score':      3.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Database Connection Pool Exhaustion',
        'playbook': (
            '1. Check RDS instance connection count vs max_connections parameter\n'
            '2. Review pg_stat_activity for long-running or idle transactions\n'
            '3. Restart affected ECS service to reset connection pool\n'
            '4. If connections are maxed, scale up RDS instance class\n'
            '5. Consider enabling RDS Proxy to manage connection pooling'
        ),
    },
    {
        'name':             'Any Service — General Error Spike',
        'service':          None,
        'log_contains':     None,
        'min_z_score':      5.0,
        'check_errors':     1,
        'check_latency':    0,
        'metric_name':      None,
        'metric_operator':  None,
        'metric_threshold': None,
        'diagnosis':        'Elevated Error Rate - Root Cause Unknown',
        'playbook': (
            '1. Review recent deployments across all services (CodePipeline)\n'
            '2. Check CloudWatch ECS metrics: CPU, memory, running task count\n'
            '3. Search logs for the most common error message in this window\n'
            '4. Check external dependency status pages (Hubspot, Chargebee, AWS)\n'
            '5. Escalate to on-call engineer if no deployment explains the spike'
        ),
    },
]


def _seed_default_rules(db: sqlite3.Connection) -> None:
    """Insert any default rules that don't already exist (matched by name).
    Safe to call on existing databases — only adds new rules, never overwrites."""
    for rule in _DEFAULT_RULES:
        exists = db.execute(
            'SELECT 1 FROM diagnosis_rules WHERE name = ?', (rule['name'],)
        ).fetchone()
        if not exists:
            db.execute(
                """INSERT INTO diagnosis_rules
                       (name, service, log_contains, min_z_score,
                        check_errors, check_latency,
                        metric_name, metric_operator, metric_threshold,
                        diagnosis, playbook)
                   VALUES
                       (:name, :service, :log_contains, :min_z_score,
                        :check_errors, :check_latency,
                        :metric_name, :metric_operator, :metric_threshold,
                        :diagnosis, :playbook)""",
                rule,
            )


_DEFAULT_CHANNELS: list[dict[str, Any]] = [
    {
        'type':       'slack',
        'name':       'SRE On-Call Slack',
        'config':     json.dumps({'webhook_url': '', 'channel': 'incidents-critical', 'mention': '@sre-oncall'}),
        'severities': json.dumps(['critical', 'high']),
        'all_rules':  1,
        'rule_ids':   json.dumps([]),
        'active':     1,
    },
    {
        'type':       'discord',
        'name':       'SRE Discord Alerts',
        'config':     json.dumps({'webhook_url': '', 'mention': '@sre-oncall', 'username': 'Velaris'}),
        'severities': json.dumps(['critical', 'high']),
        'all_rules':  1,
        'rule_ids':   json.dumps([]),
        'active':     1,
    },
    {
        'type':       'webhook',
        'name':       'Internal Webhook',
        'config':     json.dumps({'url': '', 'method': 'POST', 'secret': '', 'headers': ''}),
        'severities': json.dumps(['critical', 'high', 'medium']),
        'all_rules':  1,
        'rule_ids':   json.dumps([]),
        'active':     1,
    },
]


def _seed_default_channels(db: sqlite3.Connection) -> None:
    """Seed the 4 default channels if the table is empty. Never overwrites."""
    count = db.execute('SELECT COUNT(*) FROM alert_channels').fetchone()[0]
    if count > 0:
        return
    for ch in _DEFAULT_CHANNELS:
        db.execute(
            """INSERT INTO alert_channels
                   (type, name, config, severities, all_rules, rule_ids, active)
               VALUES
                   (:type, :name, :config, :severities, :all_rules, :rule_ids, :active)""",
            ch,
        )
