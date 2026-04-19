"""
SQLite schema and initialisation for the analytics engine.

Tables
------
diagnosis_rules   User-managed rules: conditions → diagnosis + playbook
incidents         Detected anomaly records written by the detector
"""
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
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            service     TEXT,               -- NULL = applies to any service
            log_contains TEXT,              -- substring to search in recent error messages
            min_z_score REAL    NOT NULL DEFAULT 3.0,
            check_errors   INTEGER NOT NULL DEFAULT 1,  -- flag error-rate anomalies
            check_latency  INTEGER NOT NULL DEFAULT 0,  -- flag latency anomalies
            diagnosis   TEXT    NOT NULL,
            playbook    TEXT    NOT NULL,
            enabled     INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    DEFAULT (datetime('now'))
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
            anomaly_type        TEXT    NOT NULL,   -- 'error_rate' | 'latency' | 'both'
            sample_errors       TEXT,               -- JSON list of recent error messages
            diagnosis_rule_id   INTEGER REFERENCES diagnosis_rules(id),
            diagnosis_label     TEXT,
            playbook            TEXT,
            status              TEXT    NOT NULL DEFAULT 'open'
                                        CHECK(status IN ('open','acknowledged','resolved'))
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_service
            ON incidents(service, detected_at);

        CREATE INDEX IF NOT EXISTS idx_incidents_status
            ON incidents(status);
    """)
    _seed_default_rules(db)
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Default rules — seeded once on first init (skipped if rules already exist)
# ---------------------------------------------------------------------------

_DEFAULT_RULES: list[dict[str, Any]] = [
    {
        'name':          'Token Service — Dependency Failure',
        'service':       'token-ms',
        'log_contains':  None,
        'min_z_score':   3.0,
        'check_errors':  1,
        'check_latency': 0,
        'diagnosis':     'Application Dependency Failure (token-ms -> userManagementService)',
        'playbook': (
            '1. Check userManagementService health endpoint\n'
            '2. Review internal API connectivity between token-ms and user-ms\n'
            '3. Inspect DB connection pool status on shared RDS instance\n'
            '4. Check recent deployments on token-ms or its dependencies\n'
            '5. Escalate to platform team if issue persists > 10 min'
        ),
    },
    {
        'name':          'Success Plan — High Latency',
        'service':       'success-plan-ms',
        'log_contains':  None,
        'min_z_score':   3.0,
        'check_errors':  0,
        'check_latency': 1,
        'diagnosis':     'Resource Contention / DB Saturation (success-plan-ms)',
        'playbook': (
            '1. Check ECS task memory utilisation in CloudWatch\n'
            '2. Review RDS connection count — look for connection pool exhaustion\n'
            '3. Check if a slow query is blocking the DB (pg_stat_activity)\n'
            '4. Consider restarting the ECS task to clear connection state\n'
            '5. If memory > 90%, trigger vertical scaling or add a task replica'
        ),
    },
    {
        'name':          'Event Handler — SQS / IAM Failure',
        'service':       None,
        'log_contains':  'SQS',
        'min_z_score':   2.0,
        'check_errors':  1,
        'check_latency': 0,
        'diagnosis':     'SQS Permission or Connectivity Failure (event-handler)',
        'playbook': (
            '1. Check IAM role attached to the ECS task for sqs:SendMessage permission\n'
            '2. Verify the SQS queue ARN in the service environment variables\n'
            '3. Check if the FIFO queue deduplication ID is conflicting\n'
            '4. Review SQS CloudWatch metrics: NumberOfMessagesSent, ApproximateAgeOfOldestMessage\n'
            '5. Contact platform team to update IAM policy if AccessDenied persists'
        ),
    },
    {
        'name':          'Any Service — DB Connection Error',
        'service':       None,
        'log_contains':  'connection',
        'min_z_score':   3.0,
        'check_errors':  1,
        'check_latency': 0,
        'diagnosis':     'Database Connection Pool Exhaustion',
        'playbook': (
            '1. Check RDS instance connection count vs max_connections parameter\n'
            '2. Review pg_stat_activity for long-running or idle transactions\n'
            '3. Restart affected ECS service to reset connection pool\n'
            '4. If connections are maxed, scale up RDS instance class\n'
            '5. Consider enabling RDS Proxy to manage connection pooling'
        ),
    },
    {
        'name':          'Any Service — General Error Spike',
        'service':       None,
        'log_contains':  None,
        'min_z_score':   5.0,
        'check_errors':  1,
        'check_latency': 0,
        'diagnosis':     'Elevated Error Rate — Root Cause Unknown',
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
    count = db.execute('SELECT COUNT(*) FROM diagnosis_rules').fetchone()[0]
    if count > 0:
        return  # already seeded

    db.executemany(
        """INSERT INTO diagnosis_rules
               (name, service, log_contains, min_z_score,
                check_errors, check_latency, diagnosis, playbook)
           VALUES
               (:name, :service, :log_contains, :min_z_score,
                :check_errors, :check_latency, :diagnosis, :playbook)""",
        _DEFAULT_RULES,
    )
