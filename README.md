# Log Analytics and Automated Diagnosis Platform — Velaris.io

A Z-score anomaly detection and automated diagnosis platform for microservice logs, built on OpenObserve + SQLite with a FastAPI/React dashboard.

---

## Architecture

```
CloudWatch JSON exports / synthetic logs
        │
        ▼
ingestion/ingest.py  ──►  OpenObserve (port 5080)  ◄──  engine/detector.py
                                                              │
                                                              ▼
                                                     db/incidents.db (SQLite)
                                                              │
                                                              ▼
                                               dashboard/api.py  →  :8501
```

- **Ingestion** — flattens nested CloudWatch JSON and pushes to OpenObserve via HTTP
- **Detector** — queries OpenObserve, computes Z-scores against a rolling 30-day per-service baseline, writes incidents + diagnoses to SQLite
- **Dashboard** — FastAPI backend serving a React/Chart.js SPA with live API data

---

## Prerequisites

- Python 3.12+
- Docker + Docker Compose

---

## Setup

```bash
# 1. Clone and create virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Copy environment config
cp .env.example .env             # edit if needed

# 3. Start OpenObserve
docker compose up openobserve -d
# Wait ~15 seconds, then verify: http://localhost:5200
```

---

## Running the full pipeline

### Step 1 — Ingest logs into OpenObserve

`data/raw/` already contains real CloudWatch Logs Insights exports pulled from the
Velaris.io dev environment — no generator script is needed.

```bash
python ingestion/ingest.py        # reads every *.json in data/raw/
# or target specific files:
python ingestion/ingest.py data/raw/token-ms.json --service token-ms

# or pull live logs directly from AWS CloudWatch (requires AWS credentials):
python ingestion/fetch_and_ingest.py
```

### Step 2 — Run the anomaly detector

```bash
# Analyse the current 5-minute window:
python engine/detector.py

# Analyse a specific historical window (e.g. during evaluation day):
python engine/detector.py --at "2026-04-18 14:15:00"

# Backfill by replaying N hours of history in 15-min steps:
python engine/detector.py --replay-hours 168 --clear-incidents
```

### Step 3 — Start the dashboard

```bash
python -m uvicorn dashboard.api:app --reload --port 8501
# Open: http://localhost:8501
```

Note: `engine/detector.py` and `ingestion/ingest.py` must be run as scripts
(`python engine/detector.py`), not with `-m` (`python -m engine.detector`) — they
import sibling modules by bare name (e.g. `from models import ...`), which only
resolves when the script's own directory is on `sys.path`.

---

## Evaluation

Replay the 24-hour evaluation day and print Precision / Recall / F1 vs static threshold:

```bash
python evaluation/replay.py

# Export results to CSV + PNG chart (for dissertation figures):
python evaluation/export_results.py --out evaluation/results
```

Expected results (Z=3 threshold, 5-min step):

| Method           | Precision | Recall | F1    |
|------------------|-----------|--------|-------|
| Z-Score (ours)   | 80.0%     | 100%   | 0.889 |
| Static Threshold | 50.0%     | 100%   | 0.667 |

---

## Live CloudWatch metrics (optional)

Fetch real ECS CPU/Memory, SQS queue depth and RDS connection counts:

```bash
# Requires AWS credentials with CloudWatch:GetMetricStatistics
python metrics/fetch_metrics.py --hours 24
```

Configure which resources to fetch in [metrics/services.json](metrics/services.json).

---

## Docker Compose (full stack)

```bash
docker compose up
# OpenObserve: http://localhost:5200
# Dashboard:   http://localhost:8501
```

---

## Project structure

```
engine/
  detector.py          Z-score detection engine + diagnosis rule matching
  models.py            SQLite schema (incidents, diagnosis_rules, metrics)

ingestion/
  ingest.py            CloudWatch JSON exports → OpenObserve ETL
  fetch_and_ingest.py  Live pull from AWS CloudWatch Logs → OpenObserve

data/
  raw/                 Real CloudWatch Logs Insights exports (JSON)

metrics/
  fetch_metrics.py     boto3 CloudWatch metrics fetcher
  services.json        ECS/SQS/RDS resource config

dashboard/
  api.py               FastAPI backend (REST endpoints + SPA host)
  static/index.html    React/Chart.js single-page dashboard

evaluation/
  replay.py            Precision/Recall evaluation harness
  export_results.py    Export results to CSV + comparison chart PNG

db/                    SQLite database (gitignored, recreated by detector)
```
