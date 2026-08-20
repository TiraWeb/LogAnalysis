# Velaris.io — Log Analytics & Automated Diagnosis

A lightweight anomaly detection tool that uses Z-scores to spot weird log patterns in microservices and flag incidents. Built because paying for heavyweight APMs for side projects/dev envs is painful. Runs on **OpenObserve**, **SQLite** and a **FastAPI + React** UI.

<img width="1920" height="1028" alt="Dashboard preview" src="https://github.com/user-attachments/assets/2256e488-084d-4690-be0c-27bebb25379b" />

<img width="1920" height="1028" alt="Incident view" src="https://github.com/user-attachments/assets/73ddfae3-5e34-4ef4-beb2-010c5effa299" />

---

## How it works


```

CloudWatch JSON exports / Live logs
│
▼
ingestion/ingest.py  ──►  OpenObserve (:5080)  ◄──  engine/detector.py
│
▼
db/incidents.db (SQLite)
│
▼
dashboard/api.py  ──►  UI (:8501)

```

- **Ingestion:** Flattens messy, nested CloudWatch JSON and dumps it straight into OpenObserve via HTTP.
- **Detector:** Pulls log counts from OpenObserve, calculates Z-scores against a rolling 30-day baseline per service and writes flagged anomalies + diagnoses into a local SQLite DB.
- **Dashboard:** Simple FastAPI backend serving a lightweight React/Chart.js single-page app.

---

## Prerequisites

- Python 3.12+
- Docker & Docker Compose

---

## Quickstart

### 1. Local setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env

```

### 2. Spin up OpenObserve

```bash
docker compose up openobserve -d
# Give it ~15 seconds to initialize, then check http://localhost:5200

```

---

## Usage

### Step 1: Ingest log data

You can use the raw CloudWatch Insights dumps included in `data/raw/` (pulled from our dev env), or stream straight from AWS if you have credentials configured.

```bash
# Ingest all raw dumps in data/raw/
python ingestion/ingest.py

# Ingest a specific log dump for a single service
python ingestion/ingest.py data/raw/token-ms.json --service token-ms

# Or pull directly from AWS CloudWatch (requires local AWS auth)
python ingestion/fetch_and_ingest.py

```

### Step 2: Run the anomaly detector

```bash
# Run against the last 5 minutes
python engine/detector.py

# Run against a specific time window
python engine/detector.py --at "2026-04-18 14:15:00"

# Replay the last week of logs in 15-minute chunks (wipes old incidents)
python engine/detector.py --replay-hours 168 --clear-incidents

```

> **Note on running scripts:** Execute scripts directly (e.g., `python engine/detector.py`). Don't use `python -m engine.detector`—imports use direct relative paths and expect the script directory on `sys.path`.

### Step 3: Launch the UI

```bash
python -m uvicorn dashboard.api:app --reload --port 8501

```

Head to `http://localhost:8501`.

---

## Lazy mode (Full Docker Stack)

If you just want the whole thing up and running without managing virtualenvs:

```bash
docker compose up

```

* OpenObserve: `http://localhost:5200`
* Dashboard: `http://localhost:8501`

---

## Evaluation & Benchmarks

Ran a test replaying a 24-hour window to see how Z-score anomaly detection compares to dumb static thresholds (Z-score threshold set to `3.0` with 5-minute step windows):

```bash
python evaluation/replay.py

# Export CSV + plots for docs/write-ups:
python evaluation/export_results.py --out evaluation/results

```

### Results

| Method | Precision | Recall | F1 Score |
| --- | --- | --- | --- |
| **Z-Score (This tool)** | **80.0%** | **100%** | **0.889** |
| Static Threshold | 50.0% | 100% | 0.667 |

---

## Optional: Fetch real CloudWatch infra metrics

If you want correlated metrics alongside log spikes (ECS CPU/RAM, SQS queue depth, RDS connections):

```bash
# Needs AWS creds with CloudWatch:GetMetricStatistics permission
python metrics/fetch_metrics.py --hours 24

```

Tweak target resource ARNs and namespaces in `metrics/services.json`.

---

## Repository layout

```
├── engine/
│   ├── detector.py        # Z-score engine & pattern matching logic
│   └── models.py          # SQLite schema (incidents, rules, metrics)
├── ingestion/
│   ├── ingest.py          # Local JSON -> OpenObserve ETL
│   └── fetch_and_ingest.py# AWS CloudWatch Logs API collector
├── data/
│   └── raw/               # Sample CloudWatch log exports
├── metrics/
│   ├── fetch_metrics.py   # CloudWatch resource metrics scraper (boto3)
│   └── services.json      # Resource mappings (ECS/SQS/RDS)
├── dashboard/
│   ├── api.py             # FastAPI backend & static file server
│   └── static/index.html  # React + Chart.js dashboard app
├── evaluation/
│   ├── replay.py          # Test harness for precision/recall
│   └── export_results.py  # Generates evaluation charts/CSVs
└── db/                    # Local SQLite storage (gitignored)

```
