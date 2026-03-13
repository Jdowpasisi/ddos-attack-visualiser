<div align="center">

```
██████╗ ██████╗  ██████╗ ███████╗    ███╗   ███╗ █████╗ ██████╗
██╔══██╗██╔══██╗██╔═══██╗██╔════╝    ████╗ ████║██╔══██╗██╔══██╗
██║  ██║██║  ██║██║   ██║███████╗    ██╔████╔██║███████║██████╔╝
██║  ██║██║  ██║██║   ██║╚════██║    ██║╚██╔╝██║██╔══██║██╔═══╝
██████╔╝██████╔╝╚██████╔╝███████║    ██║ ╚═╝ ██║██║  ██║██║
╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
```

# DDoS Attack Map Visualiser

**Real-time AI-powered threat intelligence on a 3D globe**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)](https://reactjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

[Quick Start](#quick-start) · [Screenshots](#screenshots) · [Architecture](#architecture) · [Features](#features) · [API Reference](#api-reference)

![Dashboard Screenshot](screenshots/dashboard-full.png)

</div>

---

## Overview

A full-stack cybersecurity threat visualisation system that ingests live malicious IP data from **seven threat intelligence sources**, scores each threat with a **RandomForest classifier trained on CICIDS2017**, and renders attacks as animated arcs on a **WebGL 3D globe** — all updating in real time over WebSocket.

An **autonomous LLM agent** (Groq Llama 3.3 70B) automatically investigates high-severity events: it queries its own incident history, looks up IP reputation, fetches CVE data or trend context, and writes structured incident reports — with different tool sequences for repeat attackers vs new threats.

```
Live Threat Feeds → Geo Enrichment → ML Scoring → PostgreSQL → WebSocket → 3D Globe
                                                       ↓
                                              AI Agent Investigation
                                              (severity ≥ 8.0 events)
                                                       ↓
                                              LLM Briefing Synthesis
```

---

## Screenshots

### Full Dashboard

![Full Dashboard](screenshots/dashboard-full.png)

### Panel Gallery

| AI Threat Analysis | Incident Reports |
|---|---|
| ![AI Threat Analysis](screenshots/ai-threat-analysis.png) | ![Incident Reports](screenshots/incident-reports.png) |
| ![Attack Intel](screenshots/attack-intel.png) | ![Threat Level Gauge](screenshots/threat-level-gauge.png) |
| ![Live Threat Stream](screenshots/live-threat-stream.png) | ![Total Events](screenshots/total-events.png) |

### Incident Drilldown

![Detailed Incident Reports](screenshots/detailed-incident-reports.png)

---

## Features

<table>
<tr>
<td width="50%">

### Real-Time Visualisation
- WebGL 3D globe via `react-globe.gl` (Three.js)
- Animated attack arcs colour-coded by severity
- **Arc aggregation** — repeated patterns merge into weighted arcs (log-scale stroke, peak severity retained)
- 30-second TTL eviction for visual freshness
- Pause-and-inspect with per-arc detail panel
- Simulated arcs render as dashed, real arcs as solid

</td>
<td width="50%">

### Autonomous AI Agent
- Fires automatically on severity ≥ 8.0 events
- 4-tool agentic loop: incident history → IP reputation → CVE lookup / trend analysis
- **Adaptive branching**: repeat attackers get CVE focus, new attackers get trend context
- Detects coordinated campaigns across events
- REPEAT / CAMPAIGN badges in the incidents panel
- Live tool-call progress widget during investigation

</td>
</tr>
<tr>
<td width="50%">

### Machine Learning
- RandomForest classifier trained on **CICIDS2017** (~180k real traffic samples)
- SMOTE balancing on training set only
- 9 network flow features (packet rates, byte rates, TCP flags, IAT, protocol)
- ~99.7% ROC-AUC on held-out test set
- Severity formula: `min(10, probability × 8 + rate_bonus)`
- Runs in `ThreadPoolExecutor` — never blocks the async event loop

</td>
<td width="50%">

### Live Threat Intelligence
| Source | Type | TTL |
|--------|------|-----|
| Feodo Tracker | Botnet C2 IPs | 5 min |
| AbuseIPDB | Malicious IP blacklist | 30 min |
| Cloudflare Radar | Attack target weights | 1 hr |
| Spamhaus DROP/eDROP | Hijacked IP blocks | 1 hr |
| Emerging Threats | Compromised servers | 1 hr |
| CINS Army | Scanning/attacking hosts | 1 hr |

</td>
</tr>
</table>

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser (React 18)                           │
│                                                                     │
│  ┌──────────────────┐  WebSocket   ┌─────────────────────────────┐  │
│  │   3D Globe       │◄────────────┤   DashboardContext          │  │
│  │  (react-globe.gl)│             │   (single source of truth)  │  │
│  └──────────────────┘             └──────┬──────────────────────┘  │
│         ▲ arcs                           │ HTTP polling             │
└─────────┼───────────────────────────────┼─────────────────────────┘
          │ WS push                        │ REST (stats/briefing/incidents)
┌─────────┼───────────────────────────────┼─────────────────────────┐
│         │           FastAPI Backend      │                          │
│  ┌──────┴──────┐  ┌────────────┐  ┌────┴────────────────────────┐ │
│  │ Connection  │  │  API       │  │   Background Ingestion Loop  │ │
│  │ Manager     │  │  Routes    │  │   (every 10 seconds)         │ │
│  │ (WebSocket) │  │  /api/v1/* │  │                              │ │
│  └─────────────┘  └────────────┘  └────┬─────────────────────────┘ │
│                                        │                            │
│                          ┌─────────────▼──────────────────────────┐ │
│                          │    Processing Pipeline                  │ │
│                          │                                         │ │
│                          │  Feeds → Geo (5-tier) → ML Scoring     │ │
│                          │       → PostgreSQL → WS Broadcast       │ │
│                          │       → Agent (if severity ≥ 8.0)      │ │
│                          └─────────────────────────────────────────┘ │
│                                                                     │
│  ┌──────────────────────────┐    ┌───────────────────────────────┐  │
│  │  AI Agent                │    │  LLM Briefing                 │  │
│  │  (Groq Llama 3.3 70B)    │    │  (Groq · every 60s)           │  │
│  │  4-tool agentic loop     │───►│  enriched with agent findings │  │
│  └──────────────────────────┘    └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
               ┌──────────────▼──────────────┐
               │     PostgreSQL 15            │
               │  attack_events               │
               │  incident_reports            │
               │  ip_reputation               │
               └─────────────────────────────┘
```

### Data Flow

Every 10 seconds the ingestion loop runs:

1. **Fetch** — collect malicious IPs from Feodo Tracker, AbuseIPDB, and blocklists
2. **Enrich** — resolve each IP to lat/lon via 5-tier geo fallback (LRU cache → DB cache → ip-api.com → mock DB → country centre)
3. **Score** — RandomForest model outputs severity 0–10 in a `ThreadPoolExecutor`
4. **Store** — write `AttackEvent` to PostgreSQL; `flush()` to get the ID
5. **Broadcast** — push arc JSON over WebSocket to all connected browsers
6. **Investigate** — if `severity ≥ 8.0`, fire the AI agent as a non-blocking `asyncio.create_task()`
7. **Commit** — make the batch permanent

---

## Quick Start

### With Docker (recommended)

```bash
git clone https://github.com/yourusername/ddos-attack-visualiser.git
cd ddos-attack-visualiser

# Copy and configure environment
cp backend/.env.example backend/.env
# Add your API keys (optional — the system works without them via fallbacks)

docker-compose up --build
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3000 |
| API docs | http://localhost:8000/docs |
| Health check | http://localhost:8000/ |

> The ML model trains automatically during Docker image build. First build takes 3–5 minutes.

---

### Local Development

**Backend**

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\Activate.ps1      # Windows PowerShell

pip install -r requirements.txt

# Train the ML model (required on first run)
python ml/trainer.py

# Start the API server
uvicorn main:app --reload --port 8000
```

**Frontend**

```bash
cd frontend
npm install
npm run dev                     # http://localhost:3000
```

---

## Configuration

### `backend/.env`

```env
# Database
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/ddos_attack_map

# Ingestion
INGESTION_INTERVAL_SECONDS=10   # How often to fetch new threats
INGESTION_BATCH_SIZE=5          # Events per cycle
MIN_REAL_EVENTS_PER_BATCH=5     # Minimum live events before simulated padding is added
INVESTIGATION_THRESHOLD=8.0     # Severity score that triggers AI agent

# Threat Intelligence API Keys (all optional — graceful fallback if absent)
ABUSEIPDB_API_KEY=              # https://www.abuseipdb.com/api
CLOUDFLARE_API_TOKEN=           # https://developers.cloudflare.com/radar/
GROQ_API_KEY=                   # https://console.groq.com (for AI features)

# Debug
DEBUG=false                     # Enable SQL echo logging
```

### `frontend/.env`

```env
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

---

## Project Structure

```
ddos-attack-visualiser/
├── backend/
│   ├── api/
│   │   └── routes.py            # Globe-optimised endpoints (/api/v1/*)
│   ├── agents/
│   │   └── threat_investigator.py  # Autonomous AI agent (4-tool loop)
│   ├── ml/
│   │   ├── trainer.py           # CICIDS2017 training script
│   │   ├── predictor.py         # Inference interface
│   │   └── model.pkl            # Trained model (generated at build time)
│   ├── services/
│   │   ├── feeds.py             # Threat intelligence feed clients
│   │   ├── geo.py               # 5-tier IP geolocation with LRU cache
│   │   ├── ingest.py            # Core data pipeline
│   │   └── briefing.py         # LLM situational briefing (Groq)
│   ├── database.py              # Async SQLAlchemy 2.0 engine
│   ├── models.py                # ORM models (AttackEvent, IncidentReport)
│   ├── main.py                  # FastAPI app + background loop
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AttackGlobe.tsx      # 3D globe + arc aggregation
│   │   │   ├── CyberDashboard.tsx   # Dashboard overlay
│   │   │   ├── LiveThreatStream.tsx # Aggregated threat stream
│   │   │   ├── BriefingPanel.tsx    # LLM briefing with typewriter
│   │   │   ├── IncidentsPanel.tsx   # Agent investigation reports
│   │   │   ├── StatsPanel.tsx       # Attack Intel panel
│   │   │   └── AgentStatusWidget.tsx # Live tool-call progress
│   │   └── context/
│   │       └── DashboardContext.tsx # Single source of truth
│   ├── nginx.conf
│   └── Dockerfile
├── docker-compose.yml
└── PROJECT_REPORT.md
```

---

## API Reference

### WebSocket

```
WS /api/v1/ws/attacks
```

Streams attack arc objects as they are ingested. Sends 50 initial events on connect. Heartbeat ping every 30s.

**Message format:**
```json
{
  "type": "attack",
  "attack": {
    "id": 42,
    "srcLat": 39.9042, "srcLon": 116.4074,
    "tgtLat": 39.0438, "tgtLon": -77.4874,
    "color": "#ff8000",
    "strokeWidth": 2.5,
    "attackType": "SYN Flood",
    "severity": 7.2,
    "packetRate": 50000,
    "sourceIp": "1.234.56.78",
    "isSimulated": false
  }
}
```

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/attacks/stream?since_id=0` | Incremental attack feed (HTTP fallback) |
| `GET` | `/api/v1/attacks/stats` | Events/min, top countries, attack types, peak rate |
| `GET` | `/api/v1/briefing` | Latest LLM threat briefing (cached 60s) |
| `GET` | `/api/v1/incidents` | Agent investigation reports |
| `GET` | `/api/v1/agent/status` | Live agent tool-call status |
| `GET` | `/` | Health check + ingestion status |
| `POST` | `/ingestion/trigger?count=10` | Manually trigger ingestion |

---

## Machine Learning

The threat scoring model is a **RandomForest classifier** trained on the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) — real network traffic captures with labeled attack flows.

**Features used:**
```
Flow Duration · Total Fwd/Backward Packets · Flow Bytes/s
Flow Packets/s · Flow IAT Mean · Fwd PSH Flags · Protocol
```

**Training pipeline:**
1. Load CICIDS2017 CSVs, select 9 features, encode labels
2. 80/20 stratified train/test split
3. Apply SMOTE to training set only (prevents data leakage)
4. Fit `RandomForestClassifier(n_estimators=200, n_jobs=-1)`
5. Evaluate on held-out test set — report honest precision/recall per class
6. Save model + scaler + feature names to `model.pkl`

**Severity formula:**

```python
base_score = ml_probability * 8.0       # 0–8 from model confidence
rate_bonus = {                           # +0–2 for high packet rates
    rate > 100_000: min(2.0, (rate - 100_000) / 200_000 * 2),
    rate > 50_000:  1.0,
    rate > 20_000:  0.5,
    else:           0.0
}
severity = min(10.0, base_score + rate_bonus)
```

To retrain with CICIDS2017 data:
```bash
# Download CSVs from https://www.unb.ca/cic/datasets/ids-2017.html
# Place in backend/ml/data/
python backend/ml/trainer.py
```

---

## AI Agent — How It Works

The autonomous investigation agent uses Groq Llama 3.3 70B with a multi-tool agentic loop. It fires automatically for any event with severity ≥ 8.0.

### Tool call sequence

```
find_related_incidents()          ← always first: query own memory
        │
        ├── is_repeat_attacker?
        │         ├── YES → lookup_ip_reputation() + fetch_cve_data()
        │         └── NO  → lookup_ip_reputation() + get_attack_trend()
        │
        └── is_campaign?
                  └── YES → lookup_ip_reputation() + fetch_cve_data() + get_attack_trend()
```

The tool sequence is not hardcoded — the LLM reads `find_related_incidents` output and decides which tools to call next based on what it finds. Logs in `incident_reports.tools_called` show the actual sequence per investigation.

### Agent feeds briefing

Every 60 seconds the briefing service queries both raw attack events **and** recent agent investigation findings. The LLM receives verified metrics (peak packet rate, average severity) alongside agent-detected patterns (repeat attacker count, campaigns). The briefing is a synthesis of two intelligence sources.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **WebSocket for arcs, HTTP for aggregates** | Arcs need sub-second push latency. Stats/briefing change every 30-60 seconds — polling is simpler and appropriate. Using WebSocket for everything is over-engineering. |
| **ThreadPoolExecutor for ML** | scikit-learn is CPU-bound C code. Running it in the async event loop blocks all other requests during inference. ThreadPoolExecutor isolates it to a separate OS thread. |
| **Arc aggregation by `sourceIp\|attackType`** | Raw event count is unbounded. Aggregating by attack pattern bounds React state to unique patterns and makes visual weight (stroke thickness) meaningful — a persistent campaign looks different from a one-shot probe. |
| **5-tier geo fallback** | External APIs fail, rate limits hit, demos happen in spotty WiFi. Every tier ensures arcs always appear on the globe. |
| **Hybrid fallback engine** | If real feeds return fewer than `MIN_REAL_EVENTS_PER_BATCH` events (default `5`), simulated events pad the batch and are marked `is_simulated=true`. This keeps the stream populated without overstating how many live events were available. |
| **`asyncio.create_task()` for agent** | Awaiting the agent in the ingestion loop would pause ingestion for 5-10 seconds per high-severity event. `create_task()` schedules it concurrently — ingestion continues immediately. |
| **SMOTE on train split only** | Applying SMOTE before the train/test split would leak synthetic attack samples into the test set and inflate metrics. SMOTE applied to training data only gives honest evaluation on real held-out data. |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `FileNotFoundError: model.pkl` | ML model not trained | `python backend/ml/trainer.py` |
| No arcs on globe | Ingestion not running | `POST /ingestion/trigger?count=10` |
| All timestamps show same value | `formatTimeAgo` not recalculating | Add 1-second tick interval (see audit report) |
| `UNKNOWN` threat level in incidents | Agent returned truncated JSON | `classify_severity()` fallback needed (see audit report) |
| `429` from ip-api.com | Rate limit hit | System auto-falls back to mock geo — no action needed |
| WebSocket connected but stale arcs | Ingestion interval too long | Set `INGESTION_INTERVAL_SECONDS=5` |
| AbuseIPDB feed empty | Missing API key | Set `ABUSEIPDB_API_KEY` in `.env` |
| Agent never fires | Threshold too high | Lower `INVESTIGATION_THRESHOLD` in `.env` |
| Memory crash in WSL2 | Unbounded WSL memory | Add `.wslconfig`: `memory=4GB`, `swap=2GB` |

---

## Docker Memory Limits

For development on memory-constrained machines (WSL2):

```yaml
# docker-compose.yml — recommended limits
services:
  db:
    mem_limit: 256m
  backend:
    mem_limit: 384m
  frontend:
    mem_limit: 64m   # nginx serving static files
```

WSL2 config at `C:\Users\<you>\.wslconfig`:
```ini
[wsl2]
memory=4GB
processors=2
swap=2GB
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | React 18, TypeScript, Vite | UI framework |
| | react-globe.gl, Three.js r128 | WebGL 3D globe |
| | Tailwind CSS v4 | Cyberpunk UI theme |
| **Backend** | FastAPI, Python 3.11 | Async REST + WebSocket server |
| | SQLAlchemy 2.0, asyncpg | Async PostgreSQL ORM |
| | httpx | Async HTTP client for feed APIs |
| **ML** | scikit-learn, NumPy, imbalanced-learn | RandomForest + SMOTE |
| | joblib | Model serialisation |
| **AI** | Groq (Llama 3.3 70B) | Agent tool-calling + briefings |
| **Database** | PostgreSQL 15 | Persistent storage |
| **DevOps** | Docker Compose, Nginx | Containerisation + static serving |
| | GitHub Actions | CI pipeline (lint + build) |

---

## Acknowledgements

- **[Feodo Tracker](https://feodotracker.abuse.ch/)** — abuse.ch botnet C2 intelligence
- **[AbuseIPDB](https://www.abuseipdb.com/)** — crowd-sourced malicious IP database  
- **[CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)** — Canadian Institute for Cybersecurity network traffic dataset
- **[react-globe.gl](https://github.com/vasturiano/react-globe.gl)** — Three.js globe component
- **[Groq](https://groq.com/)** — LPU inference for Llama 3.3 70B

---

<div align="center">

Built for the **IIMA Ventures AI Summer Residency** application

</div>