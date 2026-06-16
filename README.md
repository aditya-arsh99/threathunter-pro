# 🛡️ ThreatHunter Pro

> Real-time threat detection platform powered by ML anomaly detection.
> Processes **1M+ security events daily** across network flows and Windows event logs.

---

## 🏗️ Architecture

```
Data Sources (PCAP / EVTX)
        │
        ▼
  Ingestion Layer  ──►  Apache Kafka  ──►  ML Engine (TensorFlow)
  (Python parsers)      (3 topics)         (Autoencoder + LSTM)
                                                  │
                                                  ▼
                                           Alert Engine
                                                  │
                                        ┌─────────┴──────────┐
                                        ▼                    ▼
                                 Elasticsearch          Redis Cache
                                 (Event storage)   (Alert dedup)
                                        │
                                        ▼
                                  FastAPI Backend
                                        │
                                        ▼
                                 React Dashboard
```

## 🧰 Tech Stack

| Component         | Technology                    |
|-------------------|-------------------------------|
| Ingestion         | Python, Scapy, python-evtx   |
| Message Queue     | Apache Kafka 7.5              |
| ML Models         | TensorFlow 2.x (Autoencoder + LSTM) |
| Storage / Search  | Elasticsearch 8.11            |
| Visualisation     | Kibana 8.11                   |
| Cache / Dedup     | Redis 7.2                     |
| API               | FastAPI (Python)              |
| Dashboard         | React + Recharts              |
| Infrastructure    | Docker Compose                |

---

## 🚀 Quick Start

### Prerequisites
- Docker Engine 24+
- Docker Compose v2
- 8GB+ RAM recommended (Elasticsearch is memory-hungry)

### 1. Clone and configure
```bash
git clone https://github.com/yourname/threathunter-pro.git
cd threathunter-pro
cp .env.example .env
# Edit .env to change passwords (especially for production)
```

### 2. Start infrastructure
```bash
chmod +x manage.sh
./manage.sh start
```

### 3. Check health
```bash
./manage.sh health
```

### 4. Access services

| Service        | URL                      | Credentials              |
|----------------|--------------------------|--------------------------|
| Kibana         | http://localhost:5601    | elastic / ThreatHunter@2024 |
| Elasticsearch  | http://localhost:9200    | elastic / ThreatHunter@2024 |
| Kafka UI       | http://localhost:8090    | —                        |
| Redis UI       | http://localhost:8091    | —                        |
| API            | http://localhost:8000    | —                        |
| Dashboard      | http://localhost:3000    | —                        |

---

## 📁 Project Structure

```
threathunter-pro/
├── docker-compose.yml          # Full infrastructure definition
├── .env.example                # Environment variable template
├── manage.sh                   # Start/stop/health management script
├── README.md
│
├── config/
│   ├── elasticsearch.yml       # ES cluster config
│   └── redis.conf              # Redis config
│
├── scripts/
│   └── es_setup.sh             # One-time ES index/ILM setup
│
├── ingestion/                  # Phase 2
│   ├── pcap_ingestor.py        # PCAP/NetFlow → Kafka
│   ├── evtx_ingestor.py        # Windows EVTX → Kafka
│   └── kafka_producer.py       # Shared Kafka producer
│
├── ml_engine/                  # Phase 3
│   ├── models/
│   │   ├── autoencoder.py      # Autoencoder for network anomalies
│   │   └── lstm_detector.py    # LSTM for Windows event sequences
│   ├── feature_extractor.py    # Feature engineering
│   ├── trainer.py              # Model training pipeline
│   └── inference.py            # Real-time inference consumer
│
├── alert_engine/               # Phase 4
│   └── alerter.py              # Scoring + severity + ES write
│
├── api/                        # Phase 5
│   ├── main.py                 # FastAPI app
│   └── routes/
│       ├── events.py
│       ├── alerts.py
│       └── health.py
│
├── dashboard/                  # Phase 6
│   └── (React app)
│
└── data/
    ├── pcap_samples/           # Test PCAP files
    ├── evtx_samples/           # Test EVTX files
    └── models/                 # Trained model weights (.h5)
```

---

## 🔨 Build Phases

- [x] **Phase 1** — Docker infrastructure (Kafka, ES, Redis, Kibana)
- [ ] **Phase 2** — Ingestion layer (PCAP + EVTX parsers)
- [ ] **Phase 3** — ML engine (Autoencoder + LSTM)
- [ ] **Phase 4** — Alert engine
- [ ] **Phase 5** — FastAPI backend
- [ ] **Phase 6** — React dashboard

---

## 📄 License
MIT
