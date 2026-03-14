# 🛡️ ThreatLens – AI Network Threat Detection Platform

> Full-stack Python network security platform with Deep Packet Inspection (DPI), XGBoost ML classification, real-time web dashboard, firewall rule management, adware blocking, and PDF/CSV reporting.

**Evolved from:** [DPI Engine (C++)](https://github.com/devansh934/DPI-Engine-Deep-Packet-Inspection-System) by Devansh Patel

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔐 **Login Authentication** | Session-based login with configurable credentials |
| 🔍 **Deep Packet Inspection** | Parse Ethernet/IP/TCP/UDP/TLS/HTTP layers using Scapy |
| 🏷️ **SNI Extraction** | Extract domain names from TLS ClientHello (even HTTPS!) |
| 🤖 **XGBoost ML (F1=0.99)** | Classifies flows: PORT_SCAN, DOS, MALWARE_C2, ADWARE, TOR, P2P |
| 📊 **Live Dashboard** | Real-time web UI with ApexCharts and WebSocket |
| 🚨 **Smart Alerts** | DOS/PortScan with cooldown timers to prevent spam |
| 🚫 **Adware Blocking** | Block EasyList domains, trackers, malicious IPs |
| 📁 **CSV / PDF Export** | Download traffic logs and security reports |
| 🐳 **Docker Ready** | Multi-stage build, health checks, resource limits |
| 🧪 **24 Tests** | pytest test suite for all components |

---

## 🔑 Default Login Credentials

| Field | Value |
|-------|-------|
| **Username** | `admin` |
| **Password** | `threatlens123` |

> ⚠️ **Change these for production!** Set `ADMIN_USER` and `ADMIN_PASS` environment variables or update `.env` file.

---

## ⚡ Quick Start (Local – Windows/Linux/Mac)

### Step 1: Clone & Setup

```bash
# Clone the project
git clone https://github.com/YOUR_USERNAME/threatlens_project.git
cd threatlens_project

# Create virtual environment
python -m venv .venv

# Activate – Windows:
.venv\Scripts\activate

# Activate – Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure (Optional)

```bash
# Copy environment template
cp .env.example .env

# Edit .env to customize (credentials, port, etc.)
```

### Step 3: Train ML Model (First Time Only)

```bash
# Download datasets + train XGBoost model
python scripts/train_model.py
```

This downloads NSL-KDD, CTU-13, and generates synthetic data, then trains the XGBoost model (takes ~2-3 minutes).

### Step 4: Run

```bash
# Demo mode (synthetic traffic – no root required)
python run.py

# Custom port
python run.py --port 8080
```

### Step 5: Open Browser

```
http://127.0.0.1:8000
```

Login with: `admin` / `threatlens123`

---

## 🐳 Docker Deployment

### Quick Docker Start

```bash
# Build and run (background)
docker-compose up --build -d

# View logs
docker logs -f threatlens

# Stop
docker-compose down
```

### Docker with Custom Config

```bash
# Create .env from template
cp .env.example .env

# Edit credentials and settings
nano .env

# Start
docker-compose up --build -d
```

### Docker with Live Capture

```bash
# Linux: capture on eth0
CAPTURE_INTERFACE=eth0 docker-compose up

# Analyse a PCAP file
PCAP_FILE=./my_capture.pcap docker-compose up
```

---

## ☁️ Cloud Deployment

### Deploy to a VPS (DigitalOcean, AWS EC2, Azure VM)

```bash
# 1. SSH into your server
ssh user@your-server-ip

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# 3. Clone project
git clone https://github.com/YOUR_USERNAME/threatlens_project.git
cd threatlens_project

# 4. Configure
cp .env.example .env
nano .env    # Change ADMIN_PASS, set CORS_ORIGINS, etc.

# 5. Deploy
docker-compose up --build -d

# 6. Access
# http://your-server-ip:8000
```

### Deploy to Railway / Render / Fly.io

1. Push to GitHub
2. Connect the repo to your platform
3. Set environment variables:
   - `ADMIN_USER` = your username
   - `ADMIN_PASS` = your secure password
   - `PORT` = 8000
   - `HOST` = 0.0.0.0
4. Deploy – the Dockerfile handles the rest

### Deploy with Nginx Reverse Proxy (HTTPS)

```nginx
server {
    listen 443 ssl;
    server_name threatlens.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/threatlens.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/threatlens.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 🏗️ Project Structure

```
threatlens_project/
│
├── threatlens/
│   ├── engine/                      # Core DPI engine
│   │   ├── models.py                # Dataclasses: ParsedPacket, Flow, Alert
│   │   ├── sni_extractor.py         # TLS ClientHello SNI parser
│   │   ├── packet_parser.py         # Scapy-based layer extraction
│   │   ├── flow_tracker.py          # 5-tuple session tracking
│   │   ├── rule_manager.py          # IP/domain/app blocking rules
│   │   └── dpi_engine.py            # Main orchestrator + threat detection
│   │
│   ├── ml/
│   │   ├── classifier.py            # MLClassifier with XGBoost
│   │   ├── auto_train.py            # Background retraining scheduler
│   │   └── models/                  # xgb_model.pkl, scaler.pkl, model_meta.json
│   │
│   ├── api/
│   │   └── main.py                  # FastAPI: auth, REST, WebSocket, pages
│   │
│   └── frontend/
│       ├── templates/               # Jinja2: login, dashboard, alerts, etc.
│       └── static/                  # CSS + JS
│
├── scripts/
│   ├── train_model.py               # XGBoost + SMOTE + 5-fold CV
│   └── download_datasets.py         # NSL-KDD + CTU-13 downloader
│
├── tests/
│   └── test_threatlens.py           # 24 pytest tests
│
├── data/                            # Downloaded datasets
├── run.py                           # CLI entry point
├── requirements.txt                 # Pinned dependencies
├── Dockerfile                       # Multi-stage, non-root
├── docker-compose.yml               # Health check, resource limits
├── .env.example                     # Config template
└── README.md
```

---

## 🖥️ Dashboard Pages

| URL | Page | Description |
|-----|------|-------------|
| `/login` | **Login** | Authentication page |
| `/` | **Dashboard** | KPIs, live chart, app donut, threat feed |
| `/traffic` | **Live Traffic** | Real-time packet table |
| `/alerts` | **Alerts** | Alert history with severity filters |
| `/rules` | **Firewall Rules** | Add/remove/toggle blocking rules |
| `/reports` | **Reports** | Summary + PDF/CSV export |
| `/ml-training` | **ML Training** | Model training dashboard |
| `/logout` | **Logout** | End session |

---

## 🌐 REST API

All API endpoints require authentication (session cookie).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check (no auth required) |
| `GET` | `/api/stats` | Engine statistics |
| `GET` | `/api/packets?limit=100` | Recent packets |
| `GET` | `/api/alerts?limit=50` | Recent alerts |
| `GET` | `/api/flows` | Active flows |
| `GET` | `/api/rules` | Blocking rules |
| `POST` | `/api/rules?rule_type=DOMAIN&value=evil.com` | Add rule |
| `DELETE` | `/api/rules/{id}` | Remove rule |
| `PATCH` | `/api/rules/{id}/toggle` | Toggle rule |
| `GET` | `/api/reports/csv` | Download CSV |
| `GET` | `/api/reports/pdf` | Download PDF |
| `WS` | `/ws/live` | WebSocket: real-time events |

---

## 🤖 Machine Learning

### XGBoost Model (v2.0)

| Metric | Value |
|--------|-------|
| **Algorithm** | XGBoost (300 estimators) |
| **Validation F1** | 0.9907 (99%) |
| **Training Data** | 197,962 samples |
| **Class Balance** | SMOTE (→ 679K balanced) |
| **Cross-Validation** | 5-fold stratified (F1 = 0.9902 ± 0.0003) |

### 11 Features Per Flow

```
avg_pkt_size, pkt_count, flow_duration_sec, bytes_per_sec,
dst_port, protocol_tcp, protocol_udp, has_sni,
inter_arrival_mean, inter_arrival_std, pkt_size_std
```

### 7 Threat Labels

| Label | Description |
|-------|-------------|
| `NORMAL` | Benign traffic |
| `PORT_SCAN` | Sequential port probing |
| `DOS_ATTACK` | High-volume packet flood |
| `MALWARE_C2` | Periodic beaconing (C2) |
| `ADWARE` | Ad network traffic |
| `TOR_TRAFFIC` | Tor relay patterns |
| `P2P_TRAFFIC` | BitTorrent / peer-to-peer |

### Retrain the Model

```bash
# Full pipeline: download datasets + train
python scripts/train_model.py

# Use your own dataset
python scripts/train_model.py --data /path/to/dataset.csv
```

---

## 🚨 Alert System

| Alert | Trigger | Cooldown | Severity |
|-------|---------|----------|----------|
| `DOS_ATTACK` | > 500 pkt/s from single IP | **60s per IP** | CRITICAL |
| `PORT_SCAN` | > 20 unique ports in 10s | **30s per IP** | HIGH |
| `MALWARE_C2` | ML confidence > 75% | – | HIGH |
| `ADWARE` | Matched adware domain | – | MEDIUM |

> DOS and Port Scan alerts have **per-IP cooldown timers** to prevent alert spam.

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USER` | `admin` | Login username |
| `ADMIN_PASS` | `threatlens123` | Login password |
| `HOST` | `0.0.0.0` | Bind host |
| `PORT` | `8000` | Bind port |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `LOG_LEVEL` | `INFO` | Logging level |
| `CAPTURE_INTERFACE` | – | Network interface for live capture |
| `PCAP_FILE` | – | PCAP file to analyse |
| `WORKERS` | `1` | Uvicorn worker count |

### CLI Flags

```bash
python run.py --help
python run.py --port 8080
python run.py --interface "Wi-Fi"       # Windows (run as Admin)
python run.py --interface eth0          # Linux (use sudo)
python run.py --pcap ./capture.pcap
python run.py --list-interfaces
```

---

## 🧪 Running Tests

```bash
# Run all 24 tests
pytest tests/ -v

# Run specific test
pytest tests/test_threatlens.py::test_sni_extraction_youtube -v
```

---

## 📋 Requirements

- **Python** 3.10+
- **pip** packages: see `requirements.txt`
- **Root/admin** only for live packet capture
- **Docker** (optional): for containerised deployment

---

## ⚠️ Legal & Ethical Notice

ThreatLens is for **defensive** network monitoring of networks you own or are authorised to monitor.

- Do NOT use on networks without authorisation
- Captured metadata is stored locally only
- Change default credentials before production deployment

---

## 👨‍💻 Credits

**Original C++ DPI Engine:** Devansh Patel – [@devansh934](https://github.com/devansh934)

**ThreatLens Platform:** Built with FastAPI, Scapy, XGBoost, scikit-learn, and an Upzet-inspired dashboard.
