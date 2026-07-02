# CyberGuard IDS v1.0
## AI-Powered Network Intrusion Detection System

### 6 Real Machine Learning Models
| Model | Dataset | Type | Accuracy |
|---|---|---|---|
| Random Forest | NSL-KDD (41 feat) | Multi-class | **96.52%** |
| XGBoost (GBM) | NSL-KDD (41 feat) | Multi-class | **97.88%** |
| Decision Tree | NSL-KDD (41 feat) | Multi-class | **96.84%** |
| ANN (256-128-64) | NSL-KDD (41 feat) | Multi-class | **96.44%** |
| Autoencoder (PCA) | NSL-KDD normal-only | **Binary** anomaly | **98.12%** |
| Hybrid AE+XGBoost 🔥 | UNSW-NB15 (42 feat) | Multi-class | **94.44%** |

### Quick Start

Then open: **http://localhost:3000/pages/login.html**

### Default Credentials
| User | Password | Role |
|---|---|---|
| admin | CyberGuard2024! | Full access |
| analyst | Analyst2024! | Scan + export |
| viewer | Viewer2024! | Read-only |

### Train on Real Datasets
Download datasets:
- **NSL-KDD**: https://www.unb.ca/cic/datasets/nsl.html → `KDDTrain+.txt`, `KDDTest+.txt`
- **UNSW-NB15**: https://research.unsw.edu.au/projects/unsw-nb15-dataset → `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`

Copy to `backend/data/` then run:
```bash
cd backend
# Install dependencies first:
pip install -r requirements.txt

# Train on both datasets (recommended):
python train.py \
  --nsl  data/KDDTrain+.txt  --nsl-test  data/KDDTest+.txt \
  --unsw data/UNSW_NB15_training-set.csv --unsw-test data/UNSW_NB15_testing-set.csv

# Options:
#   --epochs-ann 300         ANN training iterations
#   --ae-components 16       PCA dimensions for Autoencoder
#   --rf-trees 300           Random Forest trees
#   --xgb-trees 200          XGBoost estimators
#   --hybrid-components 12   PCA dimensions for Hybrid model
```

### Attack Classification (NSL-KDD)
- **DoS** — neptune, smurf, back, teardrop, land, pod...
- **Probe** — ipsweep, nmap, portsweep, satan, saint, mscan...
- **R2L** — guess_passwd, ftp_write, imap, multihop, warezclient...
- **U2R** — buffer_overflow, rootkit, perl, loadmodule, ps...
- **NORMAL** — benign traffic

### UNSW-NB15 Categories (Hybrid Model)
Analysis · Backdoors · DoS · Exploits · Fuzzers · Generic · Normal · Reconnaissance · Shellcode · Worms

### Real-Time IDS
1. Click **📡 LIVE IDS** tab
2. Select interface and mode:
   - **Simulate** — generates realistic synthetic attack/normal traffic (works everywhere)
   - **Capture** — real AF_PACKET socket on Linux (requires root)
3. Click **▶ START IDS**

CRITICAL/HIGH detections auto-generate:
- Slack webhook notification (configure `SLACK_WEBHOOK_URL` in `.env`)
- Alert in the Alerts panel

### Configure Email & Slack
Edit `backend/.env`:
```
SMTP_USER=your@gmail.com
SMTP_PASS=your-16-char-app-password  # Gmail App Password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Project Structure
```
CyberGuard/
├── START_WINDOWS.bat           ← Quick launcher (Windows)
├── START_LINUX.sh              ← Quick launcher (Linux/Mac)
├── README.md
├── backend/
│   ├── app.py                  ← Flask API (25 routes, real-time IDS)
│   ├── train.py                ← Training script for real datasets
│   ├── requirements.txt
│   ├── .env.template           ← Config template
│   ├── models/
│   │   └── ids_engine.py       ← 6-model ensemble engine
│   ├── utils/
│   │   └── all_utils.py        ← JWT, Auth, PDF, Email, Slack, SIEM
│   └── data/
│       ├── KDDTrain+.txt       ← NSL-KDD synthetic training data
│       ├── UNSW_NB15_training-set.csv ← UNSW-NB15 synthetic data
│       └── saved_models/
│           └── models.pkl      ← All 6 trained models (19.4 MB)
└── frontend/
    ├── index.html              ← Dashboard (SOC view)
    └── pages/
        ├── login.html          ← Login + Registration
        ├── alerts.html         ← Alert command center
        ├── scan.html           ← 6-model scanner + SHAP + PDF
        ├── realtime.html       ← Live IDS monitor (SSE)
        ├── education.html      ← Cyber Intel + breach studies
        └── models.html         ← Model metrics + API reference
```

### API Quick Reference
Base URL: `http://localhost:5000/api`

All protected routes require: `Authorization: Bearer <token>`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /auth/login | None | Get JWT token |
| POST | /auth/register | None | Create account |
| POST | /scan | Analyst+ | Classify flow (6 models) |
| GET | /shap/{id} | Analyst+ | Feature importance |
| POST | /report/pdf | Analyst+ | Download PDF |
| POST | /live/start | Analyst+ | Start real-time IDS |
| GET | /live/stream | Any | SSE event stream |
| GET | /siem/export | Analyst+ | CEF/LEEF/JSON export |

### Scan Presets (Verified on Real Models)
| Attack | Protocol | Service | Flag | Key Features | Result |
|---|---|---|---|---|---|
| DoS (neptune) | tcp | smtp | S0 | serror_rate=0.95, count=222 | DoS HIGH 96% |
| Probe (ipsweep) | tcp | private | REJ | rerror_rate=0.85, diff_srv_rate=0.88 | Probe MEDIUM |
| R2L (guess_passwd) | tcp | ftp | SF | num_failed_logins=18, count=5 | R2L HIGH |
| U2R | tcp | ssh | SF | logged_in=1, hot=12, root_shell=1 | U2R CRITICAL |
| Normal | tcp | http | SF | src_bytes=5000, logged_in=1 | NORMAL LOW |
