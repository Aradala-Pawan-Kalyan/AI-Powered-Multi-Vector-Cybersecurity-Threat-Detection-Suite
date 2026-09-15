# Sentinel — AI Threat Detection Suite (Full-Stack Web App)

A real website (HTML/CSS/JS) backed by a FastAPI REST API — a full
security suite that goes beyond URL scanning to also cover malicious
files, phishing/spam emails, and intrusion (hacker) detection from
server logs, plus a live self-monitoring feed of this app's own traffic.

## Project structure

```
phishing_web/
├── backend/
│   ├── main.py              # FastAPI app: all API routes + serves the frontend + live self-monitoring
│   ├── features.py          # 40-feature URL analysis engine
│   ├── file_analysis.py     # Static file/malware heuristics (documents + executables)
│   ├── deep_file_analysis.py # Format-specific deep scans (PDF JS, image stego, APK permissions)
│   ├── email_analysis.py    # Spam/phishing email analysis
│   ├── log_analysis.py      # Server/auth log intrusion detection (IDS-lite)
│   ├── generate_dataset.py  # Synthetic labeled URL dataset generator
│   ├── train_model.py       # Trains RandomForestClassifier -> model.pkl
│   ├── dataset.csv          # 4,000 labeled URLs (already generated)
│   ├── model.pkl            # Trained model (already trained)
│   ├── requirements.txt
│   └── history.db           # SQLite: all scan history + threat feed (created on first run)
└── frontend/
    ├── index.html           # The website (8 views: URL/Batch/Files/Email/Threats/Dashboard/History/Model)
    ├── style.css             # Dark "security terminal" visual design
    └── app.js                # Talks to the backend via fetch()
```

## The four detectors

1. **URL phishing detector** — 40 lexical/structural/brand-similarity
   features → RandomForest model → Safe/Phishing + risk score.
2. **File threat scanner** — upload any document or executable.
   Static-only analysis (nothing is ever opened or run): checks the
   file's real byte signature against its claimed extension (catches
   an `.exe` disguised as `invoice.pdf`), RTLO filename tricks, double
   extensions, embedded Office macros, zip-bomb compression ratios,
   packed/high-entropy payloads, and known malicious API/command
   strings (e.g. `CreateRemoteThread`, `powershell -enc`). Plus
   **format-specific deep scans**:
   - **PDFs** — embedded JavaScript, auto-run (`/OpenAction`/`/AA`) and
     `/Launch` actions, embedded file attachments, encryption, and
     listed link targets.
   - **Images (PNG/JPEG)** — data appended after the image's official
     end marker (a common simple steganography trick), plus an LSB
     (least-significant-bit) randomness check as a secondary signal.
   - **Android APKs** — permissions extracted from the binary
     `AndroidManifest.xml`, with special attention to dangerous
     combinations associated with banking trojans/spyware (SMS
     interception + Accessibility Service + overlay windows, etc.)
3. **Email phishing/spam detector** — paste a raw email (headers +
   body, e.g. from "view source" or a `.eml` file). Flags
   From/Reply-To domain mismatches, brand-impersonation display names,
   urgency/social-engineering language, risky attachment types, and
   scores every embedded link using the same URL heuristics.
4. **Intrusion / "hacker" detection** — two modes:
   - **Log analysis**: upload an Apache/Nginx access log or Linux
     `auth.log` and it flags SSH brute-force attempts, SQL injection,
     XSS, path traversal, known attack-tool user agents (sqlmap, nikto,
     nmap...), and reconnaissance-style scanning.
   - **Live self-monitoring**: middleware watches every request hitting
     *this app itself* and flags rate anomalies (bot/scripted traffic),
     scanning-tool user agents, sensitive-path probes (`/.env`,
     `/wp-login.php`, etc.), and injection-style query strings — in
     real time, no log upload needed. Great for a live demo: open the
     Threats tab, then hit the site a bunch of times from another
     terminal/curl and watch events appear.

All four detectors share one unified **Threats** feed and one
**Dashboard** with aggregate stats across everything.

## What's new vs. the Streamlit version

**Real website, not a Python widget framework** — plain HTML/CSS/JS
frontend served by FastAPI, with client-side tab navigation, an
animated radial risk gauge, and Chart.js dashboards. You can restyle,
white-label, or embed this in any existing site.

**A proper REST API** (not just a script) — `POST /api/scan`,
`POST /api/batch`, `GET /api/history`, `GET /api/stats`,
`GET /api/feature-importance` — so you can also call the detector from
a browser extension, a Slack bot, curl, Postman, or another app.

**Nearly double the detection features (20 → 40)**, including:
- **Typosquatting distance** — Levenshtein edit-distance from the
  domain to 20+ commonly-spoofed brand domains (`paypa1.com`,
  `micros0ft-support.net`, etc.)
- **Punycode / homoglyph detection** — flags `xn--` encoded domains and
  Cyrillic look-alike characters used to impersonate Latin brand names
- **Redirect-parameter detection** — `?redirect=`, `?url=`, `?next=`
  style open-redirect patterns
- **Malware-style file extensions** — links straight to `.exe`, `.scr`,
  `.apk`, etc.
- **Percent-encoding / decode mismatch** — catches URLs whose real
  destination is hidden via `%`-encoding
- **Case-switch anomaly detection**, **HTTPS+IP conflict detection**,
  and more (see `features.py` for the full list, or the Model tab in
  the app)

**Persistent history** — SQLite-backed instead of in-memory session
state, so history survives a restart and can back a real dashboard.

**Live dashboard** — total scans, phishing rate, safe/phishing
breakdown, and a recent-activity timeline, all backed by real queries
against the history table.

## Run it locally

```bash
cd backend
pip install -r requirements.txt

# model.pkl and dataset.csv are already included and trained, but you
# can regenerate/retrain any time:
python train_model.py

# start the server (serves both the API and the website)
uvicorn main:app --reload --port 8000
```

Open **http://localhost:8000** in your browser — that's the whole
website. No separate frontend server needed; FastAPI serves the static
files directly.

## API reference (for integrating elsewhere)

| Method | Path                       | Body / Form                          | Returns                                  |
|--------|----------------------------|----------------------------------------|--------------------------------------------|
| POST   | `/api/scan`                | `{"url", "threshold"}`                | URL prediction, risk score, reasons        |
| POST   | `/api/batch`                | `{"urls": [...], "threshold"}`        | per-URL results + counts                   |
| GET    | `/api/history`              | —                                       | recent URL scans                           |
| DELETE | `/api/history`              | —                                       | clears URL history                         |
| POST   | `/api/scan-file`            | multipart `file`                        | verdict, risk score, reasons, SHA-256       |
| GET    | `/api/file-history`         | —                                       | recent file scans                          |
| DELETE | `/api/file-history`         | —                                       | clears file history                        |
| POST   | `/api/scan-email`           | `{"content": "raw email text"}`       | verdict, risk score, reasons, links found  |
| GET    | `/api/email-history`        | —                                       | recent email scans                         |
| DELETE | `/api/email-history`        | —                                       | clears email history                       |
| POST   | `/api/analyze-log`          | form `content` or file upload           | flagged intrusion events, summary          |
| GET    | `/api/threats`              | —                                       | unified threat feed (logs + live traffic)  |
| DELETE | `/api/threats`              | —                                       | clears threat feed                         |
| GET    | `/api/stats`                | —                                       | totals across all 4 detectors for dashboard|
| GET    | `/api/feature-importance`   | —                                       | top URL-model features and weights          |
| GET    | `/api/health`                | —                                       | API + model status                         |

Interactive API docs are auto-generated by FastAPI at
**http://localhost:8000/docs**.

## About the training data

Same approach as before: `generate_dataset.py` builds a synthetic,
rule-generated dataset (2,000 legit + 2,000 phishing-style URLs) so the
project is reproducible offline. It now also generates typosquat,
punycode, redirect-parameter, and malware-extension examples so the
new features have real signal to learn from.

**For production**, swap in real labeled data — e.g.
[PhishTank](https://phishtank.org) / [OpenPhish](https://openphish.com)
for phishing URLs and the [Tranco](https://tranco-list.eu) list for
legitimate ones — then re-run `train_model.py` against your new
`dataset.csv` (must have `url,label` columns). No other code changes
needed.

## Deploying

### Render / Railway / Fly.io (single container)
1. Push this repo to GitHub.
2. Build command: `pip install -r backend/requirements.txt`
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT --app-dir backend`
4. Make sure `backend/model.pkl` and `backend/dataset.csv` are committed
   (or add a pre-start step that runs `python train_model.py`).

### AWS (EC2 / App Runner) or Azure App Service
```bash
pip install -r backend/requirements.txt
cd backend
python train_model.py     # only needed if model.pkl isn't committed
uvicorn main:app --host 0.0.0.0 --port 80
```
Put it behind an ALB/Nginx with HTTPS termination for a public deployment.

### Docker (optional, works anywhere)
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ backend/
COPY frontend/ frontend/
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Tech stack

- **Backend / AI:** Python, FastAPI, scikit-learn (RandomForestClassifier), pandas, SQLite
- **Frontend:** vanilla HTML/CSS/JS, Chart.js (via CDN)
- **Cybersecurity logic:** 40 hand-engineered lexical/structural/brand-similarity features
- **Deployment targets:** Render, Railway, Fly.io, AWS, Azure, Docker

## Disclaimer

Educational/demo project.

- The **URL classifier** uses lexical features only (no live
  WHOIS/domain-age or SSL-certificate checks) and is trained on
  synthetic data.
- The **file scanner** performs static heuristic analysis only —
  it never opens, runs, or executes an uploaded file, and it does
  **not** do real malware signature matching or sandboxed dynamic
  analysis. An honestly-named `.exe` with no obfuscation tricks will
  score low; this is a triage/education tool, not a replacement for a
  real antivirus/EDR product.
- The **email analyzer** works on the text you paste and doesn't
  verify SPF/DKIM/DMARC against live DNS.
- The **log analyzer** and **live self-monitoring** use pattern-based
  heuristics and can both miss novel attacks and occasionally flag
  benign traffic (false positives) — tune the thresholds in
  `main.py`/`log_analysis.py` for your environment.

Don't rely on any of this as a sole line of defense in a production
security stack.
