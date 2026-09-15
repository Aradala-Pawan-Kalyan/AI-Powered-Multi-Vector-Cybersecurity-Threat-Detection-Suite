"""
main.py
--------
FastAPI backend for the Sentinel security suite: URL phishing detection,
malicious file detection, spam/phishing email detection, log-based
intrusion detection, and live self-monitoring of this app's own traffic.

Run:
    uvicorn main:app --reload --port 8000

Serves:
    GET  /                        -> the website (frontend/index.html)

    URL detector:
    POST   /api/scan               -> scan a single URL
    POST   /api/batch              -> scan a list of URLs
    GET    /api/history            -> past URL scans
    DELETE /api/history            -> clear URL scan history

    File detector:
    POST   /api/scan-file          -> upload + analyze a file (static heuristics only)
    GET    /api/file-history       -> past file scans
    DELETE /api/file-history       -> clear file scan history

    Email detector:
    POST   /api/scan-email         -> analyze pasted/uploaded email content
    GET    /api/email-history      -> past email scans
    DELETE /api/email-history      -> clear email scan history

    Intrusion / hacker detection:
    POST   /api/analyze-log        -> analyze an uploaded/pasted server or auth log
    GET    /api/threats            -> combined threat feed (log findings + live self-monitoring)
    DELETE /api/threats            -> clear threat feed

    Dashboard:
    GET    /api/stats               -> aggregate counts across all detectors
    GET    /api/feature-importance  -> URL model feature importances
    GET    /api/health              -> API/model status
"""

import os
import re
import time
import sqlite3
import datetime
from urllib.parse import unquote
from contextlib import closing
from collections import defaultdict, deque
from typing import List, Optional

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile, File, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from features import extract_features, explain_features
from file_analysis import analyze_file
from email_analysis import analyze_email
from log_analysis import analyze_log, ATTACK_TOOL_AGENTS, SENSITIVE_PATH_PROBES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")
DB_PATH = os.path.join(BASE_DIR, "history.db")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB cap on analyzed files

app = FastAPI(title="Sentinel Security Suite API")


# ----------------------------------------------------------------------
# Model loading
# ----------------------------------------------------------------------
if not os.path.exists(MODEL_PATH):
    raise RuntimeError(
        "model.pkl not found. Run `python train_model.py` in the backend "
        "folder first."
    )

_bundle = joblib.load(MODEL_PATH)
MODEL = _bundle["model"]
FEATURE_COLUMNS = _bundle["feature_columns"]


# ----------------------------------------------------------------------
# SQLite store
# ----------------------------------------------------------------------
def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                phishing_probability REAL NOT NULL,
                reasons TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS file_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                filename TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                reasons TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                subject TEXT NOT NULL,
                sender TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                ip TEXT,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT NOT NULL
            )
        """)
        conn.commit()


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def save_scan(url, prediction, proba, reasons):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO scans (timestamp, url, prediction, phishing_probability, reasons) "
            "VALUES (?, ?, ?, ?, ?)",
            (_now(), url, prediction, proba, "; ".join(reasons)),
        )
        conn.commit()


def save_file_scan(filename, verdict, risk_score, sha256, reasons):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO file_scans (timestamp, filename, verdict, risk_score, sha256, reasons) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), filename, verdict, risk_score, sha256, "; ".join(reasons)),
        )
        conn.commit()


def save_email_scan(subject, sender, verdict, risk_score, reasons):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO email_scans (timestamp, subject, sender, verdict, risk_score, reasons) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), subject, sender, verdict, risk_score, "; ".join(reasons)),
        )
        conn.commit()


def save_threat_event(source, ip, type_, severity, detail):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO threat_events (timestamp, source, ip, type, severity, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (_now(), source, ip, type_, severity, detail),
        )
        conn.commit()


init_db()


# ----------------------------------------------------------------------
# Live self-monitoring middleware (in-memory sliding window + persisted flags)
# ----------------------------------------------------------------------
REQUEST_WINDOW_SECONDS = 10
REQUEST_RATE_THRESHOLD = 25  # requests from one IP within the window
_recent_requests = defaultdict(lambda: deque(maxlen=200))  # ip -> timestamps
_flagged_recently = {}  # (ip, type) -> last-flagged unix time, to avoid event spam

SUSPICIOUS_QUERY_PATTERNS = [
    r"'\s*or\s*'1'\s*=\s*'1", r"union(\s+all)?\s+select", r"<script",
    r"\.\./", r"drop\s+table",
]


def _should_reflag(key, cooldown=30):
    last = _flagged_recently.get(key, 0)
    now = time.time()
    if now - last > cooldown:
        _flagged_recently[key] = now
        return True
    return False


@app.middleware("http")
async def self_monitoring_middleware(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    path = str(request.url.path)
    query = str(request.url.query)
    agent = request.headers.get("user-agent", "")

    if not path.startswith("/api/threats") and not path.startswith("/static"):
        now = time.time()
        bucket = _recent_requests[ip]
        bucket.append(now)
        recent_count = sum(1 for t in bucket if now - t <= REQUEST_WINDOW_SECONDS)

        if recent_count > REQUEST_RATE_THRESHOLD and _should_reflag((ip, "rate")):
            save_threat_event(
                "live", ip, "rate_anomaly", "medium",
                f"{recent_count} requests from {ip} within {REQUEST_WINDOW_SECONDS}s — possible scripted/bot traffic"
            )

        if any(tool in agent.lower() for tool in ATTACK_TOOL_AGENTS) and _should_reflag((ip, "agent")):
            save_threat_event(
                "live", ip, "attack_tool_agent", "high",
                f"Request to {path} used a known scanning-tool user agent ('{agent}')"
            )

        probe_target = unquote(f"{path}?{query}").lower()
        if any(p in probe_target for p in SENSITIVE_PATH_PROBES) and _should_reflag((ip, "probe")):
            save_threat_event(
                "live", ip, "sensitive_path_probe", "medium",
                f"{ip} probed a sensitive path: {path}"
            )

        if any(re.search(p, probe_target) for p in SUSPICIOUS_QUERY_PATTERNS) and _should_reflag((ip, "inject")):
            save_threat_event(
                "live", ip, "injection_attempt", "high",
                (f"{ip} sent a request with an injection-style payload: {path}?{query}")[:250]
            )

    response = await call_next(request)
    return response


# ----------------------------------------------------------------------
# Request / response schemas
# ----------------------------------------------------------------------
class ScanRequest(BaseModel):
    url: str
    threshold: float = 0.5


class BatchRequest(BaseModel):
    urls: List[str]
    threshold: float = 0.5


class EmailRequest(BaseModel):
    content: str


class LogRequest(BaseModel):
    content: str


# ----------------------------------------------------------------------
# URL scoring
# ----------------------------------------------------------------------
def score_url(url: str, threshold: float = 0.5):
    feat = extract_features(url)
    row = pd.DataFrame([feat])[FEATURE_COLUMNS]
    proba = float(MODEL.predict_proba(row)[0][1])
    label = "Phishing" if proba >= threshold else "Safe"
    reasons = explain_features(feat, url)
    return {
        "url": url,
        "prediction": label,
        "phishing_probability": round(proba, 4),
        "risk_score_pct": round(proba * 100, 1),
        "reasons": reasons,
        "features": feat,
    }


@app.post("/api/scan")
def scan_url(req: ScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL must not be empty")
    result = score_url(req.url.strip(), req.threshold)
    save_scan(result["url"], result["prediction"], result["phishing_probability"], result["reasons"])
    return result


@app.post("/api/batch")
def scan_batch(req: BatchRequest):
    if not req.urls:
        raise HTTPException(status_code=400, detail="No URLs provided")
    if len(req.urls) > 500:
        raise HTTPException(status_code=400, detail="Max 500 URLs per batch")

    results = []
    for u in req.urls:
        u = str(u).strip()
        if not u:
            continue
        result = score_url(u, req.threshold)
        save_scan(result["url"], result["prediction"], result["phishing_probability"], result["reasons"])
        results.append(result)

    n_phish = sum(1 for r in results if r["prediction"] == "Phishing")
    return {
        "total": len(results),
        "phishing_count": n_phish,
        "safe_count": len(results) - n_phish,
        "results": results,
    }


@app.get("/api/history")
def get_history(limit: int = 200):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/history")
def clear_history():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
    return {"status": "cleared"}


# ----------------------------------------------------------------------
# File detector
# ----------------------------------------------------------------------
@app.post("/api/scan-file")
async def scan_file(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="File too large (25 MB max for this demo)")
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")

    result = analyze_file(data, file.filename or "unknown")
    save_file_scan(result["filename"], result["verdict"], result["risk_score"], result["sha256"], result["reasons"])

    if result["verdict"] != "Likely Safe":
        deep_kind = result.get("deep_analysis", {}).get("kind")
        extra = f" (deep scan: {deep_kind})" if deep_kind else ""
        save_threat_event(
            "file", None, "malicious_file_upload",
            "critical" if result["verdict"] == "Malicious" else "medium",
            f"Uploaded file '{result['filename']}' flagged as {result['verdict']} (score {result['risk_score']}){extra}"
        )
    return result


@app.get("/api/file-history")
def file_history(limit: int = 200):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM file_scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/file-history")
def clear_file_history():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM file_scans")
        conn.commit()
    return {"status": "cleared"}


# ----------------------------------------------------------------------
# Email detector
# ----------------------------------------------------------------------
@app.post("/api/scan-email")
def scan_email(req: EmailRequest):
    if not req.content or not req.content.strip():
        raise HTTPException(status_code=400, detail="Email content must not be empty")
    result = analyze_email(req.content)
    save_email_scan(result["subject"], result["from"], result["verdict"], result["risk_score"], result["reasons"])

    if result["verdict"] != "Likely Legitimate":
        save_threat_event(
            "email", None, "phishing_email",
            "critical" if result["verdict"] == "Phishing / Spam" else "medium",
            f"Email '{result['subject'][:80]}' from {result['from']} flagged as {result['verdict']}"
        )
    return result


@app.get("/api/email-history")
def email_history(limit: int = 200):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM email_scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/email-history")
def clear_email_history():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM email_scans")
        conn.commit()
    return {"status": "cleared"}


# ----------------------------------------------------------------------
# Log-based intrusion detection
# ----------------------------------------------------------------------
@app.post("/api/analyze-log")
async def analyze_log_endpoint(content: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    text = None
    if file is not None:
        raw = await file.read()
        text = raw.decode("utf-8", errors="ignore")
    elif content:
        text = content

    if not text or not text.strip():
        raise HTTPException(status_code=400, detail="No log content provided")

    result = analyze_log(text)
    for e in result["events"][:100]:
        save_threat_event("log_upload", e["ip"], e["type"], e["severity"], e["detail"])
    return result


@app.get("/api/threats")
def get_threats(limit: int = 300):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM threat_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    rows = [dict(r) for r in rows]
    by_severity = defaultdict(int)
    for r in rows:
        by_severity[r["severity"]] += 1
    return {"events": rows, "by_severity": dict(by_severity)}


@app.delete("/api/threats")
def clear_threats():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM threat_events")
        conn.commit()
    return {"status": "cleared"}


# ----------------------------------------------------------------------
# Dashboard / meta
# ----------------------------------------------------------------------
@app.get("/api/stats")
def get_stats():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        total_urls = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
        phishing_urls = conn.execute("SELECT COUNT(*) c FROM scans WHERE prediction='Phishing'").fetchone()["c"]
        recent = conn.execute("SELECT timestamp, prediction FROM scans ORDER BY id DESC LIMIT 30").fetchall()

        total_files = conn.execute("SELECT COUNT(*) c FROM file_scans").fetchone()["c"]
        bad_files = conn.execute("SELECT COUNT(*) c FROM file_scans WHERE verdict!='Likely Safe'").fetchone()["c"]

        total_emails = conn.execute("SELECT COUNT(*) c FROM email_scans").fetchone()["c"]
        bad_emails = conn.execute("SELECT COUNT(*) c FROM email_scans WHERE verdict!='Likely Legitimate'").fetchone()["c"]

        total_threats = conn.execute("SELECT COUNT(*) c FROM threat_events").fetchone()["c"]
        critical_threats = conn.execute("SELECT COUNT(*) c FROM threat_events WHERE severity='critical'").fetchone()["c"]

    return {
        "total_scans": total_urls,
        "phishing_count": phishing_urls,
        "safe_count": total_urls - phishing_urls,
        "recent": [dict(r) for r in recent],
        "total_files": total_files,
        "flagged_files": bad_files,
        "total_emails": total_emails,
        "flagged_emails": bad_emails,
        "total_threats": total_threats,
        "critical_threats": critical_threats,
    }


@app.get("/api/feature-importance")
def feature_importance():
    pairs = sorted(
        zip(FEATURE_COLUMNS, MODEL.feature_importances_.tolist()),
        key=lambda x: x[1], reverse=True,
    )
    return [{"feature": name, "importance": round(val, 5)} for name, val in pairs[:15]]


@app.get("/api/health")
def health():
    return {"status": "ok", "model_features": len(FEATURE_COLUMNS)}


# ----------------------------------------------------------------------
# Serve the frontend (static website) at "/"
# ----------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def serve_index():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
