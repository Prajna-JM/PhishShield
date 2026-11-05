from pathlib import Path
from datetime import datetime, timezone
import sqlite3
import joblib

from flask import Flask, request, jsonify
from flask_cors import CORS

from security import extract_urls, analyze_url, text_warnings
from explain import explain_prediction

BASE = Path(__file__).resolve().parent
MODEL_PATH = BASE / "models" / "text_model.joblib"
DB_PATH = BASE / "database" / "phishshield.sqlite3"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB request limit
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173"]}})

if not MODEL_PATH.exists():
    raise RuntimeError("Model missing. Run: python train_model.py")
model = joblib.load(MODEL_PATH)

def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_preview TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                category TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

def detect_category(text):
    t = text.lower()
    patterns = {
        "Banking / KYC": ["bank", "kyc", "account blocked", "account suspended"],
        "UPI / Payment": ["upi", "payment", "transaction", "refund", "pin"],
        "Job / Recruitment": ["job offer", "registration fee", "recruitment", "interview fee"],
        "Delivery / Parcel": ["parcel", "delivery", "shipment", "package"],
        "Prize / Lottery": ["winner", "prize", "lottery", "reward"]
    }
    for category, terms in patterns.items():
        if any(term in t for term in terms):
            return category
    return "General / Unknown"

def calculate_risk(text_probability, url_score, has_urls):
    # A transparent heuristic index, NOT a calibrated probability of fraud.
    raw = 0.75 * (text_probability * 100) + 0.25 * url_score if has_urls else text_probability * 100
    return max(0, min(100, round(raw)))

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "PhishShield API"})

@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    if not isinstance(message, str):
        return jsonify({"error": "Message must be text."}), 400
    message = message.strip()
    if not message:
        return jsonify({"error": "Please enter a message."}), 400
    if len(message) > 10000:
        return jsonify({"error": "Message must be 10,000 characters or fewer."}), 400

    probabilities = model.predict_proba([message])[0]
    classes = list(model.classes_)
    phishing_probability = float(probabilities[classes.index("phishing")])

    urls = extract_urls(message)
    url_results = [analyze_url(url) for url in urls]
    max_url_score = max((item["score"] for item in url_results), default=0)
    risk_score = calculate_risk(phishing_probability, max_url_score, bool(urls))

    # Classification threshold is a tunable product decision, not ground truth.
    prediction = "Potential Phishing" if risk_score >= 50 else "Likely Legitimate"
    risk_level = "High" if risk_score >= 70 else "Medium" if risk_score >= 35 else "Low"
    warnings = text_warnings(message)
    for item in url_results:
        warnings.extend(item["reasons"])
    warnings = list(dict.fromkeys(warnings))

    result = {
        "prediction": prediction,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category": detect_category(message),
        "text_model_probability": round(phishing_probability * 100, 2),
        "urls": url_results,
        "model_explanations": explain_prediction(model, message),
        "warning_signs": warnings,
        "recommendation": (
            "Do not click links or share OTPs, passwords, PINs or payment details. "
            "Verify the request using the organisation's official app or a phone number "
            "you already trust."
            if risk_score >= 50 else
            "No strong warning signs were found by this prototype. This does not prove "
            "the message is safe; verify unexpected requests independently."
        )
    }

    with connect_db() as conn:
        conn.execute("""
            INSERT INTO scans
            (message_preview, prediction, risk_score, risk_level, category, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            message[:240], prediction, risk_score, risk_level,
            result["category"], datetime.now(timezone.utc).isoformat()
        ))
    return jsonify(result)

@app.get("/api/history")
def history():
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT id, message_preview, prediction, risk_score,
                   risk_level, category, created_at
            FROM scans ORDER BY id DESC LIMIT 25
        """).fetchall()
    return jsonify([dict(row) for row in rows])

init_db()

if __name__ == "__main__":
    # Development server only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
