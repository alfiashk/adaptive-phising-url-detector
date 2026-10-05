import os
import csv
import re
from urllib.parse import urlparse

import pandas as pd
import joblib

from backend.feature_extractor import extract_url_features
from backend.constants import MODEL_FEATURES, PHISHING_LABEL, SUSPICIOUS_HOST_TOKENS
from backend.web_inspector import inspect_url

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
FEEDBACK_PATH = os.path.join(BASE_DIR, "model", "feedback.csv")

_model = None
_model_mtime = None


def _get_model():
    global _model, _model_mtime
    model_mtime = os.path.getmtime(MODEL_PATH)
    if _model is None or _model_mtime != model_mtime:
        _model = joblib.load(MODEL_PATH)
        _model_mtime = model_mtime
    return _model


def reload_model():
    global _model, _model_mtime
    _model = None
    _model_mtime = None
    return _get_model()


def _feedback_label(url: str):
    if not os.path.exists(FEEDBACK_PATH):
        return None
    normalized = url.strip().lower().rstrip("/")
    with open(FEEDBACK_PATH, newline="", encoding="utf-8") as feedback_file:
        for row in csv.DictReader(feedback_file):
            if row["url"].strip().lower().rstrip("/") == normalized:
                return int(row["label"])
    return None


def _has_suspicious_hostname(hostname: str) -> bool:
    tokens = {
        token for token in hostname.replace(".", "-").split("-") if token
    }
    return len(tokens & SUSPICIOUS_HOST_TOKENS) >= 2


def _risk_signals(url: str, parsed, hostname: str, features: dict) -> list[str]:
    signals = []
    hostname_tokens = {
        token for token in hostname.replace(".", "-").split("-") if token
    }
    path_and_query = f"{parsed.path} {parsed.query}".lower()

    if features["IsDomainIP"]:
        signals.append("The host is an IP address instead of a domain")
    if "@" in parsed.netloc:
        signals.append("The URL contains @, which can hide the real host")
    if hostname.startswith("xn--") or any(ord(char) > 127 for char in hostname):
        signals.append("The hostname uses Unicode or punycode characters")
    if parsed.port and parsed.port not in {80, 443}:
        signals.append(f"The URL uses an unusual port ({parsed.port})")
    if len(hostname.split(".")) > 4:
        signals.append("The hostname has many nested subdomains")
    if len(url) > 150:
        signals.append("The URL is unusually long")
    if features["NoOfQMarkInURL"] and features["NoOfEqualsInURL"] >= 3:
        signals.append("The query contains many parameters")
    if re.search(r"(?:login|signin|verify|account|password|credential|billing)", path_and_query):
        signals.append("The path or query requests account-related action")
    if len(hostname_tokens & SUSPICIOUS_HOST_TOKENS) >= 2:
        signals.append("The hostname combines multiple phishing-related words")
    if parsed.scheme == "http":
        signals.append("The connection is not encrypted with HTTPS")

    return signals


def predict_url(url: str) -> dict:
    model = _get_model()

    features = extract_url_features(url)
    df = pd.DataFrame([features])[MODEL_FEATURES]

    normalized_url = url.strip()
    parsed = urlparse(
        normalized_url if "://" in normalized_url else f"http://{normalized_url}"
    )
    hostname = (parsed.hostname or "").lower().rstrip(".")
    suspicious_hostname = _has_suspicious_hostname(hostname)
    risk_signals = _risk_signals(url, parsed, hostname, features)
    web_checks = inspect_url(url)
    if not web_checks["reachable"]:
        risk_signals.append("The domain could not be reached")
    if web_checks["redirects"]:
        risk_signals.append(f"The URL redirects {len(web_checks['redirects'])} time(s)")
    if web_checks["password_forms"]:
        risk_signals.append("The page contains a password form")
    if web_checks["certificate"] and not web_checks["certificate"].get("valid", False):
        risk_signals.append("The HTTPS certificate could not be validated")
    prediction = _feedback_label(url)
    if prediction is None:
        prediction = PHISHING_LABEL if suspicious_hostname else int(model.predict(df)[0])

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(df)[0]
        confidence = 1.0 if _feedback_label(url) is not None or suspicious_hostname else float(max(proba))
    else:
        confidence = 1.0

    return {
        "prediction": prediction,
        "label": "phishing" if prediction == 0 else "safe",
        "confidence": round(confidence, 4),
        "risk_signals": risk_signals,
        "web_checks": web_checks,
        "features": features,
    }