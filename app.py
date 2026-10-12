"""
PhisLens - Flask REST API and Application Server
Provides secure URL scanning and model inference endpoints.
Does NOT execute or visit user-submitted URLs.
Never trains the model on server startup.
"""

import datetime
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
from flask import Flask, jsonify, render_template, request

from feature_extractor import (
    FEATURE_NAMES,
    explain_features,
    extract_features,
    extract_feature_vector,
    normalize_url,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "phislens_model.joblib"
METRICS_PATH = BASE_DIR / "model" / "metrics.json"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

# Global model state
MODEL_BUNDLE = None
MODEL = None
MODEL_LOADED = False
MODEL_METADATA = {}


def load_model():
    """Attempts to load the trained model from disk."""
    global MODEL_BUNDLE, MODEL, MODEL_LOADED, MODEL_METADATA
    if MODEL_PATH.exists():
        try:
            MODEL_BUNDLE = joblib.load(MODEL_PATH)
            MODEL = MODEL_BUNDLE.get("model")
            MODEL_METADATA = {
                "trained_at": MODEL_BUNDLE.get("trained_at"),
                "classes": MODEL_BUNDLE.get("classes", ["legitimate", "phishing"]),
                "feature_count": len(MODEL_BUNDLE.get("feature_names", FEATURE_NAMES)),
                "samples": MODEL_BUNDLE.get("n_samples", 0),
            }
            MODEL_LOADED = True
            print(f"[+] PhisLens model loaded successfully from {MODEL_PATH}")
        except Exception as e:
            MODEL_LOADED = False
            print(f"[-] Error loading model file {MODEL_PATH}: {e}")
    else:
        MODEL_LOADED = False
        print(f"[-] Model file not found at {MODEL_PATH}. Run 'python train_model.py' to generate.")


# Load saved model once on initialization (never re-train on startup)
load_model()


@app.after_request
def add_security_and_cors_headers(response):
    """Adds security headers and permits API cross-origin requests."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/")
def index():
    """Serves the main PhisLens user interface."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint: reports service status and model availability."""
    return (
        jsonify(
            {
                "status": "healthy" if MODEL_LOADED else "degraded",
                "model_loaded": MODEL_LOADED,
                "model_type": "RandomForestClassifier",
                "feature_count": len(FEATURE_NAMES),
                "timestamp": datetime.datetime.now().isoformat(),
                "metadata": MODEL_METADATA,
            }
        ),
        200 if MODEL_LOADED else 503,
    )


@app.route("/api/stats", methods=["GET"])
def stats():
    """Returns evaluation metrics recorded during training."""
    if METRICS_PATH.exists():
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify({"status": "success", "metrics": data}), 200
        except Exception as e:
            return jsonify({"status": "error", "message": "Failed to read metrics."}), 500
    return jsonify({"status": "error", "message": "No training metrics found."}), 404


@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan():
    """
    Main URL scan endpoint.
    Validates, normalizes, extracts 26 features, and computes genuine model probabilities.
    Never executes or visits submitted URLs.
    """
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    if not MODEL_LOADED or MODEL is None:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "Phishing detection model is currently not loaded. Please run 'python train_model.py' to train and save the model.",
                }
            ),
            503,
        )

    # 1. Validate request content type and JSON payload
    if not request.is_json:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "Invalid request format: Expected Content-Type application/json.",
                }
            ),
            400,
        )

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "Request body must be a valid JSON object.",
                }
            ),
            400,
        )

    raw_url = data.get("url")
    if not raw_url or not isinstance(raw_url, str):
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "Missing or invalid 'url' parameter. URL must be a non-empty string.",
                }
            ),
            400,
        )

    if len(raw_url) > 2048:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "URL length exceeds maximum supported limit of 2048 characters.",
                }
            ),
            400,
        )

    # 2. Normalize URL safely without network communication
    try:
        normalized_url = normalize_url(raw_url)
    except ValueError as val_err:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": f"Invalid URL input: {str(val_err)}",
                }
            ),
            400,
        )
    except Exception:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": "Failed to parse URL structure.",
                }
            ),
            400,
        )

    # 3. Feature Extraction
    try:
        features_dict = extract_features(normalized_url)
        feature_vector = extract_feature_vector(normalized_url)
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": f"Feature extraction failed: {str(e)}",
                }
            ),
            500,
        )

    # 4. Model Inference & Probability Calculation
    try:
        probabilities = MODEL.predict_proba([feature_vector])[0]
        prob_legitimate = float(probabilities[0])
        prob_phishing = float(probabilities[1])
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": f"Inference engine error: {str(e)}",
                }
            ),
            500,
        )

    # 5. Risk Classification & Color Mapping
    # Phishing threshold >= 0.65 -> Red
    # Suspicious threshold 0.40 <= prob < 0.65 -> Yellow
    # Legitimate threshold prob < 0.40 -> Green
    if prob_phishing >= 0.65:
        risk_class = "phishing"
        label = "Phishing Threat Detected"
        color = "red"
        confidence_percent = round(prob_phishing * 100, 2)
    elif prob_phishing >= 0.40:
        risk_class = "suspicious"
        label = "Suspicious Link Detected"
        color = "yellow"
        confidence_percent = round(max(prob_phishing, prob_legitimate) * 100, 2)
    else:
        risk_class = "legitimate"
        label = "Legitimate Website"
        color = "green"
        confidence_percent = round(prob_legitimate * 100, 2)

    # 6. Generate Contextual Feature Explanations
    explanations = explain_features(features_dict, prob_phishing)

    parsed_info = urlparse(normalized_url)

    response_payload = {
        "status": "success",
        "url": {
            "input": raw_url,
            "normalized": normalized_url,
            "hostname": parsed_info.hostname or "",
            "scheme": parsed_info.scheme or "",
            "path": parsed_info.path or "/",
        },
        "prediction": {
            "class": risk_class,
            "label": label,
            "color": color,
            "probability_phishing": round(prob_phishing, 4),
            "probability_legitimate": round(prob_legitimate, 4),
            "confidence_percent": confidence_percent,
        },
        "explanations": explanations,
        "features_summary": {
            "length_url": int(features_dict["length_url"]),
            "length_hostname": int(features_dict["length_hostname"]),
            "subdomain_count": int(features_dict["subdomain_count"]),
            "has_ip_address": bool(features_dict["has_ip_address"]),
            "has_custom_port": bool(features_dict["has_custom_port"]),
            "is_https": parsed_info.scheme.lower() == "https",
            "has_sensitive_keywords": int(features_dict["has_sensitive_keywords"]),
            "is_shortened": bool(features_dict["is_shortened"]),
            "suspicious_tld": bool(features_dict["suspicious_tld"]),
            "entropy_hostname": features_dict["entropy_hostname"],
            "qty_dot_url": int(features_dict["qty_dot_url"]),
            "qty_hyphen_hostname": int(features_dict["qty_hyphen_hostname"]),
        },
        "safety_warning": "Predictions are produced by statistical machine learning models analyzing URL characteristics. They are not an absolute guarantee of website safety. Exercise caution before submitting personal or financial information.",
        "scanned_at": datetime.datetime.now().isoformat(),
    }

    return jsonify(response_payload), 200


if __name__ == "__main__":
    # Host on 127.0.0.1:5000
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting PhisLens Server on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
