# PhisLens — Phishing Website Detection Using Machine Learning

PhisLens is a full-stack cybersecurity web application designed to detect phishing websites from URL structural and lexical characteristics in real time. It utilizes an ensemble **Random Forest** machine learning classifier trained on a verified dataset of 20,000 URLs, operating completely **offline** with zero network exposure to untrusted target websites.

---

## Authors & Credits
* **Jaweriya Midhath Khanam** — Machine Learning & Backend Development
* **Syeda Tuba Naaz** — Cybersecurity Research & Full-Stack Architecture

**Categories:** Cybersecurity • Machine Learning • Web Security

---

## Key Features & Highlights

1. **Zero-Trust URL Sandbox**: Never visits, downloads, or executes submitted URLs. Lexical and structural forensics are computed purely from the URL string.
2. **26 Extracted Feature Vectors**:
   * **Structural**: Total URL length, domain length, path length, query length, subdomain count, and custom/non-standard port detection.
   * **Character Distribution**: Counts of dots, hyphens, slashes, `@` symbols, underscores, equals, exclamation marks, and numerical digit ratios.
   * **Threat Signals**: Detection of raw IP address hosts, URL shortener services (`bit.ly`, etc.), high-risk TLDs (`.xyz`, `.top`, etc.), and credential-harvesting keywords (`login`, `verify`, `banking`, `secure`, `account`, etc.).
   * **Statistical Entropy**: Shannon character entropy on URL and hostname to identify algorithmically generated tokens and obfuscation.
3. **Calibrated Machine Learning Engine**:
   * Model: 100-tree `RandomForestClassifier` with balanced training.
   * Calibrated probability thresholds:
     * **Legitimate (Green)**: Phishing probability < 40%
     * **Suspicious (Yellow)**: Phishing probability between 40% and 65%
     * **Phishing (Red)**: Phishing probability > 65%
   * Reports genuine, unforced confidence percentages.
4. **Cybersecurity Glassmorphism UI**:
   * Obsidian black theme with electric violet accents and neon purple glow.
   * Interactive dynamic starry particle canvas.
   * Animated optical cyber-lens logo with rotating targeting reticle.
   * Functional Dark / Light theme toggle.
   * Client-side scan history persisted in `localStorage` with re-scan capabilities.
   * Quick-test sample chips (`wikipedia.org`, `paypal-update.xyz`, IP address host, URL shortener).
5. **REST API**:
   * `GET /api/health`: Reports service status and model availability.
   * `GET /api/stats`: Serves held-out test evaluation metrics.
   * `POST /api/scan`: Accepts JSON payload `{"url": "..."}`, validates and normalizes input, and returns predictions with contextual explanations.

---

## Project Structure

```
PhisLens-New/
├── app.py                      # Flask REST API server and static frontend host
├── feature_extractor.py        # Shared 26-feature URL extraction engine
├── train_model.py              # Reproducible machine learning training script
├── requirements.txt            # Python package dependencies
├── README.md                   # Documentation, setup guide, and metrics
├── data/
│   └── phishing_site_urls.csv  # Cached Kaggle/PhishTank raw URL dataset
├── model/
│   ├── phislens_model.joblib   # Trained RandomForest model bundle
│   └── metrics.json            # Recorded test set evaluation metrics
├── templates/
│   └── index.html              # HTML5 responsive interface (Home, How It Works, About Us)
├── static/
│   ├── css/
│   │   └── style.css           # Glassmorphism, neon glow, and dark/light themes
│   └── js/
│       └── script.js           # Particle canvas, scanner controller, and history
└── tests/
    ├── test_api.py             # Flask API endpoints test suite
    └── test_features.py        # Feature extraction and normalization unit tests
```

---

## Quickstart Guide

### 1. Install Dependencies
Ensure you have Python 3.10+ (tested on Python 3.12) installed:

```bash
pip install -r requirements.txt
```
*(On Windows systems with Python launcher: `py -3.12 -m pip install -r requirements.txt`)*

### 2. Train the Machine Learning Model
The training script automatically caches the dataset, validates and cleans raw URLs, extracts 26 features, trains a Random Forest model, and evaluates on a held-out test split:

```bash
python train_model.py --samples 20000
```
*(On Windows systems: `py -3.12 train_model.py --samples 20000`)*

> [!NOTE]
> The server will load the saved model bundle (`model/phislens_model.joblib`) on startup. Model training is kept strictly separate from the Flask server and never runs every time the server starts.

### 3. Run Automated Tests
Execute the automated test suite covering URL normalization, feature extraction, API routes, and error handling:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
*(On Windows systems: `py -3.12 -m unittest discover -s tests -p "test_*.py" -v`)*

### 4. Run the Application
Start the Flask application server:

```bash
python app.py
```
*(On Windows systems: `py -3.12 app.py`)*

### 5. Access the Web Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Machine Learning Evaluation Results

Evaluated on 3,991 stratified test URLs (20% held-out test set) with zero data leakage:

| Metric | Score | Description |
| :--- | :--- | :--- |
| **Accuracy** | **85.57%** | Proportion of correctly classified URLs on unseen data |
| **Precision** | **87.41%** | Reliability of positive phishing predictions (low false alarms) |
| **Recall** | **83.02%** | Proportion of actual phishing links successfully caught |
| **F1-Score** | **85.16%** | Harmonic mean of Precision and Recall |

### Confusion Matrix on Held-Out Test Set:
* **True Legitimate (TN)**: 1,762
* **False Phishing (FP)**: 238
* **False Legitimate (FN)**: 338
* **True Phishing (TP)**: 1,653

### Top 5 Most Informative Features:
1. `has_sensitive_keywords` (authentication, banking, verification words)
2. `length_path` (deep subpath structures)
3. `entropy_url` (Shannon character randomness in URL)
4. `qty_digits_url` (proportion of numeric tokens)
5. `qty_dot_url` (excessive dot counts)

---

## Known Limitations & Security Considerations

1. **Purely Lexical Scope**: PhisLens analyzes the lexical structure of URLs. It does not inspect the live HTML DOM, JavaScript payload, or server response headers of the target site. This deliberate design ensures zero risk of drive-by downloads or browser exploitation for the user, but cannot detect compromised legitimate servers whose URLs appear completely benign.
2. **Adversarial URL Crafting**: Attackers who host phishing pages on trusted cloud providers (e.g. `sites.google.com`, `storage.googleapis.com`) or use short, clean domains without phishing keywords can lower the statistical probability score.
3. **Predictions are Not Guarantees**: As emphasized prominently on the user interface, machine learning outputs are statistical risk assessments and should be used alongside multi-factor authentication, security awareness, and defense-in-depth practices.
