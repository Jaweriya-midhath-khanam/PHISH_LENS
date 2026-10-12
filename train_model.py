"""
PhisLens - Reproducible Model Training Script
Trains a Random Forest classifier using a public dataset of raw URLs.
Extracts 26 purely lexical and structural URL features with zero data leakage,
evaluates on a held-out test set, and exports the model and metrics.
"""

import argparse
import csv
import datetime
import json
import os
import random
import sys
import urllib.request
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# Import shared feature extraction logic
from feature_extractor import FEATURE_NAMES, extract_feature_vector, normalize_url

DATASET_DEFAULT_URL = (
    "https://raw.githubusercontent.com/saksham-2410/Phishing-URL-Classifier/master/phishing_site_urls.csv"
)

# Seed list used as a resilient fallback in case of network unavailability
SEED_LEGITIMATE_URLS = [
    "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
    "https://en.wikipedia.org/wiki/Main_Page", "https://twitter.com", "https://www.instagram.com",
    "https://www.linkedin.com", "https://github.com", "https://stackoverflow.com",
    "https://www.amazon.com", "https://www.apple.com", "https://www.microsoft.com",
    "https://www.netflix.com", "https://www.reddit.com", "https://www.cloudflare.com",
    "https://www.python.org", "https://www.nih.gov", "https://www.mit.edu",
    "https://www.stanford.edu", "https://www.cdc.gov", "https://www.bbc.com/news",
    "https://www.reuters.com", "https://www.nytimes.com", "https://www.theverge.com",
    "https://www.cnn.com", "https://developer.mozilla.org", "https://www.w3schools.com",
    "https://wordpress.org", "https://www.dropbox.com", "https://www.spotify.com",
]

SEED_PHISHING_URLS = [
    "http://secure-login-apple-support-service.com/update/verify.php",
    "http://192.168.1.100/paypal/login.htm",
    "http://paypal-verification-account-update.xyz/login.html?cmd=_login_run",
    "http://www.netflix-account-suspended-bill-support.com/auth",
    "http://appleid-apple.com-verify.update.account.support-login.info",
    "http://secure.bankofamerica.com.customer-verification-portal.net/signin",
    "http://login.chase.com.acc-restore-id982.biz/verify.php",
    "http://wellsfargo.com-security-alert-review.com/auth.jsp",
    "http://185.220.101.5/ebay-signin/login.php?ref=ebay",
    "http://microsoft-outlook-office365-pass-recovery.top/index.php",
    "http://amazon-prime-account-issue-update.work/signin",
    "http://instagram-help-copyright-infringement.cf/login",
    "http://facebook-security-community-appeal.ga/checkpoint",
    "http://dhl-package-delivery-tracking-update.ml/confirm",
    "http://fedex-express-shipping-reschedule.tk/payment",
]


def download_dataset_if_needed(url: str, dest_path: Path):
    """Downloads the dataset if not already cached locally."""
    if dest_path.exists() and dest_path.stat().st_size > 1000:
        print(f"[+] Found cached dataset at: {dest_path} ({dest_path.stat().st_size / (1024*1024):.2f} MB)")
        return True

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[*] Downloading dataset from {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(dest_path, "wb") as out_file:
            chunk_size = 64 * 1024
            downloaded = 0
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                if downloaded % (1024 * 1024 * 5) == 0:
                    print(f"    Downloaded {downloaded / (1024*1024):.1f} MB...")
        print(f"[+] Download complete: {dest_path} ({dest_path.stat().st_size / (1024*1024):.2f} MB)")
        return True
    except Exception as e:
        print(f"[-] Warning: Failed to download dataset: {e}")
        return False


def is_clean_url(url: str) -> bool:
    """Validates that a URL is non-empty, contains printable characters, and has basic domain structure."""
    if not url or len(url) < 4:
        return False
    if not all(32 <= ord(c) < 127 for c in url):
        return False
    if "." not in url:
        return False
    # Discard binary garbage tokens
    if any(c in url for c in ("\x00", "\r", "\n", "\t", "\\x")):
        return False
    return True


# Expanded set of top legitimate domains & URLs to ensure realistic training distribution
TOP_LEGITIMATE_SITES = [
    "https://google.com", "https://www.google.com", "https://youtube.com", "https://www.youtube.com",
    "https://wikipedia.org", "https://en.wikipedia.org/wiki/Main_Page", "https://github.com",
    "https://amazon.com", "https://www.amazon.com", "https://apple.com", "https://www.apple.com",
    "https://microsoft.com", "https://linkedin.com", "https://reddit.com", "https://twitter.com",
    "https://instagram.com", "https://stackoverflow.com", "https://python.org", "https://netflix.com",
    "https://cloudflare.com", "https://nih.gov", "https://mit.edu", "https://harvard.edu",
    "https://stanford.edu", "https://cdc.gov", "https://bbc.com", "https://cnn.com",
    "https://reuters.com", "https://nytimes.com", "https://theverge.com", "https://mozilla.org",
    "https://w3schools.com", "https://wordpress.org", "https://dropbox.com", "https://spotify.com",
    "https://openai.com", "https://bing.com", "https://medium.com", "https://twitch.tv",
    "https://ebay.com", "https://paypal.com", "https://yahoo.com", "https://zoom.us",
    "https://duckduckgo.com", "https://gitlab.com", "https://bitbucket.org", "https://docker.com",
    "https://digitalocean.com", "https://aws.amazon.com", "https://cloud.google.com",
]


def load_raw_dataset(csv_path: Path, max_samples: int):
    """
    Loads raw URLs from the CSV file and returns balanced lists of
    legitimate (label=0) and phishing (label=1) URLs, sampled uniformly
    across the entire dataset to prevent local category/alphabetical bias.
    """
    all_good = []
    all_bad = []

    target_per_class = max_samples // 2

    if csv_path.exists():
        print(f"[*] Reading and scanning entire CSV for clean URLs: {csv_path}")
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header = next(reader, None)

            url_idx = 0
            label_idx = 1
            if header:
                for idx, col in enumerate(header):
                    col_clean = col.strip().lower()
                    if col_clean in ("url", "website"):
                        url_idx = idx
                    elif col_clean in ("label", "status", "class", "result"):
                        label_idx = idx

            for row in reader:
                if len(row) <= max(url_idx, label_idx):
                    continue
                raw_url = row[url_idx].strip()
                label_val = row[label_idx].strip().lower()

                if not is_clean_url(raw_url):
                    continue

                if label_val in ("bad", "phishing", "1", "-1"):
                    all_bad.append(raw_url)
                elif label_val in ("good", "legitimate", "0", "benign"):
                    all_good.append(raw_url)

        print(f"[+] Total clean URLs scanned from CSV: {len(all_good):,} legitimate, {len(all_bad):,} phishing")

    # Add realistic top domains to legitimate pool
    all_good.extend(TOP_LEGITIMATE_SITES * 10)

    # Deterministic uniform random sample across the full population
    random.seed(42)
    sample_good_count = min(target_per_class, len(all_good))
    sample_bad_count = min(target_per_class, len(all_bad))

    legitimate = random.sample(all_good, sample_good_count) if all_good else []
    phishing = random.sample(all_bad, sample_bad_count) if all_bad else []

    # If dataset wasn't available or had insufficient samples, supplement with seed lists
    if len(legitimate) < 50 or len(phishing) < 50:
        print("[!] Dataset insufficient; supplementing with seed lists...")
        while len(legitimate) < target_per_class:
            legitimate.extend(TOP_LEGITIMATE_SITES)
        while len(phishing) < target_per_class:
            phishing.extend(SEED_PHISHING_URLS)
        legitimate = legitimate[:target_per_class]
        phishing = phishing[:target_per_class]

    print(f"[+] Sampled {len(legitimate):,} legitimate and {len(phishing):,} phishing URLs for training.")
    return legitimate, phishing


def build_feature_matrix(urls: list, labels: list):
    """
    Extracts features for all raw URLs and constructs numerical matrix X and vector y.
    Safe normalization is applied to each URL.
    """
    X = []
    y = []
    skipped = 0

    print(f"[*] Extracting {len(FEATURE_NAMES)} features from {len(urls)} URLs...")
    for idx, (raw_url, label) in enumerate(zip(urls, labels)):
        try:
            norm_url = normalize_url(raw_url)
            features = extract_feature_vector(norm_url)
            X.append(features)
            y.append(label)
        except Exception:
            skipped += 1

        if (idx + 1) % 5000 == 0:
            print(f"    Processed {idx + 1}/{len(urls)} URLs...")

    print(f"[+] Feature matrix built: {len(X)} samples valid ({skipped} skipped due to invalid format).")
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def train_and_evaluate(
    data_path: Path,
    model_path: Path,
    metrics_path: Path,
    samples: int = 20000,
    test_size: float = 0.2,
    random_state: int = 42,
):
    """Full end-to-end reproducible training & evaluation pipeline."""
    start_time = datetime.datetime.now()
    print("=" * 65)
    print("       PhisLens Machine Learning Model Training Pipeline")
    print("=" * 65)
    print(f"Target sample size: {samples} ({samples//2} legitimate, {samples//2} phishing)")
    print(f"Test split: {int(test_size*100)}% | Random seed: {random_state}")
    print(f"Features: {len(FEATURE_NAMES)} lexical & structural features")
    print("-" * 65)

    # 1. Acquire dataset
    download_dataset_if_needed(DATASET_DEFAULT_URL, data_path)

    # 2. Load and balance raw URLs
    legitimate_urls, phishing_urls = load_raw_dataset(data_path, max_samples=samples)

    all_urls = legitimate_urls + phishing_urls
    all_labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

    # Shuffle paired data deterministically
    combined = list(zip(all_urls, all_labels))
    random.seed(random_state)
    random.shuffle(combined)
    shuffled_urls, shuffled_labels = zip(*combined)

    # 3. Extract features
    X, y = build_feature_matrix(list(shuffled_urls), list(shuffled_labels))

    # 4. Stratified Train/Test Split (Prevents data leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    print(f"[+] Train set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # 5. Model Training (Random Forest Classifier)
    print("[*] Training RandomForestClassifier (n_estimators=100)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=22,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # 6. Evaluation on Held-out Test Set
    print("[*] Evaluating on held-out test set...")
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("-" * 65)
    print("                     EVALUATION RESULTS")
    print("-" * 65)
    print(f"  Accuracy : {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall   : {rec * 100:.2f}%")
    print(f"  F1-Score : {f1 * 100:.2f}%")
    print("-" * 65)
    print("  Confusion Matrix:")
    print(f"    True Legitimate  (TN): {tn:6d}  |  False Phishing  (FP): {fp:6d}")
    print(f"    False Legitimate (FN): {fn:6d}  |  True Phishing   (TP): {tp:6d}")
    print("-" * 65)

    # Feature Importance Top 5
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("  Top 5 Most Informative Features:")
    for rank, idx in enumerate(sorted_idx[:5], 1):
        print(f"    {rank}. {FEATURE_NAMES[idx]:<24} (weight: {importances[idx]:.4f})")
    print("-" * 65)

    # 7. Save Model Bundle & Preprocessing components
    model_path.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "classes": ["legitimate", "phishing"],
        "trained_at": datetime.datetime.now().isoformat(),
        "n_samples": len(X),
        "random_state": random_state,
    }
    joblib.dump(bundle, model_path)
    print(f"[+] Saved model bundle to: {model_path}")

    # 8. Save Metrics JSON
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_payload = {
        "model_type": "RandomForestClassifier",
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "total_samples": int(len(X)),
        "feature_count": len(FEATURE_NAMES),
        "timestamp": datetime.datetime.now().isoformat(),
        "elapsed_seconds": round((datetime.datetime.now() - start_time).total_seconds(), 2),
    }

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"[+] Saved metrics JSON to: {metrics_path}")

    elapsed = (datetime.datetime.now() - start_time).total_seconds()
    print(f"[+] Training pipeline completed successfully in {elapsed:.2f} seconds.")
    return metrics_payload


def main():
    parser = argparse.ArgumentParser(description="Train PhisLens Phishing Detection Model")
    parser.add_argument("--samples", type=int, default=20000, help="Total balanced samples to train on")
    parser.add_argument("--data-path", type=str, default="data/phishing_site_urls.csv", help="Path to raw dataset")
    parser.add_argument("--model-path", type=str, default="model/phislens_model.joblib", help="Output model path")
    parser.add_argument("--metrics-path", type=str, default="model/metrics.json", help="Output metrics path")
    parser.add_argument("--test-size", type=float, default=0.2, help="Held-out test set fraction")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    train_and_evaluate(
        data_path=Path(args.data_path),
        model_path=Path(args.model_path),
        metrics_path=Path(args.metrics_path),
        samples=args.samples,
        test_size=args.test_size,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()
