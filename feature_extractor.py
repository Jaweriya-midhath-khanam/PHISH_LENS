"""
PhisLens - Shared URL Feature Extraction Engine
Extracts 26 purely lexical, structural, and statistical features directly from URL strings
without performing network calls, downloading HTML, or executing remote content.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

# Ordered list of all 26 feature names used across training and inference
FEATURE_NAMES = [
    "length_url",
    "length_hostname",
    "length_path",
    "length_query",
    "qty_dot_url",
    "qty_dot_hostname",
    "qty_hyphen_url",
    "qty_hyphen_hostname",
    "qty_underline_url",
    "qty_slash_url",
    "qty_questionmark_url",
    "qty_equal_url",
    "qty_at_url",
    "qty_and_url",
    "qty_exclamation_url",
    "qty_digits_url",
    "ratio_digits_url",
    "ratio_digits_hostname",
    "has_ip_address",
    "has_custom_port",
    "subdomain_count",
    "has_sensitive_keywords",
    "is_shortened",
    "suspicious_tld",
    "entropy_url",
    "entropy_hostname",
]

SENSITIVE_KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "banking",
    "secure", "security", "account", "wallet", "confirm", "confirmation",
    "support", "auth", "authenticate", "password", "credential",
    "ebay", "paypal", "appleid", "webscr", "recover", "passcode"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "tiny.cc",
    "shorte.st", "bc.vc", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "buzz",
    "fit", "icu", "click", "link", "rest", "surf", "country", "kim",
    "science", "gdn", "racing", "mom", "party", "loan", "men"
}

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def normalize_url(raw_url: str) -> str:
    """
    Safely normalizes an input URL string without visiting or executing it.
    Handles bare domains (example.com), protocols, and leading/trailing whitespace.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")

    # Remove wrapping quotes or brackets if present
    cleaned = cleaned.strip("\"'<>[]()")

    # Prepend http:// if scheme is missing so urllib parses hostname/netloc correctly
    if cleaned.startswith("//"):
        cleaned = "http:" + cleaned
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
        cleaned = "http://" + cleaned

    parsed = urlparse(cleaned)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("Unable to parse a valid domain or hostname from the provided URL.")

    # Disallow invalid hostnames that are just whitespace or invalid characters
    if any(c in hostname for c in (" ", "\t", "\r", "\n")):
        raise ValueError("Hostname contains invalid whitespace characters.")

    # Canonicalize hostname: strip legacy www. prefix for consistent lexical forensics
    if hostname.startswith("www.") and len(hostname) > 4:
        hostname = hostname[4:]

    # Reconstruct normalized URL string
    scheme = parsed.scheme.lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{scheme}://{netloc}{path}{query}{fragment}"


def calculate_entropy(text: str) -> float:
    """Calculates Shannon character entropy for a string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def extract_features(normalized_url: str) -> dict:
    """
    Extracts all 26 lexical, structural, and statistical features as a dictionary.
    """
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Clean hostname (strip www. prefix for consistent structural analysis)
    eff_hostname = hostname[4:] if hostname.startswith("www.") else hostname

    length_url = len(normalized_url)
    length_hostname = len(eff_hostname)
    length_path = len(path)
    length_query = len(query)

    # Character counts in URL
    qty_dot_url = normalized_url.count(".")
    qty_dot_hostname = eff_hostname.count(".")
    qty_hyphen_url = normalized_url.count("-")
    qty_hyphen_hostname = eff_hostname.count("-")
    qty_underline_url = normalized_url.count("_")
    qty_slash_url = normalized_url.count("/")
    qty_questionmark_url = normalized_url.count("?")
    qty_equal_url = normalized_url.count("=")
    qty_at_url = normalized_url.count("@")
    qty_and_url = normalized_url.count("&")
    qty_exclamation_url = normalized_url.count("!")

    # Digit counts & ratios
    digits_in_url = sum(c.isdigit() for c in normalized_url)
    digits_in_hostname = sum(c.isdigit() for c in eff_hostname)
    ratio_digits_url = round(digits_in_url / max(length_url, 1), 4)
    ratio_digits_hostname = round(digits_in_hostname / max(length_hostname, 1), 4)

    # IP address check
    has_ip_address = 1.0 if IP_REGEX.match(hostname) else 0.0

    # Non-standard port check (phishing links frequently use high ports like :8080 or :8888)
    has_custom_port = 1.0 if (parsed.port and parsed.port not in (80, 443)) else 0.0

    # Subdomain count: hostname parts minus domain and TLD (excluding 'www')
    parts = [p for p in eff_hostname.split(".") if p]
    subdomain_count = float(max(0, len(parts) - 2))

    # Sensitive keywords in path or query or domain
    lower_url = normalized_url.lower()
    keyword_matches = sum(1 for kw in SENSITIVE_KEYWORDS if kw in lower_url)

    # URL Shortener check
    is_shortened = 1.0 if hostname in SHORTENER_DOMAINS else 0.0

    # Suspicious TLD check
    tld = parts[-1] if parts else ""
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # Entropies
    entropy_url = calculate_entropy(normalized_url)
    entropy_hostname = calculate_entropy(hostname)

    features = {
        "length_url": float(length_url),
        "length_hostname": float(length_hostname),
        "length_path": float(length_path),
        "length_query": float(length_query),
        "qty_dot_url": float(qty_dot_url),
        "qty_dot_hostname": float(qty_dot_hostname),
        "qty_hyphen_url": float(qty_hyphen_url),
        "qty_hyphen_hostname": float(qty_hyphen_hostname),
        "qty_underline_url": float(qty_underline_url),
        "qty_slash_url": float(qty_slash_url),
        "qty_questionmark_url": float(qty_questionmark_url),
        "qty_equal_url": float(qty_equal_url),
        "qty_at_url": float(qty_at_url),
        "qty_and_url": float(qty_and_url),
        "qty_exclamation_url": float(qty_exclamation_url),
        "qty_digits_url": float(digits_in_url),
        "ratio_digits_url": float(ratio_digits_url),
        "ratio_digits_hostname": float(ratio_digits_hostname),
        "has_ip_address": has_ip_address,
        "has_custom_port": has_custom_port,
        "subdomain_count": subdomain_count,
        "has_sensitive_keywords": float(keyword_matches),
        "is_shortened": is_shortened,
        "suspicious_tld": suspicious_tld,
        "entropy_url": entropy_url,
        "entropy_hostname": entropy_hostname,
    }

    return features


def extract_feature_vector(normalized_url: str) -> list:
    """
    Extracts features as an ordered numeric list matching FEATURE_NAMES.
    """
    feat_dict = extract_features(normalized_url)
    return [feat_dict[name] for name in FEATURE_NAMES]


def explain_features(features: dict, prob_phishing: float) -> list:
    """
    Generates human-readable security observations explaining the risk factors.
    """
    observations = []

    if features.get("has_ip_address", 0) > 0:
        observations.append("The domain uses a raw IP address instead of a registered domain name (high risk indicator).")

    if features.get("has_custom_port", 0) > 0:
        observations.append("Uses an unusual non-standard port number, common on rogue phishing hosting servers.")

    if features.get("qty_at_url", 0) > 0:
        observations.append("Contains the '@' symbol, which can mislead users about the actual destination server.")

    if features.get("is_shortened", 0) > 0:
        observations.append("Uses a known URL shortening service, masking the final target destination.")

    if features.get("suspicious_tld", 0) > 0:
        observations.append("Uses a top-level domain (TLD) historically associated with elevated spam and phishing rates.")

    if features.get("has_sensitive_keywords", 0) >= 2:
        observations.append("Contains multiple high-value authentication/banking keywords (e.g., login, verify, secure).")
    elif features.get("has_sensitive_keywords", 0) == 1:
        observations.append("Contains an authentication-related keyword commonly targeted by credential harvesters.")

    if features.get("subdomain_count", 0) >= 3:
        observations.append("Contains an unusually deep subdomain hierarchy (common in brand-impersonation URLs).")

    if features.get("qty_hyphen_hostname", 0) >= 2:
        observations.append("Contains multiple hyphens in the hostname, often used for deceptive typosquatting.")

    if features.get("length_url", 0) > 120:
        observations.append("The overall URL is unusually long, frequently seen in obfuscated malicious redirect links.")

    if features.get("ratio_digits_url", 0) > 0.25:
        observations.append("High proportion of numerical digits in the URL, indicating possible randomized tokens.")

    if features.get("entropy_hostname", 0) > 4.2:
        observations.append("High character entropy in hostname, suggesting algorithmically generated or randomized naming.")

    if not observations:
        observations.append("URL structure is standard with no suspicious obfuscation or lexical anomalies detected.")

    return observations
