"""
Unit tests for URL normalization and feature extraction engine.
"""

import unittest
from feature_extractor import (
    FEATURE_NAMES,
    normalize_url,
    extract_features,
    extract_feature_vector,
    explain_features,
    calculate_entropy,
)


class TestFeatureExtractor(unittest.TestCase):

    def test_normalize_url_with_protocols(self):
        self.assertEqual(normalize_url("https://example.com"), "https://example.com/")
        self.assertEqual(normalize_url("http://example.com/login"), "http://example.com/login")
        self.assertEqual(normalize_url("https://sub.domain.org/path?q=1"), "https://sub.domain.org/path?q=1")

    def test_normalize_url_without_protocol(self):
        self.assertEqual(normalize_url("example.com"), "http://example.com/")
        self.assertEqual(normalize_url("www.example.com"), "http://example.com/")
        self.assertEqual(normalize_url("example.com/secure/login"), "http://example.com/secure/login")

    def test_normalize_url_with_whitespace_and_wrappers(self):
        self.assertEqual(normalize_url("   https://example.com/  "), "https://example.com/")
        self.assertEqual(normalize_url("<https://example.com>"), "https://example.com/")
        self.assertEqual(normalize_url('"example.com"'), "http://example.com/")

    def test_normalize_url_invalid_inputs(self):
        with self.assertRaises(ValueError):
            normalize_url("")
        with self.assertRaises(ValueError):
            normalize_url("   ")
        with self.assertRaises(ValueError):
            normalize_url(None)
        with self.assertRaises(ValueError):
            normalize_url("http://   ")

    def test_feature_vector_dimension_and_keys(self):
        url = "https://example.com/path"
        feat_dict = extract_features(url)
        feat_vec = extract_feature_vector(url)

        self.assertEqual(len(FEATURE_NAMES), 26)
        self.assertEqual(len(feat_dict), 26)
        self.assertEqual(len(feat_vec), 26)

        for name in FEATURE_NAMES:
            self.assertIn(name, feat_dict)
            self.assertIsInstance(feat_dict[name], float)

    def test_ip_address_detection(self):
        ip_url = normalize_url("http://192.168.1.1/admin/login")
        domain_url = normalize_url("https://secure.bank.com/login")

        feat_ip = extract_features(ip_url)
        feat_domain = extract_features(domain_url)

        self.assertEqual(feat_ip["has_ip_address"], 1.0)
        self.assertEqual(feat_domain["has_ip_address"], 0.0)

    def test_url_shortener_detection(self):
        short_url = normalize_url("http://bit.ly/3xY89")
        normal_url = normalize_url("https://github.com/project")

        self.assertEqual(extract_features(short_url)["is_shortened"], 1.0)
        self.assertEqual(extract_features(normal_url)["is_shortened"], 0.0)

    def test_suspicious_tld_detection(self):
        tld_url = normalize_url("http://verify-account.xyz/update")
        normal_url = normalize_url("https://stanford.edu/research")

        self.assertEqual(extract_features(tld_url)["suspicious_tld"], 1.0)
        self.assertEqual(extract_features(normal_url)["suspicious_tld"], 0.0)

    def test_sensitive_keywords(self):
        kw_url = normalize_url("https://mybank.com/secure/login/verify-account")
        feat = extract_features(kw_url)
        self.assertGreaterEqual(feat["has_sensitive_keywords"], 3.0)

    def test_entropy_computation(self):
        ent_low = calculate_entropy("aaaaaaa")
        ent_high = calculate_entropy("a8!d9#b1$z_9")
        self.assertEqual(ent_low, 0.0)
        self.assertGreater(ent_high, 2.5)

    def test_explain_features_output(self):
        url = normalize_url("http://192.168.1.100/paypal/login/verify.php?token=123")
        feat = extract_features(url)
        explanations = explain_features(feat, 0.95)
        self.assertIsInstance(explanations, list)
        self.assertGreater(len(explanations), 0)
        # Should detect IP address and keywords
        joined = " ".join(explanations).lower()
        self.assertIn("ip address", joined)


if __name__ == "__main__":
    unittest.main()
