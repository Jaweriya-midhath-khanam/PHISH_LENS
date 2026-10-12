"""
Unit tests for PhisLens Flask REST API endpoints.
Tests /api/health, /api/stats, /api/scan, error cases, and edge cases.
"""

import json
import unittest
from app import app, MODEL_LOADED


class TestPhisLensAPI(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])
        self.assertEqual(data["feature_count"], 26)

    def test_stats_endpoint(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        metrics = data["metrics"]
        self.assertIn("accuracy", metrics)
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)
        self.assertIn("f1_score", metrics)
        self.assertIn("confusion_matrix", metrics)

    def test_scan_legitimate_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "https://www.wikipedia.org/wiki/Computer_security"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("prediction", data)
        self.assertIn(data["prediction"]["class"], ["legitimate", "suspicious", "phishing"])
        self.assertIn(data["prediction"]["color"], ["green", "yellow", "red"])
        self.assertGreaterEqual(data["prediction"]["confidence_percent"], 0.0)
        self.assertLessEqual(data["prediction"]["confidence_percent"], 100.0)
        self.assertIsInstance(data["explanations"], list)
        self.assertIn("safety_warning", data)

    def test_scan_bare_domain(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "github.com"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["url"]["hostname"], "github.com")

    def test_scan_suspicious_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "http://192.168.1.100/paypal-verification/login.php?update=1"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        # Ensure IP was detected in features
        self.assertTrue(data["features_summary"]["has_ip_address"])
        self.assertGreater(data["features_summary"]["has_sensitive_keywords"], 0)

    def test_scan_missing_url(self):
        response = self.client.post(
            "/api/scan",
            json={},
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("url", data["error"].lower())

    def test_scan_empty_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "   "},
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")

    def test_scan_non_string_url(self):
        response = self.client.post(
            "/api/scan",
            json={"url": 12345},
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")

    def test_scan_non_json_request(self):
        response = self.client.post(
            "/api/scan",
            data="not a json string",
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")

    def test_scan_invalid_url_structure(self):
        response = self.client.post(
            "/api/scan",
            json={"url": "http://  invalid domain with spaces  "},
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")


if __name__ == "__main__":
    unittest.main()
