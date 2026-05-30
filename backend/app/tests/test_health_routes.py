import unittest

from fastapi.testclient import TestClient

from app.main import app


class HealthRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_status_returns_ok_for_render(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["health"], "/api/health")

    def test_api_health_returns_ok(self):
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
