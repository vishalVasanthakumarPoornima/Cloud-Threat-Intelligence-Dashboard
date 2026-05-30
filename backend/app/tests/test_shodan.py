import unittest
from types import SimpleNamespace

import httpx

from app.connectors.shodan import analyze
from app.services.classifier import ClassifiedIOC


class MembershipThenInternetDBClient:
    def __init__(self, internetdb_status_code=200, internetdb_payload=None):
        self.urls = []
        self.internetdb_status_code = internetdb_status_code
        self.internetdb_payload = internetdb_payload or {
            "ip": "194.238.24.137",
            "ports": [22, 80, 443],
            "cpes": ["cpe:/a:openbsd:openssh"],
            "hostnames": ["sample.example"],
            "tags": ["self-signed"],
            "vulns": ["CVE-2017-15906"],
        }

    async def get(self, url, **kwargs):
        self.urls.append(url)
        request = httpx.Request("GET", url)
        if "api.shodan.io" in url:
            return httpx.Response(
                status_code=403,
                json={"error": "Requires membership or higher to access"},
                request=request,
            )
        if self.internetdb_status_code == 404:
            return httpx.Response(
                status_code=404,
                json={"detail": "No information available"},
                request=request,
            )
        return httpx.Response(status_code=200, json=self.internetdb_payload, request=request)


class ShodanConnectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_membership_403_falls_back_to_internetdb(self):
        client = MembershipThenInternetDBClient()
        result = await analyze(
            ClassifiedIOC(
                input_type="ip",
                submitted_value="194.238.24.137",
                normalized_value="194.238.24.137",
            ),
            SimpleNamespace(shodan_api_key="test-key"),
            client,
        )

        self.assertEqual(result.source_name, "Shodan")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.normalized["api_mode"], "internetdb")
        self.assertEqual(result.normalized["ports"], [22, 80, 443])
        self.assertEqual(result.normalized["vulnerability_count"], 1)
        self.assertEqual(len(client.urls), 2)

    async def test_membership_403_and_internetdb_404_returns_no_data_success(self):
        client = MembershipThenInternetDBClient(internetdb_status_code=404)
        result = await analyze(
            ClassifiedIOC(
                input_type="ip",
                submitted_value="150.9.86.37",
                normalized_value="150.9.86.37",
            ),
            SimpleNamespace(shodan_api_key="test-key"),
            client,
        )

        self.assertEqual(result.source_name, "Shodan")
        self.assertEqual(result.status, "success")
        self.assertEqual(result.normalized["api_mode"], "internetdb")
        self.assertFalse(result.normalized["data_available"])
        self.assertEqual(result.normalized["ports"], [])
        self.assertEqual(result.normalized["vulnerability_count"], 0)
        self.assertIsNone(result.error_message)


if __name__ == "__main__":
    unittest.main()
