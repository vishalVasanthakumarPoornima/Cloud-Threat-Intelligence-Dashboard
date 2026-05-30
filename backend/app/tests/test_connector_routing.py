import unittest
from types import SimpleNamespace

from app.connectors import CONNECTOR_DEFINITIONS
from app.connectors.shodan import analyze as analyze_shodan
from app.services.classifier import ClassifiedIOC


class NoNetworkClient:
    async def get(self, *args, **kwargs):
        raise AssertionError("Unsupported IOC should not trigger GET requests.")

    async def post(self, *args, **kwargs):
        raise AssertionError("Unsupported IOC should not trigger POST requests.")


class ConnectorRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_url_inputs_are_not_routed_to_shodan(self):
        url_connectors = {
            definition.name
            for definition in CONNECTOR_DEFINITIONS
            if "url" in definition.supported_ioc_types
        }

        self.assertNotIn("Shodan", url_connectors)

    def test_ip_and_domain_inputs_are_routed_to_shodan(self):
        ip_connectors = {
            definition.name
            for definition in CONNECTOR_DEFINITIONS
            if "ip" in definition.supported_ioc_types
        }
        domain_connectors = {
            definition.name
            for definition in CONNECTOR_DEFINITIONS
            if "domain" in definition.supported_ioc_types
        }

        self.assertIn("Shodan", ip_connectors)
        self.assertIn("Shodan", domain_connectors)

    async def test_shodan_skips_urls_without_network_call(self):
        result = await analyze_shodan(
            ClassifiedIOC(
                input_type="url",
                submitted_value="https://example.com/login",
                normalized_value="https://example.com/login",
            ),
            SimpleNamespace(shodan_api_key="test-key"),
            NoNetworkClient(),
        )

        self.assertEqual(result.source_name, "Shodan")
        self.assertEqual(result.status, "not_applicable")

if __name__ == "__main__":
    unittest.main()
