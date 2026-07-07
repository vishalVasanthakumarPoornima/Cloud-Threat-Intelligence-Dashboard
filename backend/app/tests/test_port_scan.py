import asyncio
import unittest
from unittest.mock import patch

from app.schemas.active_scan import PortScanPortResult, PortScanRequest
from app.services.classifier import ClassifiedIOC
from app.services.port_scan import run_port_scan, scan_ports_for_preset


class PortScanTests(unittest.TestCase):
    def test_scan_ports_for_preset_prioritizes_common_ports(self):
        ports = scan_ports_for_preset("quick_ports")

        self.assertEqual(len(ports), 100)
        self.assertEqual(ports[:3], (80, 443, 22))

    def test_run_port_scan_uses_python_tcp_connect(self):
        async def fake_probe(*, target, port, semaphore, capture_banner):
            if port == 443:
                return PortScanPortResult(
                    port=443,
                    protocol="tcp",
                    state="open",
                    reason="tcp-connect",
                    service_name="https",
                    cpes=[],
                )
            return None

        request = PortScanRequest(
            target="93.184.216.34",
            preset="quick_ports",
            confirmed_authorized=True,
            timeout_seconds=10,
        )
        classified = ClassifiedIOC("ip", "93.184.216.34", "93.184.216.34")

        with patch("app.services.port_scan._probe_tcp_port", side_effect=fake_probe):
            response = asyncio.run(run_port_scan(request=request, classified=classified))

        self.assertEqual(response.status, "completed")
        self.assertEqual(response.command[:3], ["python-port-scan", "--mode", "tcp-connect"])
        self.assertEqual(response.ports[0].port, 443)
        self.assertIn("directly from the backend", response.warnings[0])

    def test_stealth_syn_falls_back_when_scapy_is_unavailable(self):
        async def fake_probe(*, target, port, semaphore, capture_banner):
            return None

        request = PortScanRequest(
            target="93.184.216.34",
            preset="stealth_syn",
            confirmed_authorized=True,
            timeout_seconds=10,
        )
        classified = ClassifiedIOC("ip", "93.184.216.34", "93.184.216.34")

        with patch("app.services.port_scan._load_scapy_tools", return_value=({}, "missing")), patch(
            "app.services.port_scan._probe_tcp_port",
            side_effect=fake_probe,
        ):
            response = asyncio.run(run_port_scan(request=request, classified=classified))

        self.assertEqual(response.command[:3], ["python-port-scan", "--mode", "tcp-connect"])
        self.assertTrue(any("fell back to TCP connect" in warning for warning in response.warnings))


if __name__ == "__main__":
    unittest.main()
