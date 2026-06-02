import asyncio
import unittest
from unittest.mock import patch

from app.core.config import Settings
from app.schemas.active_scan import NmapPortResult, NmapScanRequest
from app.services.classifier import ClassifiedIOC
from app.services.nmap_scan import (
    FALLBACK_PRESET_ARGS,
    build_nmap_command,
    fallback_tcp_ports,
    parse_nmap_xml,
    run_nmap_scan,
    should_use_sudo,
)


SAMPLE_NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.25.0">
          <cpe>cpe:/a:nginx:nginx:1.25.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="92"/>
      <osmatch name="FreeBSD" accuracy="80"/>
    </os>
  </host>
</nmaprun>
"""


class NmapScanTests(unittest.TestCase):
    def test_build_nmap_command_uses_fixed_preset_args(self):
        command = build_nmap_command(
            nmap_path="/usr/bin/nmap",
            preset="service_detection",
            target="example.com",
            timeout_seconds=45,
        )

        self.assertEqual(command[0], "/usr/bin/nmap")
        self.assertIn("-sV", command)
        self.assertIn("--version-light", command)
        self.assertIn("-oX", command)
        self.assertEqual(command[-1], "example.com")

    def test_build_nmap_command_can_wrap_privileged_scan_in_sudo(self):
        command = build_nmap_command(
            nmap_path="/opt/homebrew/bin/nmap",
            preset="os_detection",
            target="example.com",
            timeout_seconds=45,
            use_sudo=True,
            sudo_path="/usr/bin/sudo",
        )

        self.assertEqual(command[:3], ["/usr/bin/sudo", "-n", "/opt/homebrew/bin/nmap"])
        self.assertIn("-O", command)
        self.assertEqual(command[-1], "example.com")

    def test_should_use_sudo_only_for_privileged_presets(self):
        settings = Settings(NMAP_USE_SUDO="true")

        self.assertTrue(should_use_sudo("os_detection", settings=settings))
        self.assertTrue(should_use_sudo("stealth_syn", settings=settings))
        self.assertFalse(should_use_sudo("service_detection", settings=settings))

    def test_fallback_command_uses_unprivileged_scan_args(self):
        command = build_nmap_command(
            nmap_path="/opt/homebrew/bin/nmap",
            preset="stealth_syn",
            target="example.com",
            timeout_seconds=45,
            args=FALLBACK_PRESET_ARGS["stealth_syn"],
        )

        self.assertNotIn("-sS", command)
        self.assertIn("-sT", command)
        self.assertEqual(command[0], "/opt/homebrew/bin/nmap")

    def test_parse_nmap_xml_keeps_open_ports_and_os_matches(self):
        ports, os_matches = parse_nmap_xml(SAMPLE_NMAP_XML)

        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].port, 80)
        self.assertEqual(ports[0].service_name, "http")
        self.assertEqual(ports[0].product, "nginx")
        self.assertEqual(ports[0].cpes, ["cpe:/a:nginx:nginx:1.25.0"])
        self.assertEqual(os_matches[0].name, "Linux 5.x")
        self.assertEqual(os_matches[0].accuracy, 92)

    def test_fallback_tcp_ports_prioritizes_common_ports(self):
        ports = fallback_tcp_ports("quick_ports")

        self.assertEqual(len(ports), 100)
        self.assertEqual(ports[:3], (80, 443, 22))

    def test_missing_nmap_uses_tcp_fallback(self):
        async def fake_probe(*, target, port, semaphore):
            if port == 443:
                return NmapPortResult(
                    port=443,
                    protocol="tcp",
                    state="open",
                    reason="tcp-connect",
                    service_name="https",
                    cpes=[],
                )
            return None

        request = NmapScanRequest(
            target="93.184.216.34",
            preset="quick_ports",
            confirmed_authorized=True,
            timeout_seconds=10,
        )
        classified = ClassifiedIOC("ip", "93.184.216.34", "93.184.216.34")

        with patch("app.services.nmap_scan.shutil.which", return_value=None), patch(
            "app.services.nmap_scan._probe_tcp_port",
            side_effect=fake_probe,
        ):
            response = asyncio.run(
                run_nmap_scan(
                    request=request,
                    classified=classified,
                    settings=Settings(NMAP_PATH=""),
                )
            )

        self.assertEqual(response.status, "completed")
        self.assertEqual(response.command[0], "python-tcp-connect")
        self.assertEqual(response.ports[0].port, 443)
        self.assertIn("Nmap is not installed", response.warnings[0])


if __name__ == "__main__":
    unittest.main()
