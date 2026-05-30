import unittest

from app.core.config import Settings
from app.services.nmap_scan import FALLBACK_PRESET_ARGS, build_nmap_command, parse_nmap_xml, should_use_sudo


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


if __name__ == "__main__":
    unittest.main()
