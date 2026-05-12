import unittest

from app.services.classifier import IOCValidationError, classify_ioc


class ClassifierTests(unittest.TestCase):
    def test_public_ip(self):
        classified = classify_ioc("8.8.8.8")
        self.assertEqual(classified.input_type, "ip")
        self.assertEqual(classified.normalized_value, "8.8.8.8")

    def test_private_ip_rejected_by_default(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("10.0.0.1")

    def test_cloud_metadata_ip_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("169.254.169.254", allow_private=True)

    def test_domain_normalization(self):
        classified = classify_ioc("Example.COM.")
        self.assertEqual(classified.input_type, "domain")
        self.assertEqual(classified.normalized_value, "example.com")

    def test_localhost_domain_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("localhost")

    def test_url_normalization(self):
        classified = classify_ioc("HTTPS://Example.com/login#section")
        self.assertEqual(classified.input_type, "url")
        self.assertEqual(classified.normalized_value, "https://example.com/login")

    def test_url_with_private_ip_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("http://192.168.1.1/admin")

    def test_url_with_invalid_host_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("https://bad..example.com/path")

    def test_url_with_invalid_port_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("https://example.com:99999/path")

    def test_public_ipv6_url_normalization(self):
        classified = classify_ioc("https://[2606:4700:4700::1111]/dns-query")
        self.assertEqual(classified.input_type, "url")
        self.assertEqual(
            classified.normalized_value,
            "https://[2606:4700:4700::1111]/dns-query",
        )

    def test_hash_classification(self):
        classified = classify_ioc("44D88612FEA8A8F36DE82E1278ABB02F")
        self.assertEqual(classified.input_type, "hash")
        self.assertEqual(classified.normalized_value, "44d88612fea8a8f36de82e1278abb02f")

    def test_sql_payload_rejected(self):
        with self.assertRaises(IOCValidationError):
            classify_ioc("example.com'; DROP TABLE users; --")


if __name__ == "__main__":
    unittest.main()
