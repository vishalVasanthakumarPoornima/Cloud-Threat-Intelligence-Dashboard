from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase

import httpx

from app.connectors.virustotal import analyze_uploaded_file


class FakeClient:
    def __init__(self, get_response: httpx.Response):
        self.get_response = get_response
        self.post_called = False

    async def get(self, *args, **kwargs):
        return self.get_response

    async def post(self, *args, **kwargs):
        self.post_called = True
        return httpx.Response(200, json={"data": {"id": "analysis-id"}})


class VirusTotalFileUploadTests(IsolatedAsyncioTestCase):
    async def test_existing_report_uses_hash_lookup_without_uploading(self):
        client = FakeClient(
            httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 1, "suspicious": 2, "harmless": 10},
                            "type_description": "ASCII text",
                        }
                    }
                },
            )
        )

        result, sha256, filename = await analyze_uploaded_file(
            filename="../sample.txt",
            content_type="text/plain",
            data=b"sample",
            settings=SimpleNamespace(virustotal_api_key="vt-key"),
            client=client,
        )

        self.assertFalse(client.post_called)
        self.assertEqual(filename, "sample.txt")
        self.assertEqual(len(sha256), 64)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.normalized["submission_status"], "existing_report")
        self.assertEqual(result.normalized["malicious_detections"], 1)

    async def test_missing_report_uploads_opaque_bytes(self):
        client = FakeClient(httpx.Response(404, json={"error": {"message": "Not found"}}))

        result, sha256, filename = await analyze_uploaded_file(
            filename="archive.zip",
            content_type="application/zip",
            data=b"not really a zip",
            settings=SimpleNamespace(virustotal_api_key="vt-key"),
            client=client,
        )

        self.assertTrue(client.post_called)
        self.assertEqual(filename, "archive.zip")
        self.assertEqual(len(sha256), 64)
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.normalized["submission_status"], "submitted")

    async def test_missing_key_hashes_without_uploading(self):
        client = FakeClient(httpx.Response(200, json={}))

        result, sha256, filename = await analyze_uploaded_file(
            filename="sample.bin",
            content_type=None,
            data=b"sample",
            settings=SimpleNamespace(virustotal_api_key=""),
            client=client,
        )

        self.assertFalse(client.post_called)
        self.assertEqual(filename, "sample.bin")
        self.assertEqual(len(sha256), 64)
        self.assertEqual(result.status, "not_configured")
