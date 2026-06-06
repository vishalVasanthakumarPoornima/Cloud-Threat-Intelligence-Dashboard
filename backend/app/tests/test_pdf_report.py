from datetime import datetime, timezone
import unittest
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.schemas.results import (
    AnalysisResponse,
    IOCDetails,
    RiskReport,
    ScoreContribution,
    SourceResult,
)
from app.services.pdf_report import build_analysis_report_pdf, report_filename
from app.services.result_store import save_result


class PdfReportTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_build_analysis_report_pdf_returns_pdf_bytes(self):
        result = _sample_analysis()

        pdf = build_analysis_report_pdf(result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertGreater(len(pdf), 5000)
        self.assertIn(b"Threat Intelligence Executive Report", pdf)

    def test_build_analysis_report_pdf_supports_zero_score(self):
        result = _sample_analysis(score=0, severity="Low")

        pdf = build_analysis_report_pdf(result)

        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"Low", pdf)

    def test_download_report_route_returns_attachment(self):
        result = _sample_analysis()
        save_result(result)

        response = self.client.get(f"/api/results/{result.analysis_id}/report.pdf")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertIn(report_filename(result), response.headers["content-disposition"])
        self.assertTrue(response.content.startswith(b"%PDF-"))

    def test_download_report_route_returns_404_for_missing_result(self):
        response = self.client.get(f"/api/results/{uuid4()}/report.pdf")

        self.assertEqual(response.status_code, 404)


def _sample_analysis(score: int = 62, severity: str = "High") -> AnalysisResponse:
    return AnalysisResponse(
        analysis_id=uuid4(),
        status="completed",
        created_at=datetime(2026, 6, 6, 18, 30, tzinfo=timezone.utc),
        ioc=IOCDetails(
            input_type="domain",
            submitted_value="Example.COM",
            normalized_value="example.com",
        ),
        risk_report=RiskReport(
            score=score,
            severity=severity,
            summary=(
                "Multiple configured intelligence providers returned signals that warrant "
                "security-team review before any allow-listing or business exception."
            ),
            recommended_actions=[
                "Escalate to incident response for review.",
                "Correlate with endpoint, DNS, proxy, and firewall logs.",
                "Block or monitor the indicator according to internal policy.",
            ],
            contributions=[
                ScoreContribution(
                    source_name="VirusTotal",
                    points=30,
                    reason="Source evidence contributed to the transparent risk score.",
                ),
                ScoreContribution(
                    source_name="AlienVault OTX",
                    points=12,
                    reason="Source evidence contributed to the transparent risk score.",
                ),
                ScoreContribution(
                    source_name="Shodan",
                    points=6,
                    reason="Source evidence contributed to the transparent risk score.",
                ),
            ],
        ),
        source_results=[
            SourceResult(
                source_name="VirusTotal",
                status="success",
                normalized={
                    "malicious_detections": 7,
                    "suspicious_detections": 1,
                    "reputation": -18,
                    "categories": ["malware", "phishing"],
                },
            ),
            SourceResult(
                source_name="AlienVault OTX",
                status="success",
                normalized={
                    "pulse_count": 4,
                    "malware_tag_count": 0,
                    "tags": ["botnet", "credential-theft"],
                },
            ),
            SourceResult(
                source_name="URLScan",
                status="not_configured",
                normalized={"ioc_type": "domain", "connector": "urlscan"},
                error_message="API key is not configured on the backend.",
            ),
        ],
    )


if __name__ == "__main__":
    unittest.main()
