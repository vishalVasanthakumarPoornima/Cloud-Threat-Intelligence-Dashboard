from datetime import datetime, timezone
from unittest import TestCase
from uuid import uuid4

from app.schemas.results import AnalysisResponse, IOCDetails, RiskReport
from app.services.result_store import get_result, save_result


class ResultStoreTests(TestCase):
    def test_save_and_get_result_round_trip(self):
        analysis_id = uuid4()
        result = AnalysisResponse(
            analysis_id=analysis_id,
            status="completed",
            created_at=datetime.now(timezone.utc),
            ioc=IOCDetails(
                input_type="ip",
                submitted_value="8.8.8.8",
                normalized_value="8.8.8.8",
            ),
            risk_report=RiskReport(
                score=0,
                severity="Low",
                summary="No elevated risk.",
                recommended_actions=[],
                contributions=[],
            ),
            source_results=[],
        )

        save_result(result)

        self.assertEqual(get_result(analysis_id), result)
        self.assertIsNone(get_result(uuid4()))
