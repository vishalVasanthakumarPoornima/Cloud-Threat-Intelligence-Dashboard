from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.schemas.results import AnalysisResponse
from app.services.result_store import get_result

router = APIRouter()


@router.get("/results/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis_result(analysis_id: UUID):
    result = get_result(analysis_id)
    if result:
        return result
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Analysis {analysis_id} is not available yet.",
    )
