from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response

from app.schemas.results import AnalysisResponse
from app.services.result_store import get_result
from app.services.pdf_report import build_analysis_report_pdf, report_filename

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


@router.get("/results/{analysis_id}/report.pdf")
async def download_analysis_report(analysis_id: UUID):
    result = get_result(analysis_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} is not available yet.",
        )

    pdf = build_analysis_report_pdf(result)
    filename = report_filename(result)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
