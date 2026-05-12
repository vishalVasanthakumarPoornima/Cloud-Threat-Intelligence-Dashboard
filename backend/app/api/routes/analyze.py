from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status

from app.core.config import SettingsDep
from app.schemas.ioc import AnalyzeRequest
from app.services.classifier import IOCValidationError, classify_ioc
from app.services.orchestrator import analyze_file_upload, analyze_indicator

router = APIRouter()


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED)
async def analyze(
    payload: AnalyzeRequest,
    request: Request,
    settings: SettingsDep,
):
    """Validate and classify an IOC before any cache, database, or API work."""
    try:
        classified = classify_ioc(
            payload.ioc,
            allow_private=settings.allow_private_iocs,
        )
    except IOCValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid indicator of compromise.",
        ) from exc

    return await analyze_indicator(
        classified=classified,
        settings=settings,
        client_ip=request.client.host if request.client else None,
    )


@router.post("/analyze/file", status_code=status.HTTP_202_ACCEPTED)
async def analyze_file(
    request: Request,
    settings: SettingsDep,
    file: UploadFile = File(...),
):
    data = await file.read(settings.max_upload_file_bytes + 1)
    await file.close()

    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    if len(data) > settings.max_upload_file_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds {settings.max_upload_file_bytes} bytes.",
        )

    return await analyze_file_upload(
        filename=file.filename or "upload.bin",
        content_type=file.content_type,
        data=data,
        settings=settings,
        client_ip=request.client.host if request.client else None,
    )
