from fastapi import APIRouter, HTTPException, status

from app.core.config import SettingsDep
from app.schemas.active_scan import PortScanRequest
from app.services.classifier import IOCValidationError, classify_ioc
from app.services.port_scan import run_port_scan

router = APIRouter()


@router.post("/active-scan/ports", status_code=status.HTTP_202_ACCEPTED)
async def port_scan(payload: PortScanRequest, settings: SettingsDep):
    return await _run_authorized_port_scan(payload=payload, settings=settings)


@router.post("/active-scan/nmap", status_code=status.HTTP_202_ACCEPTED)
async def nmap_scan(payload: PortScanRequest, settings: SettingsDep):
    return await _run_authorized_port_scan(payload=payload, settings=settings)


async def _run_authorized_port_scan(payload: PortScanRequest, settings: SettingsDep):
    if not payload.confirmed_authorized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm authorization before running an active scan.",
        )

    try:
        classified = classify_ioc(
            payload.target,
            allow_private=settings.allow_private_iocs,
        )
    except IOCValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active scans require a valid public IP address or domain.",
        ) from exc

    if classified.input_type not in {"ip", "domain"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Active scans only support IP addresses and domains.",
        )

    return await run_port_scan(
        request=payload,
        classified=classified,
    )
