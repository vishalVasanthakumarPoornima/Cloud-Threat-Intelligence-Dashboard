import hashlib
import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from app.connectors import CONNECTOR_DEFINITIONS, CONNECTOR_HANDLERS
from app.connectors.base import source_failure
from app.connectors.virustotal import analyze_uploaded_file
from app.core.config import Settings
from app.schemas.results import AnalysisResponse, IOCDetails, SourceResult
from app.services.ai_summary import build_analyst_summary
from app.services.classifier import ClassifiedIOC
from app.services.result_store import save_result
from app.services.risk_engine import calculate_risk


async def analyze_indicator(
    *,
    classified: ClassifiedIOC,
    settings: Settings,
    client_ip: str | None,
) -> AnalysisResponse:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.connector_timeout_seconds),
        headers={"User-Agent": "cloud-threat-intelligence-dashboard/0.1"},
        follow_redirects=True,
    ) as client:
        gathered_results = await asyncio.gather(
            *[
                _run_connector(definition, classified, settings, client)
                for definition in CONNECTOR_DEFINITIONS
                if classified.input_type in definition.supported_ioc_types
            ]
        )
        source_results = [
            result
            for result in gathered_results
            if result.status != "not_applicable"
        ]
        risk_report = calculate_risk(source_results)
        risk_report.summary = await build_analyst_summary(
            classified=classified,
            risk_report=risk_report,
            source_results=source_results,
            settings=settings,
            client=client,
        )

    if client_ip:
        _hash_client_ip(client_ip)

    response = AnalysisResponse(
        analysis_id=uuid4(),
        status="partial" if any(result.status == "failed" for result in source_results) else "completed",
        created_at=datetime.now(timezone.utc),
        ioc=IOCDetails(
            input_type=classified.input_type,
            submitted_value=classified.submitted_value,
            normalized_value=classified.normalized_value,
        ),
        risk_report=risk_report,
        source_results=source_results,
    )
    save_result(response)
    return response


async def analyze_file_upload(
    *,
    filename: str,
    content_type: str | None,
    data: bytes,
    settings: Settings,
    client_ip: str | None,
) -> AnalysisResponse:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.connector_timeout_seconds),
        headers={"User-Agent": "cloud-threat-intelligence-dashboard/0.1"},
        follow_redirects=True,
    ) as client:
        try:
            source_result, sha256, safe_name = await analyze_uploaded_file(
                filename=filename,
                content_type=content_type,
                data=data,
                settings=settings,
                client=client,
            )
        except Exception as exc:
            sha256 = hashlib.sha256(data).hexdigest()
            safe_name = filename or "upload.bin"
            source_result = source_failure("VirusTotal", exc)

        risk_report = calculate_risk([source_result])
        risk_report.summary = _file_summary(
            filename=safe_name,
            sha256=sha256,
            risk_report=risk_report,
            source_result=source_result,
        )

    if client_ip:
        _hash_client_ip(client_ip)

    response = AnalysisResponse(
        analysis_id=uuid4(),
        status="completed" if source_result.status == "success" else "partial",
        created_at=datetime.now(timezone.utc),
        ioc=IOCDetails(
            input_type="file",
            submitted_value=safe_name,
            normalized_value=sha256,
        ),
        risk_report=risk_report,
        source_results=[source_result],
    )
    save_result(response)
    return response


async def _run_connector(definition, classified: ClassifiedIOC, settings: Settings, client: httpx.AsyncClient) -> SourceResult:
    if not definition.is_configured(settings):
        return SourceResult(
            source_name=definition.name,
            status="not_configured",
            normalized={
                "ioc_type": classified.input_type,
                "connector": definition.slug,
            },
            error_message="API key is not configured on the backend.",
        )

    handler = CONNECTOR_HANDLERS[definition.slug]
    try:
        return await handler(classified, settings, client)
    except Exception as exc:
        return source_failure(definition.name, exc)


def _hash_client_ip(client_ip: str) -> str:
    return hashlib.sha256(client_ip.encode("utf-8")).hexdigest()


def _file_summary(*, filename: str, sha256: str, risk_report, source_result: SourceResult) -> str:
    short_hash = f"{sha256[:12]}..."
    if source_result.status == "success":
        return (
            f"{filename} was checked as an opaque file upload using SHA-256 {short_hash}. "
            f"VirusTotal evidence currently produces a {risk_report.severity.lower()} "
            f"risk rating with a score of {risk_report.score}."
        )
    if source_result.normalized.get("submission_status") == "submitted":
        return (
            f"{filename} was hashed as SHA-256 {short_hash} and submitted to VirusTotal. "
            "The file was handled as raw bytes only; no local execution, extraction, or archive inspection was performed. "
            "Recheck the SHA-256 after VirusTotal finishes processing."
        )
    return (
        f"{filename} was hashed as SHA-256 {short_hash}, but VirusTotal file analysis is not complete. "
        "The file was handled as raw bytes only and was not executed or unpacked locally."
    )
