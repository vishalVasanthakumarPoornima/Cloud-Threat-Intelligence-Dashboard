import base64
import hashlib
from pathlib import PurePath

from app.connectors.base import ConnectorDefinition
from app.connectors.base import ConnectorHTTPError, compact_list, get_json, get_nested, parse_json_response
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

VIRUSTOTAL = ConnectorDefinition(
    name="VirusTotal",
    slug="virustotal",
    secret_name="VIRUSTOTAL_API_KEY",
    supported_ioc_types=frozenset({"ip", "domain", "url", "hash"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    payload = await get_json(
        client,
        VIRUSTOTAL.name,
        _virustotal_url(classified),
        headers={"x-apikey": settings.virustotal_api_key or ""},
    )
    attributes = get_nested(payload, "data", "attributes", default={}) or {}
    stats = attributes.get("last_analysis_stats") or {}
    categories = attributes.get("categories") or {}
    tags = attributes.get("tags") or []
    normalized = {
        "malicious_detections": int(stats.get("malicious") or 0),
        "suspicious_detections": int(stats.get("suspicious") or 0),
        "harmless_detections": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "reputation": attributes.get("reputation"),
        "categories": compact_list(list(categories.values()) if isinstance(categories, dict) else [], limit=8),
        "tags": compact_list(tags if isinstance(tags, list) else [], limit=8),
        "threat_label": get_nested(attributes, "popular_threat_classification", "suggested_threat_label"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }
    return SourceResult(source_name=VIRUSTOTAL.name, status="success", normalized=normalized)


async def analyze_uploaded_file(
    *,
    filename: str,
    content_type: str | None,
    data: bytes,
    settings,
    client,
) -> tuple[SourceResult, str, str]:
    safe_name = _safe_filename(filename)
    sha256 = hashlib.sha256(data).hexdigest()
    if not settings.virustotal_api_key:
        return (
            SourceResult(
                source_name=VIRUSTOTAL.name,
                status="not_configured",
                normalized={
                    "filename": safe_name,
                    "sha256": sha256,
                    "size_bytes": len(data),
                    "submission_status": "not_configured",
                },
                error_message="VirusTotal API key is not configured on the backend.",
            ),
            sha256,
            safe_name,
        )

    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        payload = await get_json(
            client,
            VIRUSTOTAL.name,
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
        )
        return (
            SourceResult(
                source_name=VIRUSTOTAL.name,
                status="success",
                normalized=_normalize_file_report(
                    payload,
                    filename=safe_name,
                    sha256=sha256,
                    size_bytes=len(data),
                    submission_status="existing_report",
                ),
            ),
            sha256,
            safe_name,
        )
    except ConnectorHTTPError as exc:
        if exc.status_code != 404:
            raise

    response = await client.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files={"file": (safe_name, data, content_type or "application/octet-stream")},
    )
    payload = parse_json_response(VIRUSTOTAL.name, response)
    analysis_id = get_nested(payload, "data", "id")
    return (
        SourceResult(
            source_name=VIRUSTOTAL.name,
            status="partial",
            normalized={
                "filename": safe_name,
                "sha256": sha256,
                "size_bytes": len(data),
                "submission_status": "submitted",
                "analysis_id": analysis_id,
                "message": "File submitted to VirusTotal; analysis may still be pending.",
            },
        ),
        sha256,
        safe_name,
    )


def _virustotal_url(classified: ClassifiedIOC) -> str:
    base = "https://www.virustotal.com/api/v3"
    if classified.input_type == "ip":
        return f"{base}/ip_addresses/{classified.normalized_value}"
    if classified.input_type == "domain":
        return f"{base}/domains/{classified.normalized_value}"
    if classified.input_type == "hash":
        return f"{base}/files/{classified.normalized_value}"
    encoded = base64.urlsafe_b64encode(classified.normalized_value.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{base}/urls/{encoded}"


def _normalize_file_report(
    payload: dict,
    *,
    filename: str,
    sha256: str,
    size_bytes: int,
    submission_status: str,
) -> dict:
    attributes = get_nested(payload, "data", "attributes", default={}) or {}
    stats = attributes.get("last_analysis_stats") or {}
    names = attributes.get("names") if isinstance(attributes.get("names"), list) else []
    tags = attributes.get("tags") if isinstance(attributes.get("tags"), list) else []
    return {
        "filename": filename,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "submission_status": submission_status,
        "malicious_detections": int(stats.get("malicious") or 0),
        "suspicious_detections": int(stats.get("suspicious") or 0),
        "harmless_detections": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "type_description": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"),
        "names": compact_list(names, limit=5),
        "tags": compact_list(tags, limit=8),
        "threat_label": get_nested(attributes, "popular_threat_classification", "suggested_threat_label"),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def _safe_filename(filename: str | None) -> str:
    name = PurePath(filename or "upload.bin").name.strip()
    if not name or any(ord(char) < 32 for char in name):
        return "upload.bin"
    return name[:180]
