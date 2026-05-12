from app.connectors.base import ConnectorDefinition
from app.connectors.base import get_json
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

ABUSEIPDB = ConnectorDefinition(
    name="AbuseIPDB",
    slug="abuseipdb",
    secret_name="ABUSEIPDB_API_KEY",
    supported_ioc_types=frozenset({"ip"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    payload = await get_json(
        client,
        ABUSEIPDB.name,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Accept": "application/json", "Key": settings.abuseipdb_api_key or ""},
        params={
            "ipAddress": classified.normalized_value,
            "maxAgeInDays": "90",
            "verbose": "",
        },
    )
    data = payload.get("data", {})
    normalized = {
        "ip_address": data.get("ipAddress"),
        "abuse_confidence_score": int(data.get("abuseConfidenceScore") or 0),
        "report_count": int(data.get("totalReports") or 0),
        "usage_type": data.get("usageType"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "is_tor": data.get("isTor"),
        "last_reported_at": data.get("lastReportedAt"),
    }
    return SourceResult(source_name=ABUSEIPDB.name, status="success", normalized=normalized)
