from app.connectors.base import ConnectorDefinition
from app.connectors.base import compact_dict, get_json
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

IPINFO = ConnectorDefinition(
    name="IPinfo",
    slug="ipinfo",
    secret_name="IPINFO_TOKEN",
    supported_ioc_types=frozenset({"ip"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    payload = await _get_ipinfo_payload(classified, settings, client)
    geo = payload.get("geo") if isinstance(payload.get("geo"), dict) else payload
    asn = payload.get("as") if isinstance(payload.get("as"), dict) else {}
    if not asn and isinstance(payload.get("asn"), dict):
        asn = payload.get("asn") or {}
    org = payload.get("org")
    if org and not asn:
        asn = {"name": org}
    privacy_flags = [
        key
        for key in ("is_anonymous", "is_anycast", "is_hosting", "is_mobile", "is_satellite")
        if payload.get(key) is True
    ]
    normalized = {
        "ip": payload.get("ip"),
        "city": geo.get("city"),
        "region": geo.get("region"),
        "country": geo.get("country") or geo.get("country_code"),
        "timezone": geo.get("timezone"),
        "asn": compact_dict(asn, ["asn", "name", "domain", "type"]),
        "privacy_flags": privacy_flags,
    }
    return SourceResult(source_name=IPINFO.name, status="success", normalized=normalized)


async def _get_ipinfo_payload(classified: ClassifiedIOC, settings, client):
    response = await client.get(
        f"https://api.ipinfo.io/lookup/{classified.normalized_value}",
        params={"token": settings.ipinfo_token},
    )
    if response.status_code != 403:
        response.raise_for_status()
        return response.json()

    fallback = await client.get(
        f"https://ipinfo.io/{classified.normalized_value}/json",
        params={"token": settings.ipinfo_token},
    )
    fallback.raise_for_status()
    return fallback.json()
