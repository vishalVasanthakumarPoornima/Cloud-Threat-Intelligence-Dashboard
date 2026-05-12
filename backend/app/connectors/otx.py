import ipaddress
from urllib.parse import quote

from app.connectors.base import ConnectorDefinition
from app.connectors.base import compact_list, get_json, get_nested
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

OTX = ConnectorDefinition(
    name="AlienVault OTX",
    slug="otx",
    secret_name="OTX_API_KEY",
    supported_ioc_types=frozenset({"ip", "domain", "url", "hash"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    indicator_type, indicator = _otx_indicator(classified)
    payload = await get_json(
        client,
        OTX.name,
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
        headers={"X-OTX-API-KEY": settings.otx_api_key or ""},
    )
    pulses = get_nested(payload, "pulse_info", "pulses", default=[]) or []
    tags = []
    references = []
    malware_families = []
    for pulse in pulses:
        tags.extend(pulse.get("tags") or [])
        references.extend(pulse.get("references") or [])
        malware_families.extend(pulse.get("malware_families") or [])

    normalized = {
        "indicator": payload.get("indicator"),
        "type": payload.get("type"),
        "pulse_count": int(get_nested(payload, "pulse_info", "count", default=0) or 0),
        "reputation": payload.get("reputation"),
        "tags": compact_list(tags, limit=10),
        "references": compact_list(references, limit=5),
        "malware_families": compact_list(malware_families, limit=8),
        "malware_tag_count": len(compact_list(malware_families + tags, limit=20)),
    }
    return SourceResult(source_name=OTX.name, status="success", normalized=normalized)


def _otx_indicator(classified: ClassifiedIOC) -> tuple[str, str]:
    if classified.input_type == "ip":
        ip = ipaddress.ip_address(classified.normalized_value)
        return ("IPv6" if ip.version == 6 else "IPv4", classified.normalized_value)
    if classified.input_type == "domain":
        return "domain", classified.normalized_value
    if classified.input_type == "url":
        return "url", quote(classified.normalized_value, safe="")
    return "file", classified.normalized_value
