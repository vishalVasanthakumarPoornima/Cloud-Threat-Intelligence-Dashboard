from app.connectors.base import ConnectorDefinition
from app.connectors.base import compact_list, count_risky_ports, get_json
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

SHODAN = ConnectorDefinition(
    name="Shodan",
    slug="shodan",
    secret_name="SHODAN_API_KEY",
    supported_ioc_types=frozenset({"ip", "domain"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    if classified.input_type == "ip":
        payload = await get_json(
            client,
            SHODAN.name,
            f"https://api.shodan.io/shodan/host/{classified.normalized_value}",
            params={"key": settings.shodan_api_key},
        )
        services = payload.get("data") or []
        ports = compact_list([item.get("port") for item in services if isinstance(item, dict)], limit=40)
        vulns = payload.get("vulns") or {}
        normalized = {
            "ip": payload.get("ip_str"),
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "asn": payload.get("asn"),
            "hostnames": compact_list(payload.get("hostnames") or [], limit=8),
            "ports": ports,
            "products": compact_list([item.get("product") for item in services if isinstance(item, dict)], limit=12),
            "vulnerability_count": len(vulns) if isinstance(vulns, dict) else 0,
            "vulnerabilities": compact_list(list(vulns.keys()) if isinstance(vulns, dict) else [], limit=10),
            "risky_service_count": count_risky_ports([int(port) for port in ports if isinstance(port, int)]),
        }
    else:
        payload = await get_json(
            client,
            SHODAN.name,
            f"https://api.shodan.io/dns/domain/{classified.normalized_value}",
            params={"key": settings.shodan_api_key},
        )
        subdomains = payload.get("subdomains") or []
        records = payload.get("data") or []
        normalized = {
            "domain": payload.get("domain") or classified.normalized_value,
            "subdomain_count": len(subdomains),
            "subdomains": compact_list(subdomains, limit=10),
            "record_count": len(records),
            "records": compact_list([record.get("value") for record in records if isinstance(record, dict)], limit=10),
            "risky_service_count": 0,
        }
    return SourceResult(source_name=SHODAN.name, status="success", normalized=normalized)
