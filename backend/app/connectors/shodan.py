from app.connectors.base import ConnectorDefinition, ConnectorHTTPError
from app.connectors.base import compact_list, count_risky_ports, get_json, source_not_applicable
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

SHODAN = ConnectorDefinition(
    name="Shodan",
    slug="shodan",
    secret_name="SHODAN_API_KEY",
    supported_ioc_types=frozenset({"ip", "domain"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    if classified.input_type not in SHODAN.supported_ioc_types:
        return source_not_applicable(SHODAN, classified)

    if classified.input_type == "ip":
        try:
            payload = await get_json(
                client,
                SHODAN.name,
                f"https://api.shodan.io/shodan/host/{classified.normalized_value}",
                params={"key": settings.shodan_api_key},
            )
        except ConnectorHTTPError as exc:
            if _is_membership_restriction(exc):
                return await _analyze_internetdb(classified, client)
            raise
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
        try:
            payload = await get_json(
                client,
                SHODAN.name,
                f"https://api.shodan.io/dns/domain/{classified.normalized_value}",
                params={"key": settings.shodan_api_key},
            )
        except ConnectorHTTPError as exc:
            if _is_membership_restriction(exc):
                return _restricted_result(classified)
            raise
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


async def _analyze_internetdb(classified: ClassifiedIOC, client) -> SourceResult:
    try:
        payload = await get_json(
            client,
            SHODAN.name,
            f"https://internetdb.shodan.io/{classified.normalized_value}",
        )
    except ConnectorHTTPError as exc:
        if exc.status_code == 404:
            return _internetdb_no_data_result(classified, fallback_reason="membership_required")
        raise
    ports = compact_list(payload.get("ports") or [], limit=40)
    vulns = compact_list(payload.get("vulns") or [], limit=12)
    cpes = compact_list(payload.get("cpes") or [], limit=12)
    normalized = {
        "ip": payload.get("ip") or classified.normalized_value,
        "hostnames": compact_list(payload.get("hostnames") or [], limit=8),
        "ports": ports,
        "cpes": cpes,
        "tags": compact_list(payload.get("tags") or [], limit=8),
        "vulnerability_count": len(vulns),
        "vulnerabilities": vulns,
        "risky_service_count": count_risky_ports([int(port) for port in ports if isinstance(port, int)]),
        "api_mode": "internetdb",
        "fallback_reason": "membership_required",
    }
    return SourceResult(source_name=SHODAN.name, status="success", normalized=normalized)


def _internetdb_no_data_result(classified: ClassifiedIOC, *, fallback_reason: str) -> SourceResult:
    return SourceResult(
        source_name=SHODAN.name,
        status="success",
        normalized={
            "ip": classified.normalized_value,
            "hostnames": [],
            "ports": [],
            "cpes": [],
            "tags": [],
            "vulnerability_count": 0,
            "vulnerabilities": [],
            "risky_service_count": 0,
            "api_mode": "internetdb",
            "fallback_reason": fallback_reason,
            "data_available": False,
            "message": "Shodan InternetDB has no indexed data for this IP address.",
        },
    )


def _is_membership_restriction(exc: ConnectorHTTPError) -> bool:
    return exc.status_code == 403 and "membership" in exc.message.lower()


def _restricted_result(classified: ClassifiedIOC) -> SourceResult:
    return SourceResult(
        source_name=SHODAN.name,
        status="not_applicable",
        normalized={
            "ioc_type": classified.input_type,
            "connector": SHODAN.slug,
            "restriction": "membership_required",
        },
        error_message="Shodan account plan does not allow this lookup.",
    )
