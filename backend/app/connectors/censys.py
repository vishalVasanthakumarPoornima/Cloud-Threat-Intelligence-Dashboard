from app.connectors.base import ConnectorDefinition
from app.connectors.base import compact_list, count_risky_ports, get_json, post_json
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

CENSYS = ConnectorDefinition(
    name="Censys",
    slug="censys",
    secret_name="CENSYS_PAT",
    auth_groups=(("CENSYS_PAT",), ("CENSYS_API_ID", "CENSYS_API_SECRET")),
    supported_ioc_types=frozenset({"ip", "domain"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    if settings.censys_pat:
        return await _analyze_platform(classified, settings, client)
    return await _analyze_legacy(classified, settings, client)


async def _analyze_platform(classified: ClassifiedIOC, settings, client) -> SourceResult:
    headers = {
        "Authorization": f"Bearer {settings.censys_pat}",
        "Accept": "application/json",
    }
    if classified.input_type == "ip":
        payload = await get_json(
            client,
            CENSYS.name,
            f"https://api.platform.censys.io/v3/global/asset/host/{classified.normalized_value}",
            headers=headers,
        )
        result = payload.get("result") or payload.get("host") or payload
        services = _platform_services(result)
        ports = compact_list([service.get("port") for service in services], limit=30)
        normalized = {
            "ip": result.get("ip") or result.get("host_id") or classified.normalized_value,
            "service_count": len(services),
            "ports": ports,
            "service_names": compact_list([service.get("protocol") or service.get("service_name") for service in services], limit=12),
            "risky_service_count": count_risky_ports([int(port) for port in ports if isinstance(port, int)]),
            "autonomous_system": result.get("autonomous_system") or result.get("as"),
            "location": result.get("location"),
            "last_updated_at": result.get("last_updated_at") or result.get("observed_at"),
            "api_mode": "platform",
        }
    else:
        payload = await post_json(
            client,
            CENSYS.name,
            "https://api.platform.censys.io/v3/global/search/query",
            headers=headers,
            json={
                "query": classified.normalized_value,
                "page_size": 5,
                "fields": [
                    "host.ip",
                    "host.services.port",
                    "host.services.protocol",
                    "host.location.country",
                    "host.autonomous_system.name",
                ],
            },
        )
        result = payload.get("result") or payload
        hits = result.get("hits") or result.get("records") or result.get("results") or []
        ports: list[int] = []
        sample_hosts = []
        for hit in hits:
            host = hit.get("host") if isinstance(hit.get("host"), dict) else hit
            if isinstance(host.get("ip"), str):
                sample_hosts.append(host.get("ip"))
            for service in host.get("services") or hit.get("matched_services") or []:
                port = service.get("port")
                if isinstance(port, int):
                    ports.append(port)
        normalized = {
            "total": result.get("total") or result.get("total_count"),
            "hit_count": len(hits),
            "sample_hosts": compact_list(sample_hosts, limit=5),
            "ports": compact_list(ports, limit=20),
            "risky_service_count": count_risky_ports(ports),
            "api_mode": "platform",
        }
    return SourceResult(source_name=CENSYS.name, status="success", normalized=normalized)


async def _analyze_legacy(classified: ClassifiedIOC, settings, client) -> SourceResult:
    auth = (settings.censys_api_id or "", settings.censys_api_secret or "")
    if classified.input_type == "ip":
        payload = await get_json(
            client,
            CENSYS.name,
            f"https://search.censys.io/api/v2/hosts/{classified.normalized_value}",
            headers={"Accept": "application/json"},
            auth=auth,
        )
        result = payload.get("result", {})
        services = result.get("services") or []
        ports = compact_list([service.get("port") for service in services if isinstance(service, dict)], limit=30)
        normalized = {
            "ip": result.get("ip"),
            "service_count": len(services),
            "ports": ports,
            "service_names": compact_list([service.get("service_name") for service in services if isinstance(service, dict)], limit=12),
            "risky_service_count": count_risky_ports([int(port) for port in ports if isinstance(port, int)]),
            "autonomous_system": result.get("autonomous_system"),
            "location": result.get("location"),
            "last_updated_at": result.get("last_updated_at"),
            "api_mode": "legacy",
        }
    else:
        payload = await get_json(
            client,
            CENSYS.name,
            "https://search.censys.io/api/v2/hosts/search",
            headers={"Accept": "application/json"},
            params={
                "q": classified.normalized_value,
                "per_page": 5,
                "virtual_hosts": "EXCLUDE",
                "fields": "ip,services.port,services.service_name,location.country,autonomous_system.name",
            },
            auth=auth,
        )
        result = payload.get("result", {})
        hits = result.get("hits") or []
        ports: list[int] = []
        for hit in hits:
            for service in hit.get("services") or []:
                port = service.get("port")
                if isinstance(port, int):
                    ports.append(port)
        normalized = {
            "total": result.get("total"),
            "hit_count": len(hits),
            "sample_hosts": compact_list([hit.get("ip") for hit in hits], limit=5),
            "ports": compact_list(ports, limit=20),
            "risky_service_count": count_risky_ports(ports),
            "api_mode": "legacy",
        }
    return SourceResult(source_name=CENSYS.name, status="success", normalized=normalized)


def _platform_services(result: dict) -> list[dict]:
    services = result.get("services") or result.get("observed_services") or []
    if isinstance(services, list):
        return [service for service in services if isinstance(service, dict)]
    return []
