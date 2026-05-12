from app.connectors.base import ConnectorDefinition
from app.connectors.base import compact_list, get_json
from app.schemas.results import SourceResult
from app.services.classifier import ClassifiedIOC

URLSCAN = ConnectorDefinition(
    name="URLScan",
    slug="urlscan",
    secret_name="URLSCAN_API_KEY",
    supported_ioc_types=frozenset({"url", "domain"}),
)


async def analyze(classified: ClassifiedIOC, settings, client) -> SourceResult:
    query = (
        f'page.url:"{classified.normalized_value}"'
        if classified.input_type == "url"
        else f"page.domain:{classified.normalized_value}"
    )
    payload = await get_json(
        client,
        URLSCAN.name,
        "https://urlscan.io/api/v1/search/",
        headers={"api-key": settings.urlscan_api_key or ""},
        params={"q": query, "size": "10"},
    )
    results = payload.get("results") or []
    malicious_count = 0
    suspicious_count = 0
    screenshots = []
    contacted_domains = []
    for result in results:
        verdicts = result.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        if overall.get("malicious") is True:
            malicious_count += 1
        elif overall.get("score", 0) and overall.get("score", 0) >= 50:
            suspicious_count += 1
        screenshot = result.get("screenshot")
        if screenshot:
            screenshots.append(screenshot)
        page = result.get("page") or {}
        if page.get("domain"):
            contacted_domains.append(page.get("domain"))

    verdict = "malicious" if malicious_count else "suspicious" if suspicious_count else "clean"
    normalized = {
        "total": payload.get("total"),
        "result_count": len(results),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "verdict": verdict,
        "domains": compact_list(contacted_domains, limit=10),
        "screenshot": screenshots[0] if screenshots else None,
    }
    return SourceResult(source_name=URLSCAN.name, status="success", normalized=normalized)
