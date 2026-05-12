import json

from app.schemas.results import RiskReport, SourceResult
from app.services.classifier import ClassifiedIOC


def build_stub_summary(classified: ClassifiedIOC, severity: str, score: int) -> str:
    indicator_label = "an IP" if classified.input_type == "ip" else f"a {classified.input_type}"
    return (
        f"{classified.normalized_value} was classified as {indicator_label} "
        f"indicator. Current configured evidence produces a {severity.lower()} "
        f"risk rating with a score of {score}."
    )


async def build_analyst_summary(
    *,
    classified: ClassifiedIOC,
    risk_report: RiskReport,
    source_results: list[SourceResult],
    settings,
    client,
) -> str:
    provider = settings.ai_provider.lower()
    if provider == "groq" and settings.groq_api_key:
        return await _build_groq_summary(
            prompt=_summary_prompt(classified, risk_report, source_results),
            settings=settings,
            client=client,
            fallback=build_stub_summary(classified, risk_report.severity, risk_report.score),
        )
    if provider in {"xai", "grok"} and settings.xai_api_key:
        return await _build_xai_summary(
            prompt=_summary_prompt(classified, risk_report, source_results),
            settings=settings,
            client=client,
            fallback=build_stub_summary(classified, risk_report.severity, risk_report.score),
        )
    if provider == "gemini" and settings.gemini_api_key:
        return await _build_gemini_summary(
            prompt=_summary_prompt(classified, risk_report, source_results),
            settings=settings,
            client=client,
            fallback=build_stub_summary(classified, risk_report.severity, risk_report.score),
        )
    return build_stub_summary(classified, risk_report.severity, risk_report.score)


async def _build_gemini_summary(*, prompt: str, settings, client, fallback: str) -> str:
    try:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 220},
        }
        response = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}:generateContent",
            headers={
                "x-goog-api-key": settings.gemini_api_key,
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text")
        )
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return fallback
    return fallback


async def _build_groq_summary(*, prompt: str, settings, client, fallback: str) -> str:
    try:
        payload = {
            "model": settings.groq_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You write concise, careful cybersecurity analyst summaries from supplied passive threat intelligence evidence.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_completion_tokens": 220,
        }
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.groq_api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content")
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return fallback
    return fallback


async def _build_xai_summary(*, prompt: str, settings, client, fallback: str) -> str:
    try:
        payload = {
            "model": settings.xai_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You write concise, careful cybersecurity analyst summaries from supplied passive threat intelligence evidence.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 220,
        }
        response = await client.post(
            "https://api.x.ai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.xai_api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content")
        if isinstance(text, str) and text.strip():
            return text.strip()
    except Exception:
        return fallback
    return fallback


def _summary_prompt(
    classified: ClassifiedIOC,
    risk_report: RiskReport,
    source_results: list[SourceResult],
) -> str:
    evidence = [
        {
            "source": result.source_name,
            "status": result.status,
            "normalized": result.normalized,
        }
        for result in source_results
    ]
    return (
        "You are a cybersecurity analyst writing a concise passive threat intelligence summary. "
        "Do not claim active scanning or direct confirmation beyond the supplied API evidence. "
        "Write 3 to 5 sentences, mention the severity and the strongest evidence, and include a practical next step.\n\n"
        f"Indicator type: {classified.input_type}\n"
        f"Indicator: {classified.normalized_value}\n"
        f"Score: {risk_report.score}/100\n"
        f"Severity: {risk_report.severity}\n"
        f"Evidence JSON: {json.dumps(evidence, default=str)[:5000]}"
    )
