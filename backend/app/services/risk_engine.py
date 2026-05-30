from app.schemas.results import RiskReport, ScoreContribution, SourceResult


def calculate_risk(source_results: list[SourceResult]) -> RiskReport:
    contributions: list[ScoreContribution] = []

    for result in source_results:
        points = _points_for_source(result)
        contributions.append(
            ScoreContribution(
                source_name=result.source_name,
                points=points,
                reason=_reason_for_source(result, points),
            )
        )

    score = min(sum(item.points for item in contributions), 100)
    severity = severity_for_score(score)
    return RiskReport(
        score=score,
        severity=severity,
        summary="",
        recommended_actions=recommendations_for_severity(severity),
        contributions=contributions,
    )


def severity_for_score(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def recommendations_for_severity(severity: str) -> list[str]:
    if severity in {"Critical", "High"}:
        return [
            "Escalate to incident response for review.",
            "Correlate with endpoint, DNS, proxy, and firewall logs.",
            "Block or monitor the indicator according to internal policy.",
        ]
    if severity == "Medium":
        return [
            "Review source evidence before taking action.",
            "Search internal logs for related activity.",
        ]
    return [
        "Preserve the report for context.",
        "Re-run analysis if new evidence appears.",
    ]


def _points_for_source(result: SourceResult) -> int:
    if result.status not in {"success", "partial"}:
        return 0

    normalized = result.normalized
    source = result.source_name.lower()
    if "virustotal" in source:
        malicious = int(normalized.get("malicious_detections", 0))
        suspicious = int(normalized.get("suspicious_detections", 0))
        return min(malicious * 4 + suspicious * 2, 30)
    if "abuseipdb" in source:
        confidence = int(normalized.get("abuse_confidence_score", 0))
        return min(round(confidence * 0.25), 25)
    if "otx" in source:
        pulse_count = int(normalized.get("pulse_count", 0))
        malware_tags = int(normalized.get("malware_tag_count", 0))
        return min(pulse_count * 3 + malware_tags * 5, 20)
    if "urlscan" in source:
        verdict = str(normalized.get("verdict", "")).lower()
        return 15 if verdict == "malicious" else 8 if verdict == "suspicious" else 0
    if "shodan" in source:
        risky_services = int(normalized.get("risky_service_count", 0))
        return min(risky_services * 3, 10)
    if "ipinfo" in source:
        flags = normalized.get("privacy_flags", [])
        return min(len(flags) * 2, 5)
    return 0


def _reason_for_source(result: SourceResult, points: int) -> str:
    if result.status == "not_configured":
        return "Source API key is not configured."
    if result.status == "restricted":
        return "Source account plan does not allow this lookup."
    if result.status == "stubbed":
        return "Source connector is configured but not live yet."
    if result.status == "failed":
        return "Source failed and did not affect the score."
    if result.status == "partial" and result.normalized.get("submission_status") == "submitted":
        return "File was submitted to VirusTotal and results may still be pending."
    if points == 0:
        return "No risk signal contributed by this source."
    return "Source evidence contributed to the transparent risk score."
