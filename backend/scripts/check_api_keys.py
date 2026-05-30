import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class Check:
    name: str
    required_env: tuple[str, ...]
    method: str
    url: str
    headers: dict[str, str] | None = None
    params: dict[str, Any] | None = None
    json: dict[str, Any] | None = None
    auth: tuple[str, str] | None = None


def main() -> int:
    url_id = base64.urlsafe_b64encode(b"https://example.com/").decode("ascii").rstrip("=")
    checks = [
        Check(
            name="VirusTotal",
            required_env=("VIRUSTOTAL_API_KEY",),
            method="GET",
            url="https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": env("VIRUSTOTAL_API_KEY")},
        ),
        Check(
            name="VirusTotal URL",
            required_env=("VIRUSTOTAL_API_KEY",),
            method="GET",
            url=f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": env("VIRUSTOTAL_API_KEY")},
        ),
        Check(
            name="AbuseIPDB",
            required_env=("ABUSEIPDB_API_KEY",),
            method="GET",
            url="https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": env("ABUSEIPDB_API_KEY")},
            params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
        ),
        Check(
            name="AlienVault OTX",
            required_env=("OTX_API_KEY",),
            method="GET",
            url="https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
            headers={"X-OTX-API-KEY": env("OTX_API_KEY")},
        ),
        Check(
            name="OTX URL",
            required_env=("OTX_API_KEY",),
            method="GET",
            url=f"https://otx.alienvault.com/api/v1/indicators/url/{quote('https://example.com/', safe='')}/general",
            headers={"X-OTX-API-KEY": env("OTX_API_KEY")},
        ),
        Check(
            name="Shodan",
            required_env=("SHODAN_API_KEY",),
            method="GET",
            url="https://api.shodan.io/shodan/host/8.8.8.8",
            params={"key": env("SHODAN_API_KEY")},
        ),
        Check(
            name="URLScan",
            required_env=("URLSCAN_API_KEY",),
            method="GET",
            url="https://urlscan.io/api/v1/search/",
            headers={"api-key": env("URLSCAN_API_KEY")},
            params={"q": "page.domain:example.com", "size": "1"},
        ),
        Check(
            name="IPinfo",
            required_env=("IPINFO_TOKEN",),
            method="GET",
            url="https://ipinfo.io/8.8.8.8/json",
            params={"token": env("IPINFO_TOKEN")},
        ),
    ]
    ai_provider_check = ai_check()
    if ai_provider_check:
        checks.append(ai_provider_check)
    else:
        provider = env("AI_PROVIDER", "disabled").lower()
        reason = "provider disabled" if provider == "disabled" else f"unsupported provider {provider}"
        print(f"AI summary: SKIP {reason}")

    failures = 0
    with httpx.Client(timeout=20, follow_redirects=True) as client:
        for check in checks:
            if any(not env(key) for key in check.required_env):
                print(f"{check.name}: SKIP missing {', '.join(check.required_env)}")
                failures += 1
                continue
            try:
                response = client.request(
                    check.method,
                    check.url,
                    headers=check.headers,
                    params=check.params,
                    json=check.json,
                    auth=check.auth,
                )
                ok = 200 <= response.status_code < 300
                label = "OK" if ok else "FAIL"
                print(f"{check.name}: {label} HTTP {response.status_code} {summarize_response(response)}")
                if not ok:
                    failures += 1
            except httpx.TimeoutException:
                failures += 1
                print(f"{check.name}: FAIL timeout")
            except httpx.HTTPError as exc:
                failures += 1
                print(f"{check.name}: FAIL {exc.__class__.__name__}")
    return 1 if failures else 0


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def ai_check() -> Check | None:
    provider = env("AI_PROVIDER", "disabled").lower()
    if provider == "groq":
        return Check(
            name="Groq",
            required_env=("GROQ_API_KEY",),
            method="POST",
            url="https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {env('GROQ_API_KEY')}", "Content-Type": "application/json"},
            json={
                "model": env("GROQ_MODEL", "llama-3.1-8b-instant"),
                "messages": [{"role": "user", "content": "Reply with OK."}],
                "max_completion_tokens": 8,
            },
        )
    if provider in {"xai", "grok"}:
        return Check(
            name="xAI Grok",
            required_env=("XAI_API_KEY",),
            method="POST",
            url="https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {env('XAI_API_KEY')}", "Content-Type": "application/json"},
            json={
                "model": env("XAI_MODEL", "grok-3-mini"),
                "messages": [{"role": "user", "content": "Reply with OK."}],
                "max_tokens": 8,
            },
        )
    if provider == "gemini":
        return Check(
            name="Gemini",
            required_env=("GEMINI_API_KEY",),
            method="POST",
            url=f"https://generativelanguage.googleapis.com/v1beta/models/{env('GEMINI_MODEL', 'gemini-2.5-flash')}:generateContent",
            headers={"x-goog-api-key": env("GEMINI_API_KEY"), "Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": "Reply with OK."}]}], "generationConfig": {"maxOutputTokens": 8}},
        )
    return None


def summarize_response(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.reason_phrase
    if response.status_code >= 400:
        message = payload.get("message") or payload.get("detail") or payload.get("error")
        if isinstance(message, dict):
            message = message.get("message") or message.get("code")
        return str(message or response.reason_phrase)[:160]
    if "data" in payload:
        return "json:data"
    if "result" in payload:
        return "json:result"
    if "results" in payload:
        return "json:results"
    if "candidates" in payload:
        return "json:candidates"
    return "json"


if __name__ == "__main__":
    raise SystemExit(main())
