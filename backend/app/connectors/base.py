from dataclasses import dataclass
from typing import Any

import httpx

from app.schemas.results import SourceResult

RISKY_PORTS = {21, 22, 23, 25, 110, 135, 139, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 9300, 11211, 27017}


@dataclass(frozen=True)
class ConnectorDefinition:
    name: str
    slug: str
    secret_name: str
    supported_ioc_types: frozenset[str]
    secret_names: tuple[str, ...] | None = None
    auth_groups: tuple[tuple[str, ...], ...] | None = None

    @property
    def required_secret_names(self) -> tuple[str, ...]:
        return self.secret_names or (self.secret_name,)

    def is_configured(self, settings) -> bool:
        if self.auth_groups:
            return any(all(settings.has_secret(secret) for secret in group) for group in self.auth_groups)
        return all(settings.has_secret(secret) for secret in self.required_secret_names)


class ConnectorHTTPError(RuntimeError):
    def __init__(self, source_name: str, status_code: int, message: str):
        super().__init__(f"{source_name} returned HTTP {status_code}: {message}")
        self.source_name = source_name
        self.status_code = status_code
        self.message = message


async def get_json(
    client: httpx.AsyncClient,
    source_name: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    auth: httpx.Auth | tuple[str, str] | None = None,
) -> dict[str, Any]:
    response = await client.get(url, headers=headers, params=params, auth=auth)
    return parse_json_response(source_name, response)


async def post_json(
    client: httpx.AsyncClient,
    source_name: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = await client.post(url, headers=headers, params=params, json=json)
    return parse_json_response(source_name, response)


def parse_json_response(source_name: str, response: httpx.Response) -> dict[str, Any]:
    if response.status_code >= 400:
        raise ConnectorHTTPError(source_name, response.status_code, _safe_error(response))
    try:
        payload = response.json()
    except ValueError as exc:
        raise ConnectorHTTPError(source_name, response.status_code, "Invalid JSON response.") from exc
    if not isinstance(payload, dict):
        raise ConnectorHTTPError(source_name, response.status_code, "Unexpected JSON response.")
    return payload


def source_failure(source_name: str, exc: Exception) -> SourceResult:
    if isinstance(exc, ConnectorHTTPError):
        message = f"Provider returned HTTP {exc.status_code}: {exc.message}"
    elif isinstance(exc, httpx.TimeoutException):
        message = "Provider request timed out."
    elif isinstance(exc, httpx.HTTPError):
        message = "Provider request failed."
    else:
        message = "Connector failed while normalizing provider data."
    return SourceResult(source_name=source_name, status="failed", normalized={}, error_message=message)


def compact_dict(value: dict[str, Any], allowed_keys: list[str]) -> dict[str, Any]:
    return {key: value.get(key) for key in allowed_keys if value.get(key) not in (None, "", [], {})}


def compact_list(values: list[Any], *, limit: int = 8) -> list[Any]:
    output = []
    for value in values:
        if value in (None, "", [], {}):
            continue
        if value not in output:
            output.append(value)
        if len(output) >= limit:
            break
    return output


def get_nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def count_risky_ports(ports: list[int]) -> int:
    return sum(1 for port in ports if port in RISKY_PORTS)


def _safe_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:240] or response.reason_phrase
    if isinstance(payload, dict):
        error = payload.get("error") or payload.get("message") or payload.get("detail")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("code") or "Provider error.")[:240]
        if error:
            return str(error)[:240]
    return response.reason_phrase
