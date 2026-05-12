import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import SplitResult, urlsplit, urlunsplit

IOCType = Literal["ip", "domain", "url", "hash", "file"]

MAX_IOC_LENGTH = 2048
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$")
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
}


class IOCValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ClassifiedIOC:
    input_type: IOCType
    submitted_value: str
    normalized_value: str


def classify_ioc(value: str, *, allow_private: bool = False) -> ClassifiedIOC:
    submitted = _clean(value)

    ip_result = _try_ip(submitted, allow_private=allow_private)
    if ip_result:
        return ClassifiedIOC("ip", submitted, ip_result)

    if HASH_RE.fullmatch(submitted):
        return ClassifiedIOC("hash", submitted, submitted.lower())

    if "://" in submitted:
        return ClassifiedIOC("url", submitted, _normalize_url(submitted, allow_private=allow_private))

    domain = _normalize_domain(submitted)
    return ClassifiedIOC("domain", submitted, domain)


def _clean(value: str) -> str:
    if not isinstance(value, str):
        raise IOCValidationError("IOC must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise IOCValidationError("IOC is required.")
    if len(cleaned) > MAX_IOC_LENGTH:
        raise IOCValidationError("IOC is too long.")
    if any(ord(char) < 32 for char in cleaned):
        raise IOCValidationError("IOC contains control characters.")
    return cleaned


def _try_ip(value: str, *, allow_private: bool) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    _ensure_public_ip(ip, allow_private=allow_private)
    return str(ip)


def _ensure_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> None:
    if ip in METADATA_IPS:
        raise IOCValidationError("Metadata service IPs are blocked.")
    if allow_private:
        return
    if not ip.is_global:
        raise IOCValidationError("Private or internal IPs are blocked.")


def _normalize_url(value: str, *, allow_private: bool) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise IOCValidationError("Invalid URL.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise IOCValidationError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise IOCValidationError("URL host is required.")
    if parsed.username or parsed.password:
        raise IOCValidationError("URLs with embedded credentials are not supported.")

    host = _normalize_host(parsed.hostname)
    ip_result = _try_ip(host, allow_private=allow_private)
    port = _url_port(parsed)
    if ip_result:
        host = f"[{ip_result}]" if ":" in ip_result else ip_result
    else:
        _validate_domain(host)

    netloc = host
    if port:
        netloc = f"{host}:{port}"

    normalized = SplitResult(
        scheme=parsed.scheme.lower(),
        netloc=netloc,
        path=parsed.path or "/",
        query=parsed.query,
        fragment="",
    )
    return urlunsplit(normalized)


def _normalize_host(hostname: str) -> str:
    host = hostname.strip().lower().rstrip(".")
    if host in BLOCKED_HOSTNAMES or host.endswith(".local"):
        raise IOCValidationError("Local hostnames are blocked.")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IOCValidationError("Hostname cannot be normalized.") from exc


def _normalize_domain(value: str) -> str:
    domain = _normalize_host(value)
    _validate_domain(domain)
    return domain


def _validate_domain(domain: str) -> None:
    if len(domain) > 253:
        raise IOCValidationError("Domain is too long.")
    if "/" in domain or ":" in domain or "@" in domain:
        raise IOCValidationError("Invalid domain.")
    labels = domain.split(".")
    if len(labels) < 2:
        raise IOCValidationError("Domain must include a public suffix.")
    if not all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        raise IOCValidationError("Invalid domain label.")
    if labels[-1].isdigit():
        raise IOCValidationError("Domain suffix must not be numeric.")


def _url_port(parsed: SplitResult) -> int | None:
    try:
        return parsed.port
    except ValueError as exc:
        raise IOCValidationError("Invalid URL port.") from exc
