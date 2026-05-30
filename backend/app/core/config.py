from functools import lru_cache
from typing import Annotated

from fastapi import Depends
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Threat Intelligence Dashboard"
    app_env: str = Field(default="development", alias="APP_ENV")
    api_prefix: str = Field(default="/api", alias="API_PREFIX")
    allowed_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="ALLOWED_ORIGINS",
    )
    database_url: str = Field(
        default="postgresql+psycopg://threatintel:threatintel@localhost:5432/threatintel",
        alias="DATABASE_URL",
    )
    allow_private_iocs: bool = Field(default=False, alias="ALLOW_PRIVATE_IOCS")
    max_request_bytes: int = Field(default=8192, alias="MAX_REQUEST_BYTES")
    max_upload_file_bytes: int = Field(default=32 * 1024 * 1024, alias="MAX_UPLOAD_FILE_BYTES")
    nmap_path: str | None = Field(default=None, alias="NMAP_PATH")
    nmap_use_sudo: bool = Field(default=False, alias="NMAP_USE_SUDO")
    nmap_sudo_path: str = Field(default="/usr/bin/sudo", alias="NMAP_SUDO_PATH")
    analyze_rate_limit_per_minute: int = Field(
        default=30,
        alias="ANALYZE_RATE_LIMIT_PER_MINUTE",
    )
    connector_timeout_seconds: float = Field(default=12.0, alias="CONNECTOR_TIMEOUT_SECONDS")

    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")
    otx_api_key: str | None = Field(default=None, alias="OTX_API_KEY")
    shodan_api_key: str | None = Field(default=None, alias="SHODAN_API_KEY")
    urlscan_api_key: str | None = Field(default=None, alias="URLSCAN_API_KEY")
    ipinfo_token: str | None = Field(default=None, alias="IPINFO_TOKEN")

    ai_provider: str = Field(default="disabled", alias="AI_PROVIDER")
    gemini_model: str = Field(default="gemini-2.5-flash", alias="GEMINI_MODEL")
    groq_model: str = Field(default="llama-3.1-8b-instant", alias="GROQ_MODEL")
    xai_model: str = Field(default="grok-3-mini", alias="XAI_MODEL")
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    groq_api_key: str | None = Field(default=None, alias="GROQ_API_KEY")
    xai_api_key: str | None = Field(default=None, alias="XAI_API_KEY")
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("database_url")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+psycopg://", 1)
        return value

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]

    def has_secret(self, secret_name: str) -> bool:
        return bool(self.secret_value(secret_name))

    def secret_value(self, secret_name: str) -> str | None:
        field_name = secret_name.lower()
        return getattr(self, field_name, None)


@lru_cache
def get_settings() -> Settings:
    return Settings()


SettingsDep = Annotated[Settings, Depends(get_settings)]
