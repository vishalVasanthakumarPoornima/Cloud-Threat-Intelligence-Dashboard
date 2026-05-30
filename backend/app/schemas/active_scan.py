from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

NmapPreset = Literal[
    "quick_ports",
    "open_ports",
    "service_detection",
    "os_detection",
    "stealth_syn",
]
ActiveScanStatus = Literal["completed", "failed", "not_available", "timeout"]


class NmapScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: str = Field(
        min_length=1,
        max_length=253,
        description="Authorized IP address or domain to scan.",
    )
    preset: NmapPreset = Field(default="quick_ports")
    confirmed_authorized: bool = Field(
        default=False,
        description="User confirmation that they are authorized to actively scan this target.",
    )
    timeout_seconds: int = Field(default=45, ge=10, le=180)


class NmapPortResult(BaseModel):
    port: int
    protocol: str
    state: str
    reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpes: list[str] = Field(default_factory=list)


class NmapOsMatch(BaseModel):
    name: str
    accuracy: int | None = None


class NmapScanResponse(BaseModel):
    status: ActiveScanStatus
    target: str
    normalized_target: str
    input_type: Literal["ip", "domain"]
    preset: NmapPreset
    command: list[str]
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    ports: list[NmapPortResult]
    os_matches: list[NmapOsMatch] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    summary: str
    error_message: str | None = None
