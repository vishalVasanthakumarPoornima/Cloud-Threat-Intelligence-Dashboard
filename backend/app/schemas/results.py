from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

IOCType = Literal["ip", "domain", "url", "hash", "file"]
Severity = Literal["Low", "Medium", "High", "Critical"]
SourceStatus = Literal[
    "not_applicable",
    "not_configured",
    "pending",
    "success",
    "partial",
    "restricted",
    "failed",
    "stubbed",
]


class IOCDetails(BaseModel):
    input_type: IOCType
    submitted_value: str
    normalized_value: str


class ScoreContribution(BaseModel):
    source_name: str
    points: int = Field(ge=0, le=100)
    reason: str


class SourceResult(BaseModel):
    source_name: str
    status: SourceStatus
    normalized: dict = Field(default_factory=dict)
    error_message: str | None = None


class RiskReport(BaseModel):
    score: int = Field(ge=0, le=100)
    severity: Severity
    summary: str
    recommended_actions: list[str]
    contributions: list[ScoreContribution]


class AnalysisResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: UUID
    status: Literal["completed", "partial", "pending"]
    created_at: datetime
    ioc: IOCDetails
    risk_report: RiskReport
    source_results: list[SourceResult]
