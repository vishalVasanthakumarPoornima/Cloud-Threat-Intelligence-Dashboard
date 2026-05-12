import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AnalysisRequest(Base):
    __tablename__ = "analysis_requests"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    input_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    input_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    user_ip_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    tool_results: Mapped[list["ToolResult"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )
    risk_report: Mapped["RiskReport | None"] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )


class ToolResult(Base):
    __tablename__ = "tool_results"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analysis_requests.id"))
    source_name: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    raw_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    normalized_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    analysis: Mapped[AnalysisRequest] = relationship(back_populates="tool_results")


class RiskReport(Base):
    __tablename__ = "risk_reports"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_requests.id"),
        unique=True,
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    analysis: Mapped[AnalysisRequest] = relationship(back_populates="risk_report")


class CacheEntry(Base):
    __tablename__ = "cache_entries"

    cache_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    input_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    input_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    source_name: Mapped[str] = mapped_column(String(80), nullable=False)
    response_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    event_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    source_ip_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
