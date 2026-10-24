"""Canonical request and response contracts for the browser API."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from veyl.backend.agent.schemas import AgentReview, AgentReviewStatus


RiskLevel = Literal["unknown", "low", "medium", "high"]
FindingSeverity = Literal["info", "low", "medium", "high"]
ThreatStatus = Literal["not_configured", "unavailable", "clean", "match"]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=4096)
    message: str = Field(default="", max_length=4000)


class ScanFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    detail: str
    points: int
    severity: FindingSeverity


class ThreatIntelligence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    status: ThreatStatus
    label: str
    detail: str | None = None


class ScanReport(BaseModel):
    """Response consumed by app/static/app.js; keep both sides on these names."""

    model_config = ConfigDict(extra="forbid")

    submitted_url: str
    host: str
    verdict: str
    level: RiskLevel
    risk_score: int = Field(ge=0, le=100)
    score_label: str
    findings: list[ScanFinding]
    recommendation: str
    threat_intelligence: ThreatIntelligence
    analysis_mode: str
    agent: AgentReview
    scanned_at: datetime


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ready"]
    safe_browsing_configured: bool
    agent_status: Literal["not_configured", "missing_dependency", "ready"]
    agent_connected: bool
