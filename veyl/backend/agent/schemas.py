"""Stable response contract for the optional AI review."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


AgentReviewStatus = Literal[
    "complete",
    "not_configured",
    "missing_dependency",
    "unavailable",
]


class AgentReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AgentReviewStatus
    provider: str
    explanation: str | None = None
    message: str | None = None
