"""Optional Gemini explanation over the deterministic scanner's evidence."""

from __future__ import annotations

import importlib.util
import logging
import os
from typing import Any

from app.agent_adapter import evidence_for_agent
from veyl.backend.agent.prompts import build_explanation_prompt
from veyl.backend.agent.schemas import AgentReview


LOGGER = logging.getLogger(__name__)
PROVIDER = "Gemma via Google GenAI"
DEFAULT_MODEL = "gemma-4-26b-a4b-it"


def _has_genai_sdk() -> bool:
    try:
        return importlib.util.find_spec("google.genai") is not None
    except ModuleNotFoundError:
        return False


def agent_runtime_status() -> str:
    if not os.getenv("GEMINI_API_KEY", "").strip():
        return "not_configured"
    if not _has_genai_sdk():
        return "missing_dependency"
    return "ready"


def review_report(report: dict[str, Any]) -> AgentReview:
    """Return an optional text explanation; deterministic scanning always wins."""
    status = agent_runtime_status()
    if status != "ready":
        return AgentReview(status=status, provider=PROVIDER)

    try:
        from google import genai

        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
        model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
        if model.startswith("models/"):
            model = model.removeprefix("models/")
        response = client.models.generate_content(
            model=model,
            contents=build_explanation_prompt(evidence_for_agent(report)),
        )
        explanation = (response.text or "").strip()
        if not explanation:
            raise RuntimeError("The model returned an empty explanation.")
        return AgentReview(status="complete", provider=PROVIDER, explanation=explanation)
    except Exception as exc:  # AI is an optional layer; preserve the scan report.
        LOGGER.warning("Optional AI review failed (%s).", type(exc).__name__)
        code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
        if code in {401, 403}:
            message = "Gemma rejected the API key. Check GEMINI_API_KEY and key restrictions."
        elif code == 404:
            message = "The configured model was not found. Check GEMINI_MODEL."
        elif code == 429:
            message = "The AI provider rate limit or quota was reached. Try again later."
        else:
            message = "The AI review failed. Check the backend terminal for its error type."
        return AgentReview(status="unavailable", provider=PROVIDER, message=message)
