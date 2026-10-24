"""HTTP API shared by the browser UI and the scanner backend."""

import json
import os
import urllib.error
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException

from app.scanner import SAFE_BROWSING_KEY, ScanInputError, analyze_url
from veyl.backend.agent.orchestrator import agent_runtime_status, review_report
from veyl.backend.api.schemas import HealthResponse, ScanReport, ScanRequest


router = APIRouter(prefix="/api")

RENDER_ANALYZE_ENDPOINT = os.getenv(
    "ANALYZE_ENDPOINT_URL", "https://veyl.onrender.com/analyze"
)


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    agent_status = agent_runtime_status()
    return HealthResponse(
        status="ready",
        safe_browsing_configured=bool(SAFE_BROWSING_KEY),
        agent_status=agent_status,
        agent_connected=agent_status == "ready",
    )


@router.post("/scan", response_model=ScanReport)
def scan(payload: ScanRequest) -> dict[str, Any]:
    try:
        report = analyze_url(payload.url, payload.message)
    except ScanInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    agent_review = review_report(report)
    report["agent"] = agent_review
    return report


@router.post("/analyze-proxy")
def analyze_proxy(payload: dict[str, Any]) -> dict[str, Any]:
    """Forward an analysis request to the Render endpoint to avoid browser CORS limits."""
    req_body = dict(payload)
    if "message" not in req_body and "url" in req_body:
        req_body = {"message": req_body["url"]}
    elif "url" in req_body and req_body["url"]:
        current_msg = req_body.get("message", "")
        if req_body["url"] not in current_msg:
            req_body["message"] = f"{current_msg}\n{req_body['url']}".strip()

    try:
        req_data = json.dumps(req_body).encode("utf-8")
        req = urllib.request.Request(
            RENDER_ANALYZE_ENDPOINT,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=75) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_text = exc.read().decode("utf-8")
        try:
            detail = json.loads(err_text)
        except Exception:
            detail = err_text
        raise HTTPException(status_code=exc.code, detail=detail) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach remote endpoint ({RENDER_ANALYZE_ENDPOINT}): {exc}",
        ) from exc


@router.post("/analyze")
def analyze(payload: dict[str, Any]) -> dict[str, Any]:
    """Compatibility endpoint mirroring https://veyl.onrender.com/analyze."""
    return analyze_proxy(payload)

