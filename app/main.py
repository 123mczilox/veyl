from typing import Any

from app.config import APP_ROOT as ROOT
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from veyl.backend.api.routes import analyze_proxy
from veyl.backend.api.routes import router as api_router


app = FastAPI(title="LinkGuard URL Analyzer", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
app.include_router(api_router)


@app.get("/")
def home() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


@app.post("/analyze")
def root_analyze(payload: dict[str, Any]) -> dict[str, Any]:
    return analyze_proxy(payload)

