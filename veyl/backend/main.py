"""Compatibility entry point for the unified LinkGuard application.

Run either ``uvicorn app.main:app --reload`` or
``uvicorn veyl.backend.main:app --reload`` from the project root.
"""

from app.main import app

__all__ = ["app"]
