"""Shared application configuration loaded before scanner modules initialize."""

from pathlib import Path

from dotenv import load_dotenv


APP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = APP_ROOT.parent

# Load local development secrets before app.scanner reads its provider key.
# Prefer the project-root file, but also accept the backend location used by the
# earlier standalone backend setup. Existing environment variables still win.
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(PROJECT_ROOT / "veyl" / "backend" / ".env")
