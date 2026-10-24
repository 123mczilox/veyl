# LinkGuard URL Analyzer

LinkGuard serves its frontend and FastAPI backend from one local app. The browser submits a URL and optional message text to `POST /api/scan`; the backend validates and passively analyzes it, optionally checks Google Safe Browsing, and can return an optional AI explanation of the structured findings. The destination URL is never opened by this app.

This project is served by Python/FastAPI. It does not use npm or a `package.json`, so start it from the project root rather than running `npm run dev`.

## Run locally (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The backend folder can also be used as the ASGI entry point with `python -m uvicorn veyl.backend.main:app --reload` from the same project root; both commands serve the same app and API.

## How the pieces connect

`app/static/app.js` posts the form to `/api/scan` on this same server by default. `veyl/backend/api/routes.py` validates the request contract, calls the passive scanner in `app/scanner.py`, and attaches an optional explanation from `veyl/backend/agent/orchestrator.py`. The browser renders the single JSON report returned by that route. This same-origin setup needs no CORS configuration.

`veyl/backend/api/schemas.py` is the canonical API contract and enforces the scan request and report fields. The older top-level `veyl/backend/url_parser.py` and `risk_engine.py` are legacy prototypes; their `url`/`hostname` and `risk_indicators`/`risk_level` shapes are not used by `/api/scan`. The active report uses `submitted_url`, `host`, `level`, `risk_score`, and a nested `agent` object.

## Optional providers

Copy `.env.example` to `.env` in the project root and add only the keys you want to use. For compatibility with the earlier standalone backend, the app also reads `veyl/backend/.env`; values in the project-root file take precedence. Restart Uvicorn after changing configuration.

- `GOOGLE_SAFE_BROWSING_API_KEY` enables URL-only reputation lookups. A Gemini key does not enable this provider. Google documents Safe Browsing for non-commercial use; commercial detection should use Web Risk. See [Google Safe Browsing API](https://developers.google.com/safe-browsing/reference/rest) and [Web Risk](https://cloud.google.com/web-risk/docs).
- `GEMINI_API_KEY` enables the optional hostname review, not a reputation lookup. Install its SDK with `python -m pip install -r veyl/backend/requirements.txt`. `GEMINI_MODEL` can override the model name; use the model ID without a `models/` prefix.
- `ANALYZE_ENDPOINT_URL` specifies the remote compatibility endpoint used by `/api/analyze-proxy` and the legacy `/analyze` route (default: `https://veyl.onrender.com/analyze`). Do not point it at this same app's `/analyze` route; that would make the proxy call itself. The UI uses the local `/api/scan` endpoint by default and can be overridden with `LINKGUARD_API_URL` in the browser.


The AI layer receives the hostname and deterministic findings, but not the URL path, query values, fragment, or original message. It returns an explanation without changing the rule-based score or verdict. If the key or SDK is missing, or the provider is unavailable, the scan report still returns normally.

## API contract

- `GET /api/health` reports scanner and optional-provider readiness.
- `POST /api/scan` accepts `{"url":"https://example.com","message":"optional context"}` and returns the `ScanReport` contract rendered by the frontend, including a nested `agent` object.
- Invalid, local, private, reserved, and internal destinations are rejected with HTTP 422.

The score is rule signal points, not a percentage or calibrated probability. Finding severity sets a minimum score and assessment level, so a medium or high finding cannot be displayed as a low assessment just because the point sum is small or a reputation provider returned no match. A no-match result does not prove a link is safe. Scans are not persisted, and the scanner does not visit destinations, resolve their hosts, follow redirects, download content, or run scripts. Message text is analyzed locally; only the URL is sent to the optional reputation provider.

Public development tunnel hosts such as LocalTunnel are reported as a caution signal because the URL alone does not identify who controls the tunneled service; this is not, by itself, a malicious verdict.

This is a prototype, not a production security service. Before public deployment, add rate limiting, abuse controls, secret management, logging that excludes submitted data, and a threat-intelligence provider appropriate for the product's use.
