
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .engine.analyzer import ENGINE_VERSION, analyze
from .models import AnalysisRequest, EmailAnalysis, HealthResponse


MAX_BODY_BYTES = 320_000

app = FastAPI(
    title="Phishing Email Analysis Engine",
    version=ENGINE_VERSION,
    description="Explainable, local-first email threat analysis.",
    docs_url="/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body is too large."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid Content-Length header."},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    return response


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", engine_version=ENGINE_VERSION)


@app.post("/api/v1/analyze", response_model=EmailAnalysis)
async def analyze_email(payload: AnalysisRequest) -> EmailAnalysis:
    return analyze(payload.raw_email)
