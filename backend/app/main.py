"""ScamSleuth API.

Run from the backend folder:
    uvicorn app.main:app --reload --port 8000

Privacy: submitted text is analysed in memory and never stored or logged.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from .engine import analyze
from .samples import SAMPLES

app = FastAPI(title="ScamSleuth API", version="1.0.0")

origins = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    text: str = Field("", max_length=5000, description="Message, job offer or notice to analyse")
    url: str = Field("", max_length=2048, description="Optional link to analyse (never opened)")

    @model_validator(mode="after")
    def need_something(self):
        if not self.text.strip() and not self.url.strip():
            raise ValueError("Provide a message or a link to analyse.")
        return self


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/samples")
def samples():
    return SAMPLES


@app.post("/api/analyze")
def analyze_endpoint(req: AnalyzeRequest):
    return analyze(req.text, req.url)


# Optional: serve the built React app from the same server (single-host deploy).
_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _DIST.is_dir():
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="frontend")
