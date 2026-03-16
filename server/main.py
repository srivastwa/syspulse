"""
eCISO SysPulse Server — receives and displays security assessment reports.

Run with:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import database as db

BASE_DIR = Path(__file__).parent

app = FastAPI(title="eCISO SysPulse Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.on_event("startup")
def startup() -> None:
    db.init_db()


# ── API endpoints ────────────────────────────────────────────────────────────

@app.post("/api/reports", status_code=201)
async def receive_report(request: Request) -> JSONResponse:
    """Accept a SysPulse JSON report and store it."""
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty body")
    try:
        json.loads(body)  # validate JSON
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    report_id = db.insert_report(body.decode("utf-8"))
    return JSONResponse({"id": report_id, "status": "accepted"}, status_code=201)


@app.delete("/api/reports/{report_id}", status_code=204)
def delete_report(report_id: int) -> None:
    if not db.delete_report(report_id):
        raise HTTPException(status_code=404, detail="Report not found")


@app.get("/api/reports/{report_id}/json")
def download_report_json(report_id: int) -> JSONResponse:
    row = db.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return JSONResponse(json.loads(row["raw_json"]))


# ── Web views ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    reports = db.list_reports()
    stats   = db.get_stats()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "reports": reports,
        "stats":   stats,
    })


@app.get("/report/{report_id}", response_class=HTMLResponse)
def report_detail(request: Request, report_id: int) -> HTMLResponse:
    row = db.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    data = json.loads(row["raw_json"])
    return templates.TemplateResponse("report.html", {
        "request":   request,
        "meta":      row,
        "report":    data,
        "system":    data.get("system", {}),
        "score":     data.get("score", {}),
        "matches":   data.get("score", {}).get("ranked_matches", []),
        "compliance": data.get("compliance_results", []),
    })


@app.post("/report/{report_id}/delete")
def delete_report_form(report_id: int) -> RedirectResponse:
    db.delete_report(report_id)
    return RedirectResponse("/", status_code=303)
