"""
FastAPI application — Local AI Security Log Analyzer

Endpoints:
  POST /api/upload          Upload a log file
  POST /api/load-sample     Load the built-in Cultive8 sample log
  POST /api/analyze/{id}    Start analysis (supports ?model=...)
  GET  /api/status/{id}     Poll analysis progress and system stats
  GET  /api/report/{id}     Get final report
  GET  /api/models          List available local AI models
  GET  /api/health          System health check
  GET  /                    Serve the frontend
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

import psutil
import uvicorn
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.analyzer import (
    DEFAULT_MODEL,
    analyze_chunk,
    check_ollama_health,
    correlate_findings,
    get_log_text_budget,
)
from backend.chunker import chunk_log_lines, count_tokens, read_log_file
from backend.models import AnalysisReport, Finding, JobStatus, Severity

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Local AI Security Log Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# In-memory job state: job_id -> data dict
jobs: dict[str, dict] = {}

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB
ALLOWED_EXTENSIONS = {".log", ".txt"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_job(job_id: str) -> dict:
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return jobs[job_id]


def _add_log(job_id: str, message: str):
    """Append a message to the job's log."""
    if job_id in jobs:
        jobs[job_id]["status"].log_messages.append(message)
    logger.info("[%s] %s", job_id, message)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a log file for analysis."""
    if file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(400, f"Invalid file type '{ext}'. Allowed: {ALLOWED_EXTENSIONS}")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum: {MAX_FILE_SIZE // (1024*1024)} MB")
    if not content.strip():
        raise HTTPException(400, "File is empty")

    job_id = uuid.uuid4().hex[:12]
    filename = file.filename or "uploaded.log"
    save_path = UPLOAD_DIR / f"{job_id}_{filename}"
    save_path.write_bytes(content)

    text = content.decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if l.strip()]
    total_lines = len(lines)

    status = JobStatus(
        job_id=job_id,
        status="uploaded",
        filename=filename,
        total_lines=total_lines,
        file_size=len(content),
    )
    jobs[job_id] = {
        "status": status,
        "file_path": str(save_path),
        "lines": lines,
        "report": None,
        "model_name": DEFAULT_MODEL,
    }

    _add_log(job_id, f"File uploaded: {filename} ({total_lines} lines, {len(content)} bytes)")

    return {
        "job_id": job_id,
        "filename": filename,
        "total_lines": total_lines,
        "file_size": len(content),
    }


@app.post("/api/load-sample")
async def load_sample_log():
    """Quick-load the official Cultive8 assessment sample log."""
    candidate_paths = [
        Path("Cultive8_Workspace_Agrigen_Server.log"),
        Path(__file__).resolve().parent.parent / "Cultive8_Workspace_Agrigen_Server.log",
    ]
    sample_path = None
    for p in candidate_paths:
        if p.exists():
            sample_path = p
            break

    if not sample_path:
        raise HTTPException(404, "Sample log file not found on server")

    content = sample_path.read_bytes()
    job_id = uuid.uuid4().hex[:12]
    filename = "Cultive8_Workspace_Agrigen_Server.log"
    save_path = UPLOAD_DIR / f"{job_id}_{filename}"
    save_path.write_bytes(content)

    text = content.decode("utf-8", errors="replace")
    lines = [l for l in text.splitlines() if l.strip()]
    total_lines = len(lines)

    status = JobStatus(
        job_id=job_id,
        status="uploaded",
        filename=filename,
        total_lines=total_lines,
        file_size=len(content),
    )
    jobs[job_id] = {
        "status": status,
        "file_path": str(save_path),
        "lines": lines,
        "report": None,
        "model_name": DEFAULT_MODEL,
    }

    _add_log(job_id, f"Sample log loaded: {filename} ({total_lines} lines, {len(content)} bytes)")

    return {
        "job_id": job_id,
        "filename": filename,
        "total_lines": total_lines,
        "file_size": len(content),
    }


@app.get("/api/models")
async def list_models():
    """List available local models from Ollama."""
    health = await check_ollama_health()
    return health


@app.post("/api/analyze/{job_id}")
async def start_analysis(job_id: str, model: Optional[str] = Query(None)):
    """Start the analysis pipeline for an uploaded file."""
    job = _get_job(job_id)
    status: JobStatus = job["status"]

    if status.status in ("analyzing", "correlating"):
        return {"status": "already_running"}

    if model:
        job["model_name"] = model

    status.status = "analyzing"
    status.progress_percent = 0.0
    status.log_messages = status.log_messages[-5:]

    asyncio.create_task(_run_analysis(job_id))
    return {"status": "started", "model": job["model_name"]}


@app.get("/api/status/{job_id}")
async def get_status(job_id: str):
    """Get the current analysis status and resource utilization."""
    job = _get_job(job_id)
    status: JobStatus = job["status"]

    mem = psutil.virtual_memory()
    proc = psutil.Process()
    mem_info = proc.memory_info()

    return {
        **status.model_dump(),
        "model_name": job.get("model_name", DEFAULT_MODEL),
        "system": {
            "ram_used_mb": round(mem_info.rss / (1024 * 1024), 1),
            "ram_total_mb": round(mem.total / (1024 * 1024), 1),
            "ram_percent": mem.percent,
            "cpu_percent": psutil.cpu_percent(interval=0),
        },
    }


@app.get("/api/report/{job_id}")
async def get_report(job_id: str):
    """Get the final consolidated security analysis report."""
    job = _get_job(job_id)
    if job["report"] is None:
        raise HTTPException(400, "Analysis not complete yet")
    return job["report"].model_dump()


@app.get("/api/health")
async def health_check():
    """System health check and RAM tracking."""
    ollama = await check_ollama_health()
    mem = psutil.virtual_memory()
    return {
        "status": "ok",
        "ollama": ollama,
        "system": {
            "ram_total_mb": round(mem.total / (1024 * 1024), 1),
            "ram_used_mb": round(mem.used / (1024 * 1024), 1),
            "ram_percent": mem.percent,
        },
    }


# ---------------------------------------------------------------------------
# Static files (frontend)
# ---------------------------------------------------------------------------

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


@app.get("/")
async def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return JSONResponse({"message": "Frontend not found. Place index.html in /frontend/"})


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ---------------------------------------------------------------------------
# Analysis pipeline (background task)
# ---------------------------------------------------------------------------

async def _run_analysis(job_id: str):
    """Full analysis pipeline: chunk → analyze → correlate → report."""
    job = jobs[job_id]
    status: JobStatus = job["status"]
    model_name = job.get("model_name", DEFAULT_MODEL)
    start_time = time.time()

    try:
        lines = job["lines"]
        _add_log(job_id, f"Initiating AI security analysis using model: {model_name}")
        _add_log(job_id, f"Processing {len(lines)} log lines...")

        # --- Step 1: Chunking with strict 2048 token budget ---
        status.status = "chunking"
        log_budget = get_log_text_budget()
        _add_log(job_id, f"Token budget: {log_budget} tokens per chunk (leaves room for system prompt, context & reply)")

        chunks = chunk_log_lines(lines, max_chunk_tokens=log_budget, overlap_lines=0)
        status.total_chunks = len(chunks)
        _add_log(job_id, f"Log partitioned into {len(chunks)} token-bounded chunks (preserving line numbers)")

        # --- Step 2: Sequential Model Calls with Context Carry-Forward ---
        status.status = "analyzing"
        all_findings: list[Finding] = []
        context = ""
        total_model_calls = 0
        total_tokens = 0

        for i, chunk in enumerate(chunks):
            status.current_chunk = i + 1
            status.progress_percent = round(((i + 1) / (len(chunks) + 1)) * 85, 1)
            status.elapsed_seconds = round(time.time() - start_time, 1)

            _add_log(
                job_id,
                f"Analyzing chunk {i+1}/{len(chunks)} (lines {chunk['line_start']}-{chunk['line_end']}, {chunk['token_count']} tokens)...",
            )

            try:
                result = await analyze_chunk(chunk, i + 1, context, model=model_name)
                total_model_calls += 1
                total_tokens += chunk["token_count"]

                if result.findings:
                    all_findings.extend(result.findings)
                    status.findings_so_far = len(all_findings)
                    _add_log(job_id, f"  → Identified {len(result.findings)} finding(s) in chunk {i+1}")
                    for f in result.findings:
                        _add_log(job_id, f"    [{f.severity.value}] {f.attack_type} (IP: {f.source_ip}, lines: {f.evidence_lines})")
                else:
                    _add_log(job_id, f"  → Chunk {i+1}: Normal traffic / no threats detected")

                context = result.context_summary
                status.chunks_completed = i + 1

            except Exception as exc:
                _add_log(job_id, f"  ⚠ Chunk {i+1} analysis encountered error: {exc}")
                logger.exception("Chunk %d failed", i)

        # --- Step 3: Cross-Chunk Event Correlation ---
        status.status = "correlating"
        status.progress_percent = 90.0
        _add_log(job_id, f"Correlating {len(all_findings)} raw findings across all chunks...")

        try:
            merged = await correlate_findings(all_findings, lines, model=model_name)
            _add_log(job_id, f"Consolidated into {len(merged)} correlated security finding(s)")
        except Exception as exc:
            logger.warning("Correlation exception: %s", exc)
            _add_log(job_id, f"⚠ Correlation error: {exc}. Preserving individual findings.")
            merged = all_findings

        # --- Step 4: Final Report Assembly ---
        status.progress_percent = 98.0
        elapsed = time.time() - start_time

        severity_counts = {s.value: 0 for s in Severity}
        for f in merged:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        report = AnalysisReport(
            job_id=job_id,
            filename=status.filename,
            total_lines=status.total_lines,
            total_chunks=len(chunks),
            total_findings=len(merged),
            severity_counts=severity_counts,
            findings=merged,
            processing_time_seconds=round(elapsed, 2),
            model_name=model_name,
            total_model_calls=total_model_calls,
            total_tokens_used=total_tokens,
        )

        job["report"] = report
        status.status = "complete"
        status.progress_percent = 100.0
        status.elapsed_seconds = round(elapsed, 1)
        status.findings_so_far = len(merged)

        _add_log(job_id, "═" * 50)
        _add_log(job_id, f"✅ Analysis completed in {elapsed:.1f}s")
        _add_log(job_id, f"   Model: {model_name} | Chunks: {len(chunks)} | Calls: {total_model_calls}")
        _add_log(job_id, f"   Findings: {len(merged)}")
        for s in Severity:
            if severity_counts[s.value] > 0:
                _add_log(job_id, f"   • {s.value}: {severity_counts[s.value]}")

    except Exception as exc:
        status.status = "error"
        status.error = str(exc)
        status.elapsed_seconds = round(time.time() - start_time, 1)
        _add_log(job_id, f"❌ Analysis pipeline failed: {exc}")
        logger.exception("Analysis pipeline failed for %s", job_id)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
