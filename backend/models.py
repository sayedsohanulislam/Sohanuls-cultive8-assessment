"""
Pydantic models for the log analyzer application.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Finding(BaseModel):
    """A single security finding detected in the logs."""
    id: str = Field(description="Unique finding identifier")
    attack_type: str = Field(description="Type of attack, e.g. Brute Force, SQL Injection")
    severity: Severity = Field(description="Severity level")
    source_ip: str = Field(description="Source IP address or identifier")
    evidence_lines: list[int] = Field(default_factory=list, description="Line numbers in the log file")
    description: str = Field(description="Short human-readable description")
    reason: str = Field(description="Why this is considered an attack")
    recommended_action: str = Field(description="Suggested remediation")
    related_finding_ids: list[str] = Field(default_factory=list, description="IDs of related findings")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    event_count: int = 1


class ChunkResult(BaseModel):
    """Result from analyzing a single chunk."""
    chunk_index: int
    line_start: int
    line_end: int
    findings: list[Finding] = Field(default_factory=list)
    context_summary: str = Field(default="", description="Key facts to carry to next chunk")
    raw_response: str = Field(default="", description="Raw model response for debugging")


class AnalysisReport(BaseModel):
    """Final consolidated analysis report."""
    job_id: str
    filename: str
    total_lines: int
    total_chunks: int
    total_findings: int
    severity_counts: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    processing_time_seconds: float = 0.0
    model_name: str = ""
    total_model_calls: int = 0
    total_tokens_used: int = 0


class JobStatus(BaseModel):
    """Status of an analysis job."""
    job_id: str
    status: str = "pending"  # pending, uploading, chunking, analyzing, correlating, complete, error
    progress_percent: float = 0.0
    current_chunk: int = 0
    total_chunks: int = 0
    chunks_completed: int = 0
    findings_so_far: int = 0
    elapsed_seconds: float = 0.0
    log_messages: list[str] = Field(default_factory=list)
    error: Optional[str] = None
    filename: str = ""
    total_lines: int = 0
    file_size: int = 0
