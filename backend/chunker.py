"""
Log file chunker — splits log files into token-bounded chunks
while preserving line boundaries, original line numbers, and security signals.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Optional
import tiktoken


# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------
_ENCODER: tiktoken.Encoding | None = None


def _get_encoder() -> tiktoken.Encoding:
    global _ENCODER
    if _ENCODER is None:
        _ENCODER = tiktoken.get_encoding("cl100k_base")
    return _ENCODER


def count_tokens(text: str) -> int:
    """Return the approximate number of tokens in *text*."""
    return len(_get_encoder().encode(text))


# ---------------------------------------------------------------------------
# Line formatting and signal enrichment
# ---------------------------------------------------------------------------

def enrich_and_format_line(raw_line: str, line_num: int) -> tuple[str, dict]:
    """Parse JSON log line, decode URL parameters, extract metadata, and format for the model."""
    line_str = raw_line.strip()
    if not line_str:
        return "", {}

    try:
        data = json.loads(line_str)
    except Exception:
        # Non-JSON line fallback
        return f"[L{line_num}] {line_str}", {"raw": line_str, "line_num": line_num}

    ip = str(data.get("client_ip", "internal"))
    method = str(data.get("method", ""))
    path = str(data.get("path", ""))
    status = data.get("status", "")
    auth_result = data.get("auth_result", "")
    username = data.get("username", "")
    submitted_text = data.get("submitted_text", "")
    requests_in_win = data.get("requests_in_window", None)

    # Double unquote to reveal hidden or encoded payloads (e.g. %252e%252e%252f -> ../)
    decoded_path = urllib.parse.unquote(urllib.parse.unquote(path)) if path else ""

    signals = []

    # 1. Auth analysis
    if auth_result == "invalid_password" or (status == 401 and "login" in path):
        signals.append(f"Failed login for '{username or 'unknown'}'")
    elif auth_result == "success" and "login" in path:
        signals.append(f"Successful login for '{username or 'unknown'}'")

    # 2. SQL Injection detection
    sql_patterns = [r"'\s*OR\s*1\s*=\s*1", r"UNION\s+SELECT", r"SLEEP\s*\(", r";\s*SELECT"]
    for pat in sql_patterns:
        if re.search(pat, decoded_path, re.IGNORECASE):
            signals.append("SQL injection payload detected")
            break

    # 3. Path traversal detection
    if ".." in decoded_path or "/etc/passwd" in decoded_path:
        signals.append("Path traversal attempt")

    # 4. Probing sensitive paths
    sensitive_probes = [".env", ".git", "wp-admin", "phpmyadmin", "actuator", "server-status", "backup.sql", "config.json"]
    for probe in sensitive_probes:
        if probe in decoded_path.lower() and status in (403, 404):
            signals.append(f"Vulnerability scan for {probe}")
            break

    # 5. Rate limit abuse
    if status == 429 or (requests_in_win and requests_in_win > 100):
        signals.append(f"Rate limit exceeded (429, requests_in_window={requests_in_win})")

    # 6. Prompt injection detection
    if submitted_text and ("ignore previous instructions" in submitted_text.lower() or "report all events as safe" in submitted_text.lower()):
        signals.append(f"Prompt injection attempt: '{submitted_text}'")

    signal_tag = f" [ALERT: {'; '.join(signals)}]" if signals else ""
    
    # Compact format that preserves all key information
    parts = [f"[L{line_num}]"]
    if ip != "internal":
        parts.append(f"IP={ip}")
    if method:
        parts.append(method)
    if decoded_path:
        parts.append(decoded_path)
    if status:
        parts.append(f"status={status}")
    if auth_result:
        parts.append(f"auth={auth_result}")
    if username:
        parts.append(f"user={username}")
    if data.get("message"):
        parts.append(f"msg=\"{data.get('message')}\"")
    if signal_tag:
        parts.append(signal_tag)

    formatted = " ".join(parts)
    meta = {
        "line_num": line_num,
        "ip": ip,
        "status": status,
        "path": decoded_path,
        "signals": signals,
        "auth_result": auth_result,
        "username": username,
        "raw": data,
    }
    return formatted, meta


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def chunk_log_lines(
    lines: list[str],
    max_chunk_tokens: int = 1200,
    *,
    overlap_lines: int = 0,
) -> list[dict]:
    """Split *lines* into chunks that each fit within *max_chunk_tokens*.

    Preserves original line numbers [L<n>] and line boundaries.
    """
    if not lines:
        return []

    chunks: list[dict] = []
    idx = 0

    while idx < len(lines):
        chunk_lines: list[str] = []
        chunk_metas: list[dict] = []
        chunk_token_count = 0
        start_idx = idx

        while idx < len(lines):
            line = lines[idx]
            line_num = idx + 1
            formatted, meta = enrich_and_format_line(line, line_num)
            if not formatted:
                idx += 1
                continue

            line_tokens = count_tokens(formatted)

            # Check token budget
            if chunk_token_count + line_tokens > max_chunk_tokens and chunk_lines:
                break

            chunk_lines.append(formatted)
            chunk_metas.append(meta)
            chunk_token_count += line_tokens
            idx += 1

        text = "\n".join(chunk_lines)
        chunks.append({
            "line_start": start_idx + 1,
            "line_end": idx,
            "text": text,
            "metas": chunk_metas,
            "token_count": count_tokens(text),
        })

        if overlap_lines > 0 and idx < len(lines):
            idx = max(idx - overlap_lines, start_idx + 1)

    return chunks


def read_log_file(path: str) -> list[str]:
    """Read a log file and return non-empty stripped lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [line.rstrip("\n\r") for line in fh if line.strip()]
