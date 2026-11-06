# Local AI Security Log Analyzer

A web application that uses a **locally-running AI model** to analyze server logs for security threats. It splits log files into token-bounded chunks, processes each through a local language model, correlates findings across chunks, and produces a unified security report.

> Built for the Cultive8 Developer Assessment — November 2026

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Ollama** — local model runtime ([install guide](https://ollama.ai/download))

### 1. Install Ollama and pull the model

```bash
# Install Ollama (if not already installed)
# Windows: Download from https://ollama.ai/download or winget install Ollama.Ollama
# Linux: curl -fsSL https://ollama.ai/install.sh | sh

# Pull the recommended Qwen 2.5 1.5B model (~986MB, fits well within 4GB RAM)
ollama pull qwen2.5:1.5b

# Optional: Ultra-lightweight model (~397MB) for low-resource environments
ollama pull qwen2.5:0.5b
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the application

```bash
# Make sure Ollama is running first (it starts automatically on install)
# Then start the backend:
python -m backend.main
```

The app will be available at **http://localhost:8000**.

### 4. Analyze logs

1. Open http://localhost:8000 in your browser
2. Upload the provided `.log` file (drag & drop or click to browse)
3. Click **Start Analysis**
4. Watch the real-time progress as each chunk is analyzed
5. Review the consolidated security report

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Frontend (HTML/JS)              │
│  Upload → Progress → Report                     │
└─────────┬───────────────────────────┬───────────┘
          │ REST API                  │ Polling
┌─────────▼───────────────────────────▼───────────┐
│              FastAPI Backend                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Chunker  │ │ Analyzer │ │   Correlator     │ │
│  │ (split + │ │ (Ollama  │ │ (merge + link    │ │
│  │  tokens) │ │  client) │ │  cross-chunk)    │ │
│  └──────────┘ └──────────┘ └──────────────────┘ │
└─────────┬───────────────────────────────────────┘
          │ HTTP API
┌─────────▼───────────────────────────────────────┐
│         Ollama (localhost:11434)                  │
│         Model: qwen3:0.6b (~400MB)               │
│         Context: 2048 tokens                     │
└─────────────────────────────────────────────────┘
```

## Model Details
 
| Property | Value |
|----------|-------|
| Default Model | Qwen 2.5 1.5B (`qwen2.5:1.5b` via Ollama) |
| Fallback Model | Qwen 2.5 0.5B (`qwen2.5:0.5b` via Ollama) |
| Runtime | Local Ollama daemon (`localhost:11434`) |
| Context window | 2,048 tokens per call |
| RAM usage | ~1.1 GB total (model + backend) — comfortably within 4 GB limit |
| Quantization | 4-bit / Q4_K_M (Ollama default) |

### Why Qwen 2.5 1.5B?

- **Ideal Footprint**: ~986MB download, ~1.1GB RAM — leaves 2.8+ GB free on a 4GB system.
- **Strict JSON Adherence**: Consistently produces clean JSON according to schema without token repetition.
- **Fast 2 vCPU Inference**: ~5-8 seconds per chunk without requiring a GPU.
- **Qwen family**: Fully compliant with the assessment brief recommendations.

### Model Switching

You can switch models directly from the web interface dropdown or via the API:
- `qwen2.5:1.5b` (Default, recommended balance of intelligence and RAM)
- `qwen2.5:0.5b` (Ultra-lightweight, 397 MB)
- Any other installed Ollama model automatically populates in the UI selector.

## Log Splitting Method

### Token Budget Allocation (2048 total)

| Component | Tokens | Purpose |
|-----------|--------|---------|
| System prompt | ~180 | Security analyzer instructions + output format |
| Prompt template | ~150 | Analysis instructions + context section |
| Context carry-forward | ~100 | Key facts from previous chunks |
| **Log text** | **~800** | **Actual log lines with [L<n>] prefixes** |
| Response budget | ~500 | Reserved for model output |
| Safety margin | ~318 | Buffer for tokenizer differences |

### Chunking Strategy

1. **Line-level splitting**: Never cuts mid-line; each log entry stays intact
2. **Token counting**: Uses `tiktoken` (cl100k_base) for approximate token counts with safety margin
3. **Line number preservation**: Each line gets a `[L<n>]` prefix so the model can reference original line numbers in evidence
4. **Overlap**: Optional 1-line overlap between chunks for context continuity
5. **Sequential processing**: Chunks processed one at a time to respect RAM limits

### Cross-Chunk Correlation

Each chunk analysis returns a `context_summary` — a compact summary of key observations (suspicious IPs, ongoing attack patterns). This summary is injected into the next chunk's prompt, enabling the model to:

- **Track persistent threats** across chunks (e.g., brute-force over time)
- **Link related events** (e.g., failed logins in chunk 1 + successful login in chunk 5)
- **Accumulate evidence** for the final correlation pass

A final **correlation pass** merges findings by `(source_ip, attack_type)` and checks for compound attack patterns:
- Brute-force → successful login = escalated to **Critical** (account compromise)
- Multiple vulnerability scans from same IP = consolidated into single finding

## Security Findings Detected

The analyzer looks for:

| Attack Type | Indicators |
|-------------|-----------|
| **Brute Force / Account Compromise** | Repeated 401s on login endpoints from same IP, followed by 200 |
| **SQL Injection** | URL-encoded SQL syntax in query parameters (`OR 1=1`, `UNION SELECT`, `SLEEP()`) |
| **Vulnerability Scanning** | Probing `.env`, `.git/config`, `wp-admin`, `phpmyadmin`, `actuator`, `backup.sql` |
| **Path Traversal** | `../../../etc/passwd` patterns in file parameters |
| **Rate Limiting Abuse** | High `requests_in_window` counts, 429 responses |
| **Prompt Injection** | Attempts to inject instructions via user-facing text fields |

## Error Handling

- **Model timeouts**: Retries up to 3 times with exponential backoff
- **JSON parsing**: Multi-level fallback — direct parse → brace matching → bracket repair
- **Chunk failures**: Failed chunks are logged but don't halt the pipeline; completed findings are preserved
- **Invalid uploads**: File type, size, and emptiness validation
- **Prompt injection**: System prompt instructs model to treat all log content as data

## Known Limitations

1. **Small model accuracy**: Qwen3 0.6B occasionally misses subtle attack patterns or produces partial JSON. The rule-based fallback merger compensates.
2. **Token approximation**: `tiktoken` (cl100k_base) is not the exact Qwen tokenizer. A 20% safety margin accounts for this.
3. **Sequential processing**: Chunks are processed one at a time (serial, not parallel) to stay within RAM limits. Analysis of a 259-line file takes ~30-60 seconds.
4. **No persistent storage**: Job state is in-memory only. Restarting the server clears previous analyses.

## Project Structure

```
Cultive8/
├── backend/
│   ├── __init__.py
│   ├── main.py          # FastAPI app, routes, analysis pipeline
│   ├── analyzer.py      # Ollama client, JSON parsing, correlation
│   ├── chunker.py       # Log splitting with token counting
│   ├── models.py        # Pydantic data models
│   └── prompts.py       # AI prompt templates
├── frontend/
│   └── index.html       # Single-page dashboard (HTML/CSS/JS)
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── AI_USAGE.md          # AI tool usage documentation
└── Cultive8_Workspace_Agrigen_Server.log  # Sample log file
```

## Tech Stack

- **Backend**: Python 3.11, FastAPI, uvicorn
- **AI Runtime**: Ollama + Qwen3 0.6B (GGUF, Q4_K_M)
- **Token Counting**: tiktoken (cl100k_base encoding)
- **Frontend**: Vanilla HTML/CSS/JavaScript (no build step)
- **Monitoring**: psutil for RAM/CPU tracking

## Optional Extras Implemented

- ✅ RAM usage and model timing displayed in UI
- ✅ Real-time progress tracking with live log
- ✅ Token usage statistics per chunk
- ✅ Configurable model (change `MODEL_NAME` in analyzer.py)
- ✅ Download report as JSON
