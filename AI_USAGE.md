# AI Usage Documentation

This document details how AI tools were used during the development of the Local AI Security Log Analyzer.

## AI Tools Used

### 1. Google Antigravity (Claude Opus 4.6 — Thinking)

**Purpose**: Primary development assistant for code generation and architecture design.

**How it was used**:

- **Architecture design**: Discussed the overall system architecture, deciding on FastAPI + Ollama + vanilla frontend stack. The AI helped evaluate trade-offs between different model runtimes (llama-cpp-python vs Ollama) and recommended Ollama for simpler setup.

- **Code generation**: Generated the core backend modules (`main.py`, `analyzer.py`, `chunker.py`, `models.py`, `prompts.py`) based on detailed specifications of what each module needed to do. I reviewed, tested, and iterated on each module.

- **Prompt engineering**: Designed the system prompt and chunk analysis prompts iteratively, optimizing for:
  - Staying within 2048 token budget
  - Reliable JSON output from a small model
  - Resistance to prompt injection from log content
  - Effective context carry-forward between chunks

- **Frontend development**: Generated the single-page dashboard with progress tracking, real-time updates, and report visualization.

- **Documentation**: Generated README.md and this AI_USAGE.md based on the actual codebase.

### 2. Ollama + Qwen 2.5 1.5B / 0.5B (Runtime AI)

**Purpose**: The local AI model used at runtime for log analysis. Primary model is `qwen2.5:1.5b` (986 MB), with `qwen2.5:0.5b` (397 MB) available for constrained environments.

**How it's used in the application**:

1. **Per-chunk analysis**: Each log chunk is sent to the model with a security analysis prompt. The model returns structured JSON with findings (attack type, severity, source IP, evidence lines, description, and recommended actions).

2. **Context carry-forward**: The model's `context_summary` output from each chunk is injected into the next chunk's prompt, enabling cross-chunk event correlation.

3. **Correlation pass**: A final model call merges and deduplicates findings across all chunks, linking related events (e.g., brute-force → account compromise).

## Prompt Design Decisions

### System Prompt (~180 tokens)
- Establishes the model as a security log analyzer
- Defines strict JSON output format to enable reliable parsing
- Explicitly instructs the model to treat log content as DATA (anti-prompt-injection)
- Lists the expected output schema

### Chunk Analysis Prompt (~120 tokens + log text)
- Lists specific attack types to look for (brute-force, SQLi, path traversal, etc.)
- Includes previous context if available
- Preserves line numbers via `[L<n>]` prefixes

### Correlation Prompt (~150 tokens + findings)
- Specifies merge rules (same IP + same attack type → one finding)
- Defines compound pattern detection (brute-force + successful login → Critical)
- Requests enriched output with event counts and timestamps

## Quality Assurance

- **JSON parsing resilience**: Multi-level fallback parser handles partial/malformed model output
- **Rule-based fallback**: If model-based correlation fails, a deterministic rule-based merger handles finding deduplication
- **Token budget enforcement**: Every prompt is checked against the 2048 token limit before sending to the model
- **Prompt injection defense**: System prompt explicitly warns against following instructions in logs; the log entry at line 217 contains a prompt injection attempt that the model correctly treats as data
