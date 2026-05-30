# AGENTS.md — Guidance for AI agents working on this repo

## Project Overview
QIP (Quantum Infinity Patcher) is a local-first CVE scanner and auto-patcher. It runs scanners inside a sandboxed Docker container, generates fix patches, and presents them via a local web UI for human review before deployment.

## Key Paths
- `src/qip/` — Host-side CLI (Click + FastAPI)
- `src/agent/` — Container-side pipeline (scanner → dedup → analyze → patch → validate → report)
- `web/` — Static review UI (vanilla JS, served by FastAPI)
- `tests/` — Pytest suite

## Conventions
- Python 3.11+, type hints everywhere
- Pydantic v2 models in `src/qip/models.py`
- All Docker interactions go through `src/qip/docker_manager.py`
- Agent writes output to `/output/report.json` inside container
- Config via `.qip.yaml` (Pydantic Settings with yaml loader)

## Running
```bash
pip install -e ".[dev]"
pytest
qip doctor && qip scan .
```
