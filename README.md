<div align="center">

# ⚛️ Quantum Infinity Patcher

### **Local-First Security CVE Agent**

*Scan. Fix. Review. Deploy — all without your code ever leaving your machine.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-required-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)]()

<br/>

<img src="https://img.shields.io/badge/🔒_Zero_Cloud-No_data_leaves_localhost-black?style=flat-square" alt="zero cloud"/>
<img src="https://img.shields.io/badge/🐳_Sandboxed-Docker_isolated_agent-black?style=flat-square" alt="sandboxed"/>
<img src="https://img.shields.io/badge/👁️_Human_Review-Before_any_deploy-black?style=flat-square" alt="human review"/>

</div>

---

## 🎯 What is QIP?

**Quantum Infinity Patcher** is a fully local, Docker-sandboxed security agent that:

1. 🔍 **Scans** your repo for known CVEs (using Grype, Trivy, pip-audit)
2. 🛠️ **Generates** fix patches automatically (dependency bumps + AST-level code fixes)
3. ✅ **Validates** patches (runs your test suite inside sandbox)
4. 👁️ **Presents** diffs in a local web UI for human review
5. 🚀 **Deploys** approved patches to your working tree via Git

> **No cloud. No SaaS. No telemetry.** Your code never leaves localhost.

---

## 📋 Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Windows 10 / macOS 12 / Ubuntu 20.04 | Latest stable |
| **Python** | 3.11 | 3.12+ |
| **Docker** | 24.0+ (Engine) | Docker Desktop latest |
| **RAM** | 4 GB free | 8 GB+ |
| **Disk** | 2 GB (images + vuln DBs) | SSD recommended |
| **Git** | 2.30+ | Latest |

<details>
<summary>📦 Python Dependencies</summary>

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `pydantic` | Config & data models |
| `docker` | Docker Engine SDK |
| `fastapi` + `uvicorn` | Review server |
| `gitpython` | Git operations for deploy |
| `rich` | Terminal formatting |
| `httpx` | HTTP client |
| `pyyaml` | Config file parsing |

</details>

---

## 🚀 Setup & Installation

### 1️⃣ Clone & Install

```powershell
git clone https://github.com/your-org/quantum-infinity-patcher.git
cd quantum-infinity-patcher

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Windows
# source .venv/bin/activate     # macOS/Linux

# Install with dev dependencies
pip install -e ".[dev]"
```

### 2️⃣ Verify Prerequisites

```powershell
qip doctor
```

This checks: Python version, Docker running, Git available, disk space.

### 3️⃣ Build the Agent Container

```powershell
qip build-agent
# Or manually: docker compose build agent
```

### 4️⃣ Scan Your Repository

```powershell
qip scan .                     # scan current directory
qip scan /path/to/other/repo   # scan any repo
```

### 5️⃣ Review Patches

```powershell
qip review    # opens http://localhost:8500
```

### 6️⃣ Deploy Approved Fixes

```powershell
qip deploy    # applies approved patches, creates git branch
```

---

## 🏗️ System Design & Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         YOUR MACHINE (localhost)                         │
│                                                                         │
│  ┌─────────┐     ┌──────────────────┐     ┌──────────────────────┐    │
│  │  $ qip  │────▶│  Docker Manager  │────▶│  Agent Container 🐳  │    │
│  │   CLI   │     │  (orchestrator)  │     │  ┌────────────────┐  │    │
│  └────┬────┘     └──────────────────┘     │  │   Scanner      │  │    │
│       │                                    │  │   (grype/trivy) │  │    │
│       │                                    │  ├────────────────┤  │    │
│       │          ┌──────────────────┐     │  │  Deduplicator  │  │    │
│       │          │  Review Server   │     │  ├────────────────┤  │    │
│       ├─────────▶│  (FastAPI:8500)  │     │  │   Analyzer     │  │    │
│       │          │  ┌────────────┐  │     │  ├────────────────┤  │    │
│       │          │  │  Web UI 🌐 │  │     │  │   Patcher      │  │    │
│       │          │  └────────────┘  │     │  ├────────────────┤  │    │
│       │          └──────────────────┘     │  │  Validator ✅  │  │    │
│       │                                    │  ├────────────────┤  │    │
│       ▼          ┌──────────────────┐     │  │  Reporter 📄   │  │    │
│  ┌─────────┐     │  History DB      │     │  └────────────────┘  │    │
│  │ Deployer│     │  (SQLite)        │     └──────────────────────┘    │
│  │  (Git)  │     └──────────────────┘                                  │
│  └─────────┘                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Agent Pipeline (inside container)

```
 ┌────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐    ┌──────────┐    ┌────────┐
 │  SCAN  │───▶│  DEDUP   │───▶│ ANALYZE  │───▶│ PATCH  │───▶│ VALIDATE │───▶│ REPORT │
 │        │    │          │    │          │    │        │    │          │    │        │
 │ Grype  │    │ Merge    │    │ Rank by  │    │ Dep    │    │ Build &  │    │ JSON   │
 │ Trivy  │    │ duplicates│   │ severity │    │ bumps  │    │ test     │    │ output │
 │ Audit  │    │ & merge  │    │ & fixable│    │ + AST  │    │ each fix │    │        │
 └────────┘    └──────────┘    └──────────┘    └────────┘    └──────────┘    └────────┘
```

### Data Flow

```
Repo (read-only mount)
    │
    ▼
/repo → scanners read source & lockfiles
    │
    ▼
/output/report.json → findings + patches + diffs
    │
    ▼
Host reads report → serves in Review UI
    │
    ▼
User approves → Deployer applies patches via GitPython
```

---

## 🔒 Security Model

| Layer | Protection |
|-------|-----------|
| **Network** | `--network=none` — container has zero internet access during scan |
| **Filesystem** | Repo mounted as `:ro` (read-only) |
| **Output** | Single `/output` volume — only way data exits container |
| **User** | Agent runs as non-root (`uid=1000`) inside container |
| **Secrets** | No tokens, API keys, or credentials inside container |
| **Review** | Every patch requires explicit human approval before deploy |
| **Blast radius** | Container is ephemeral — destroyed after each run |

---

## ⌨️ CLI Reference

```
Usage: qip [OPTIONS] COMMAND [ARGS]...

Commands:
  scan         🔍 Scan a repository for CVEs and generate patches
  review       👁️ Launch review UI server (localhost:8500)
  deploy       🚀 Apply approved patches to working tree
  history      📜 Show past scan runs and results
  doctor       🩺 Verify system prerequisites
  build-agent  🐳 Build/rebuild the agent Docker image
```

| Command | Example | Description |
|---------|---------|-------------|
| `qip scan <path>` | `qip scan .` | Scan repo, produce patches |
| `qip scan --severity high` | | Only report high+ CVEs |
| `qip review` | | Open browser review UI |
| `qip review --port 9000` | | Custom port |
| `qip deploy` | | Apply approved patches |
| `qip deploy --branch fix/cves` | | Custom branch name |
| `qip history` | | List previous runs |
| `qip history --run-id abc123` | | Details of specific run |
| `qip doctor` | | Check prerequisites |

---

## 🌐 Review UI

A sleek local web interface at `http://localhost:8500`:

- **Side-by-side diffs** for each patch
- **Severity badges** (critical / high / medium / low)
- **One-click** approve / reject / skip
- **Keyboard shortcuts** for power users:

| Key | Action |
|:---:|--------|
| `a` | ✅ Approve current patch |
| `r` | ❌ Reject current patch |
| `s` | ⏭️ Skip (decide later) |
| `j` | ⬇️ Next patch |
| `k` | ⬆️ Previous patch |
| `?` | 📖 Toggle help overlay |

---

## ⚙️ Configuration

Create `.qip.yaml` in your project root:

```yaml
# Scanner selection
scanners:
  - grype
  - pip-audit
  # - trivy
  # - npm-audit

# Minimum severity to report
severity_threshold: medium   # low | medium | high | critical

# Auto-approve patches with confidence above this threshold
auto_approve_confidence: 0.95

# Max patches per scan run
max_patches_per_run: 20

# Test command to validate patches
test_command: "pytest --tb=short -q"

# Review server settings
review:
  host: "127.0.0.1"
  port: 8500

# Docker resource limits
docker:
  image: "qip-agent:latest"
  memory_limit: "2g"
  cpu_limit: 2
```

---

## 🗂️ Project Structure

```
quantum-infinity-patcher/
├── src/
│   ├── qip/                    # 🖥️ Host-side CLI & orchestration
│   │   ├── cli.py              #    Click CLI commands
│   │   ├── config.py           #    Pydantic Settings + YAML loader
│   │   ├── models.py           #    Shared data models
│   │   ├── docker_manager.py   #    Container lifecycle management
│   │   ├── reviewer.py         #    FastAPI review server
│   │   ├── deployer.py         #    Git-based patch deployment
│   │   ├── doctor.py           #    Prerequisite health checks
│   │   ├── history.py          #    SQLite run history
│   │   └── utils.py            #    Shared utilities
│   │
│   └── agent/                  # 🐳 Runs INSIDE Docker container
│       ├── main.py             #    Pipeline orchestrator
│       ├── scanner.py          #    Multi-scanner executor
│       ├── deduplicator.py     #    Findings deduplication
│       ├── analyzer.py         #    Severity ranking & fixability
│       ├── patcher.py          #    Patch generation engine
│       ├── validator.py        #    Build + test validation
│       ├── reporter.py         #    JSON report generation
│       └── patchers/           #    Fix strategy plugins
│           └── dep_bump.py     #    Dependency version bumps
│
├── web/                        # 🌐 Review UI (static, served by FastAPI)
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── tests/                      # 🧪 Pytest suite
├── scripts/                    # 🔧 Setup & build helpers
├── Dockerfile                  # Agent container definition
├── docker-compose.yaml
├── pyproject.toml
├── .qip.example.yaml           # Example configuration
└── AGENTS.md                   # AI agent guidance
```

---

## 🧩 Supported Ecosystems

| Ecosystem | Scanner | Fix Strategy |
|-----------|---------|-------------|
| **Python** (pip/poetry) | `pip-audit`, `grype` | Bump in `requirements.txt` / `pyproject.toml` |
| **Node.js** (npm/yarn) | `npm audit`, `grype` | Bump in `package.json` |
| **Go** | `grype`, `trivy` | Bump in `go.mod` |
| **Rust** | `grype`, `trivy` | Bump in `Cargo.toml` |
| **Java** (Maven/Gradle) | `grype`, `trivy` | Bump in `pom.xml` / `build.gradle` |
| **Container images** | `grype`, `trivy` | Update base image tag |

---

## 📊 How It Compares

| Feature | Snyk | Dependabot | QIP |
|---------|------|-----------|-----|
| Code stays local | ❌ | ❌ | ✅ |
| Works offline | ❌ | ❌ | ✅* |
| AST-level fixes | ❌ | ❌ | ✅ |
| Human review UI | PR-based | PR-based | Instant local UI |
| Sandboxed execution | ❌ | ❌ | Docker isolated |
| Cost | 💰 | Free (limited) | 🆓 Forever |

<sub>* After initial vulnerability database sync</sub>

---

## 🗺️ Roadmap

- [x] Multi-scanner support (Grype + pip-audit)
- [x] Docker sandbox with network isolation
- [x] Local review web UI with keyboard shortcuts
- [x] Git-based deployment with branch creation
- [ ] AST-level code patching (beyond dep bumps)
- [ ] LLM-assisted fix generation (local models)
- [ ] Plugin system for custom scanners
- [ ] Scheduled background scans (cron/watch mode)
- [ ] VS Code extension integration
- [ ] Air-gapped vulnerability DB sync

---

## 🧑‍💻 Development

```powershell
# Install in editable mode with dev deps
pip install -e ".[dev]"

# Run tests
pytest

# Lint & format
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

---

## 📄 License

MIT — use it, fork it, fix the world. 🌍
