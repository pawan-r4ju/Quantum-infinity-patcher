# 🛡️ Quantum Infinity Patcher — Local-First Security CVE Agent

> *Scan. Fix. Review. Deploy. All on your machine. The quantum way.* ⚛️

![CI status](https://img.shields.io/badge/build-passing-brightgreen) ![License](https://img.shields.io/badge/license-MIT-blue) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

**Quantum Infinity Patcher (QIP)** is a fully local, sandboxed security agent that scans your repositories for CVEs, auto-generates fixes, presents them for human review, and deploys approved patches — all without your code ever leaving your machine.

Inspired by OpenClaw's local-first agent architecture: your code stays yours. No cloud. No SaaS. No telemetry. Just a Docker sandbox, a CLI, and you.

---

## Table of Contents

- [Why QIP](#why-qip)
- [Mental Model](#mental-model)
- [Architecture](#architecture)
- [Core Concepts](#core-concepts)
- [CLI Reference](#cli-reference)
- [Agent Pipeline](#agent-pipeline)
- [Sandbox Security Model](#sandbox-security-model)
- [Review System](#review-system)
- [Deploy & Git Integration](#deploy--git-integration)
- [Configuration](#configuration)
- [Supported Ecosystems](#supported-ecosystems)
- [Fix Generation Strategy](#fix-generation-strategy)
- [Observability & History](#observability--history)
- [Plugin / Skill Architecture](#plugin--skill-architecture)
- [Project Structure](#project-structure)
- [System Requirements](#system-requirements)
- [Roadmap & Milestones](#roadmap--milestones)
- [Tech Stack](#tech-stack)
- [Success Metrics](#success-metrics)
- [Contributing](#contributing)

---

## Why QIP

Existing security tools have a trust problem:

| Problem | Snyk / Dependabot / etc. | QIP |
|---|---|---|
| Code leaves your machine | ✅ Uploaded to cloud | ❌ Never leaves localhost |
| Requires SaaS account | ✅ Mandatory | ❌ Fully offline-capable |
| Auto-fixes code-level vulns | ❌ Dependency bumps only | ✅ AST-level code patches |
| Human review before deploy | ⚠️ PR-based, delayed | ✅ Local UI, instant review |
| Works in air-gapped environments | ❌ | ✅ After initial DB sync |
| Agent runs sandboxed | ❌ Runs in your CI | ✅ Isolated Docker container |
| Cost | 💰 Per-repo pricing | 🆓 Free forever |

---

## Mental Model

Think of QIP like OpenClaw, but instead of a personal AI assistant, it's a **personal security engineer** that lives in a Docker sandbox on your laptop.

```
You write code → QIP scans it in a sandbox → QIP proposes fixes →
You review locally → You approve → QIP commits to a branch → Done.
```

The agent **never modifies your repo directly**. It works on a read-only mount, writes proposed patches to a separate output volume, and only touches your repo after explicit human approval via the review UI.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (Your PC)                        │
│                                                                      │
│  ┌─────────────────┐          ┌────────────────────────────────────┐ │
│  │   QIP CLI        │          │   Review Server (localhost:8500)   │ │
│  │                  │          │                                    │ │
│  │  qip scan        │◄────────►│  Side-by-side diff viewer          │ │
│  │  qip review      │          │  CVE metadata + CVSS scores        │ │
│  │  qip deploy      │          │  Approve / Reject / Edit           │ │
│  │  qip history     │          │  Batch actions by severity          │ │
│  │  qip doctor      │          │  Confidence indicators              │ │
│  │  qip db update   │          │  Test validation results            │ │
│  │  qip status      │          └────────────────────────────────────┘ │
│  │  qip config      │                                                │
│  └────────┬─────────┘                                                │
│           │                                                          │
│           │ Docker Engine API                                        │
│           ▼                                                          │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │            DOCKER SANDBOX (qip-agent container)                │  │
│  │            Non-root │ No network (patch phase) │ Resource-capped│  │
│  │                                                                │  │
│  │  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌──────────────┐  │  │
│  │  │ Scanner  │  │ Analyzer  │  │ Patcher  │  │ Validator    │  │  │
│  │  │          │  │           │  │          │  │              │  │  │
│  │  │ Grype    │→│ Dedup     │→│ Dep bump │→│ Run tests    │  │  │
│  │  │ Trivy    │  │ CVSS      │  │ Config   │  │ Diff check   │  │  │
│  │  │ OSV-scan │  │ Reachable │  │ AST fix  │  │ Lint check   │  │  │
│  │  │ Native   │  │ analysis  │  │          │  │              │  │  │
│  │  └──────────┘  └───────────┘  └──────────┘  └──────────────┘  │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │                    Reporter                              │  │  │
│  │  │  → patches/*.patch   (git-format diffs)                  │  │  │
│  │  │  → report.json       (machine-readable full results)     │  │  │
│  │  │  → summary.md        (human-readable overview)           │  │  │
│  │  │  → evidence/         (test logs, screenshots, traces)    │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  Volume Mounts:                                                │  │
│  │   /repo       ← read-only bind from host repo                 │  │
│  │   /output     → writable bind to .qip/scans/<run-id>/         │  │
│  │   /vuln-db    ← read-only bind from ~/.qip/vuln-db/           │  │
│  │   /skills     ← read-only bind from ~/.qip/skills/            │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              Local Stores (persisted on host)                  │  │
│  │                                                                │  │
│  │  ~/.qip/                                                       │  │
│  │  ├── config.yaml          Global user config                   │  │
│  │  ├── vuln-db/             OSV + NVD local mirror               │  │
│  │  ├── skills/              Custom scan/patch skills              │  │
│  │  ├── history.db           SQLite scan history + audit log      │  │
│  │  └── cache/               Scanner binary cache                 │  │
│  │                                                                │  │
│  │  <repo>/.qip/                                                  │  │
│  │  ├── config.yaml          Repo-level config overrides          │  │
│  │  ├── scans/               Scan run outputs (by run ID)         │  │
│  │  │   └── <run-id>/                                             │  │
│  │  │       ├── patches/     Generated .patch files               │  │
│  │  │       ├── evidence/    Test logs, traces, proofs            │  │
│  │  │       ├── report.json  Full structured results              │  │
│  │  │       └── summary.md   Human-readable overview              │  │
│  │  ├── approved/            Patches approved via review          │  │
│  │  └── .gitignore           Auto-generated                       │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Core Concepts

### Agent

The QIP Agent is a Docker container that runs the scan-analyze-patch-validate pipeline. It is stateless — every `qip scan` creates a fresh container with a unique `run_id`. The agent has:

- **Read-only access** to your repo (bind mount)
- **Read-only access** to the local vulnerability database
- **Write access only** to the output volume (`.qip/scans/<run-id>/`)
- **No network** during the patch phase (network disabled after initial scanner DB sync)
- **No Docker socket** access (cannot escape to host)
- **Resource caps** (configurable CPU/RAM limits)

### Run

Every `qip scan` produces a **Run** — an immutable record of what was scanned, what was found, and what fixes were proposed. Runs are identified by a unique `run_id` (e.g., `qip_2026-05-30_a7f3b2`) and stored in `.qip/scans/<run-id>/`.

### Patch

A Patch is a git-format diff file (`.patch`) that represents a single proposed fix for a single CVE. Each patch includes:

- The diff itself
- Metadata: CVE ID, CVSS score, severity, affected component, confidence level
- Evidence: test results, reachability analysis, before/after comparison

### Skill

Skills are pluggable scanner/patcher modules (inspired by OpenClaw skills). A skill is a directory with a `SKILL.md` manifest and an executable. Built-in skills cover major ecosystems; custom skills let you add organization-specific scanners or fix patterns.

### Review Session

A local web UI session where you inspect proposed patches, approve/reject them, optionally edit before applying, and trigger deployment. No data leaves localhost.

---

## CLI Reference

```
qip <command> [options]
```

### Lifecycle Commands

| Command | Description |
|---|---|
| `qip init` | Initialize QIP in a repo (creates `.qip/config.yaml`, `.qip/.gitignore`) |
| `qip scan [path]` | Build agent image, mount repo read-only, run full pipeline, output patches |
| `qip review [run-id]` | Launch local review UI for a scan run (latest if omitted) |
| `qip deploy [run-id]` | Apply approved patches, create branch, commit |
| `qip status` | Show current scan state, pending reviews, recent history |

### Database & Maintenance

| Command | Description |
|---|---|
| `qip db update` | Sync OSV/NVD vulnerability database to local cache |
| `qip db status` | Show DB freshness, size, last sync time |
| `qip doctor` | Verify Docker, Git, Python, disk space, config validity |
| `qip cache clean` | Remove old scan outputs, stale images, orphan containers |

### History & Observability

| Command | Description |
|---|---|
| `qip history` | List past scan runs with stats (findings, fixes, approvals) |
| `qip history show <run-id>` | Detail view of a specific run |
| `qip diff <run-id> [patch-id]` | Show a patch diff in terminal |
| `qip report <run-id>` | Open the human-readable summary in browser/pager |
| `qip compare <run-id-1> <run-id-2>` | Compare two runs (new/fixed/persistent CVEs) |

### Configuration

| Command | Description |
|---|---|
| `qip config show` | Print resolved config (flags → env → repo → user → defaults) |
| `qip config set <key> <value>` | Set a config value in user or repo config |
| `qip config edit` | Open config in `$EDITOR` |

### Skills

| Command | Description |
|---|---|
| `qip skill list` | List installed skills (built-in + custom) |
| `qip skill add <path\|url>` | Install a custom skill |
| `qip skill remove <name>` | Remove a custom skill |
| `qip skill info <name>` | Show skill metadata and capabilities |

### Agent (Advanced)

| Command | Description |
|---|---|
| `qip agent build` | Rebuild the Docker agent image from Dockerfile |
| `qip agent shell` | Drop into an interactive shell inside the agent container (debug) |
| `qip agent logs <run-id>` | Stream/view agent container logs for a run |

---

## Agent Pipeline

The agent executes a six-stage pipeline inside the Docker sandbox:

```
   ┌─────────────────────────────────────────────────────────────┐
   │                    AGENT PIPELINE                           │
   │                                                             │
   │  Stage 1: SCAN                                              │
   │  ├─ Run Grype against lockfiles + source                    │
   │  ├─ Run Trivy against lockfiles + Dockerfiles + images      │
   │  ├─ Run language-native audits (pip-audit, npm audit, etc.) │
   │  ├─ Run custom skills (if configured)                       │
   │  └─ Output: raw_findings[]                                  │
   │                                                             │
   │  Stage 2: DEDUPLICATE                                       │
   │  ├─ Merge findings across scanners (by CVE ID + component)  │
   │  ├─ Resolve conflicts (highest severity wins)               │
   │  ├─ Enrich with CVSS v3.1 scores from local vuln-db         │
   │  ├─ Tag: ecosystem, fix-available, exploit-known             │
   │  └─ Output: deduped_findings[]                              │
   │                                                             │
   │  Stage 3: ANALYZE                                           │
   │  ├─ Reachability analysis: is the vuln code actually called? │
   │  ├─ Dependency tree depth (direct vs transitive)             │
   │  ├─ Exploitability scoring (EPSS where available)            │
   │  ├─ Business impact tagging (from .qip/config.yaml)          │
   │  └─ Output: analyzed_findings[] with priority scores         │
   │                                                             │
   │  Stage 4: PATCH                                             │
   │  ├─ For each actionable finding:                             │
   │  │   ├─ Dependency bump? → update manifest + lockfile        │
   │  │   ├─ Config fix? → secure defaults                        │
   │  │   ├─ Code fix? → AST transform                            │
   │  │   └─ No fix available? → document in report only          │
   │  ├─ Generate git-format .patch file                          │
   │  ├─ Assign confidence: HIGH / MEDIUM / LOW                   │
   │  └─ Output: patches[]                                       │
   │                                                             │
   │  Stage 5: VALIDATE                                          │
   │  ├─ Apply patches to a working copy (inside container)       │
   │  ├─ Run repo's test suite (configurable test_command)        │
   │  ├─ Run linters (if configured)                              │
   │  ├─ Check for regressions                                    │
   │  ├─ Mark patch: PASS / FAIL / SKIP (no tests)               │
   │  └─ Output: validated_patches[] with test evidence           │
   │                                                             │
   │  Stage 6: REPORT                                            │
   │  ├─ Write patches/*.patch to /output                         │
   │  ├─ Write report.json (structured, machine-readable)         │
   │  ├─ Write summary.md (human-readable, Markdown)              │
   │  ├─ Write evidence/ (test logs, traces)                      │
   │  ├─ Write timing.json (per-stage durations)                  │
   │  └─ Exit with code 0 (success) or 1 (findings but no crash) │
   └─────────────────────────────────────────────────────────────┘
```

### Pipeline Configuration

```yaml
pipeline:
  scan:
    scanners: [grype, trivy, native]
    skip_paths: ["test/", "docs/"]
    timeout: 300
  analyze:
    reachability: true
    min_severity: medium
    epss_threshold: 0.1
  patch:
    strategies: [dep-bump, config, ast]
    max_patches: 50
  validate:
    enabled: true
    test_command: "npm test"
    lint_command: "npm run lint"
    timeout: 600
  report:
    formats: [json, markdown, patch]
    include_evidence: true
    timing: true
```

---

## Sandbox Security Model

Inspired by OpenClaw's sandboxing philosophy: **the agent is untrusted code running on trusted infrastructure**.

### Container Isolation

| Layer | Implementation |
|---|---|
| **Filesystem** | Repo mounted read-only (`ro`); output is separate writable volume |
| **Network** | `--network=none` during patch/validate phases; brief network for scanner DB sync only |
| **User** | Runs as non-root (`qip-agent:1000`) inside container |
| **Capabilities** | All Linux capabilities dropped (`--cap-drop=ALL`) |
| **Seccomp** | Default Docker seccomp profile (blocks 44+ dangerous syscalls) |
| **Resources** | CPU/RAM limits enforced (`--cpus=2 --memory=4g`, configurable) |
| **Docker socket** | Never mounted — no container escape vector |
| **Timeout** | Hard kill after configurable TTL (default: 30 minutes) |
| **Cleanup** | Container auto-removed on exit (`--rm`) |

### Network Phases

```
Phase 1: ONLINE  (scanner DB sync only, ~60 seconds)
└─ Network: bridge (filtered, DNS only)

Phase 2: OFFLINE (scan + patch + validate, remainder of pipeline)
└─ Network: none (--network=none)
```

### Trust Boundaries

```
TRUSTED (host)                    UNTRUSTED (container)
──────────────                    ─────────────────────
QIP CLI                           Agent scanner processes
Review Server (localhost only)    Third-party scanner binaries
Git operations                    Package manager audit tools
Config files                      Any code executed during tests
User's repo (source of truth)     Working copies of patches
```

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| Agent modifies repo | Read-only mount; verified by CLI post-run |
| Agent phones home | No network during scan/patch phases |
| Malicious patch applied | Patches require explicit human approval via review UI |
| Container escape | Seccomp + dropped caps + no Docker socket |
| Resource exhaustion | PID limit (`--pids-limit=256`) + OOM kill |
| Stale scanner | `qip doctor` warns on outdated scanner versions |
| Supply chain attack on scanner | Pinned versions + SHA256 checksums in Dockerfile |

---

## Review System

### Review Server

- **FastAPI** server bound to `localhost:8500` (never `0.0.0.0`)
- Serves a single-page review UI
- API endpoints for approve/reject/edit operations
- WebSocket for live updates during review session
- Auto-opens browser on `qip review`

### Review UI Features

| Feature | Description |
|---|---|
| **Side-by-side diff** | Before/after view powered by diff2html |
| **CVE metadata panel** | CVE ID, description, CVSS score, severity badge |
| **Confidence indicator** | HIGH (green) / MEDIUM (yellow) / LOW (red) |
| **Test results** | PASS ✅ / FAIL ❌ / SKIP ⚠️ with expandable logs |
| **Reachability tag** | Is the vulnerable code actually called? |
| **Batch actions** | "Approve all HIGH confidence" / "Approve all CRITICAL" |
| **Inline edit** | Modify a patch before approving |
| **Dependency tree** | Visual graph: direct vs transitive |
| **Sort & filter** | By severity, confidence, ecosystem, fix type |
| **Keyboard shortcuts** | `a` approve, `r` reject, `e` edit, `j/k` navigate |

### Review Workflow

```
qip review
  │
  ├─ Starts FastAPI on localhost:8500
  ├─ Opens browser automatically
  │
  └─ For each patch:
       ├─ Show diff + metadata + test results
       ├─ User action:
       │   ├─ ✅ Approve → moves to .qip/approved/
       │   ├─ ❌ Reject → logged, stays in patches/
       │   ├─ ✏️ Edit → modify diff → approve modified version
       │   └─ ⏭️ Skip → review later
       │
       └─ Summary: "4 approved, 1 rejected, 2 skipped"
          "Run `qip deploy` to apply 4 approved patches"
```

---

## Deploy & Git Integration

Deployment is explicit, never automatic.

### Deploy Pipeline

```
qip deploy [run-id]
  │
  ├─ Verify: all approved patches still apply cleanly
  ├─ Create branch: fix/qip-<date>-<short-hash>
  ├─ Apply patches sequentially via `git apply`
  ├─ Create structured commits (one per patch):
  │       fix(deps): patch CVE-2025-12345 in lodash
  │       
  │       Component: lodash@4.17.20 → 4.17.21
  │       Severity: CRITICAL (CVSS 9.8)
  │       Confidence: HIGH
  │       Patched by: Quantum Infinity Patcher (run qip_2026-05-30_a7f3b2)
  │
  ├─ Optional: `git push` (if deploy.auto_push = true)
  └─ Output: "Branch fix/qip-2026-05-30-a7f3b2 created with 4 commits"
```

### Git Safety

- Never force-pushes
- Never pushes to `main`/`master` — always creates a new branch
- Never rebases
- Checks for uncommitted changes before deploy (aborts if dirty)
- Supports `--dry-run` to preview without modifying anything

---

## Configuration

Config resolves in priority order (like OpenClaw):

```
flags → environment variables → repo .qip/config.yaml → user ~/.qip/config.yaml → defaults
```

### Full Configuration Reference

```yaml
# ~/.qip/config.yaml (user-level) or <repo>/.qip/config.yaml (repo-level)

agent:
  image: qip-agent:latest
  cpus: 2
  memory: 4g
  pids_limit: 256
  timeout: 1800
  auto_build: true
  pull_policy: never                # never | always | if-not-present

scan:
  scanners: [grype, trivy, native]
  severity_threshold: medium
  skip_paths: ["test/", "tests/", "docs/", "vendor/", "node_modules/"]
  max_findings: 500
  ecosystems: auto                  # auto-detect or explicit list

analyze:
  reachability: true
  epss: true
  prioritize_direct_deps: true
  business_critical_paths: ["src/auth/", "src/payments/", "src/api/"]

patch:
  strategies: [dep-bump, config, ast]
  auto_approve:
    enabled: false
    conditions:
      min_confidence: high
      min_severity: critical
      type: dep-bump
      test_result: pass
  max_patches: 50

validate:
  enabled: true
  test_command: ""                  # auto-detect from package.json/pyproject.toml
  lint_command: ""
  timeout: 600
  fail_strategy: skip              # skip | mark-low-confidence | abort

review:
  host: 127.0.0.1                  # NEVER 0.0.0.0
  port: 8500
  auto_open_browser: true
  theme: auto                      # auto | light | dark

deploy:
  create_branch: true
  branch_prefix: "fix/qip-"
  auto_push: false
  commit_style: one-per-patch      # one-per-patch | squash
  commit_template: |
    fix({scope}): patch {cve_id} in {component}
    
    Component: {component}@{old_version} → {new_version}
    Severity: {severity} (CVSS {cvss_score})
    Type: {fix_type}
    Confidence: {confidence}
    Patched by: Quantum Infinity Patcher (run {run_id})

history:
  db_path: ~/.qip/history.db
  retention_days: 365

skills:
  paths: ["~/.qip/skills/", ".qip/skills/"]
  enabled: []
  disabled: []
```

### Environment Variables

Every config key can be overridden: `QIP_<SECTION>_<KEY>` (uppercased, dots → underscores).

```
QIP_AGENT_CPUS=4
QIP_AGENT_MEMORY=8g
QIP_SCAN_SEVERITY_THRESHOLD=high
QIP_DEPLOY_AUTO_PUSH=true
QIP_REVIEW_PORT=9000
```

---

## Supported Ecosystems

| Ecosystem | Dependency Files | Scanners | Fix Types |
|---|---|---|---|
| **Python** | `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock` | Grype + pip-audit + safety | dep-bump, config, ast |
| **Node.js** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Grype + npm audit | dep-bump, config, ast |
| **Java/Kotlin** | `pom.xml`, `build.gradle`, `build.gradle.kts` | Grype + Trivy + OWASP | dep-bump, config |
| **Go** | `go.mod`, `go.sum` | Grype + govulncheck | dep-bump |
| **Rust** | `Cargo.toml`, `Cargo.lock` | Grype + cargo-audit | dep-bump |
| **.NET/C#** | `*.csproj`, `packages.config` | Grype + Trivy | dep-bump |
| **Ruby** | `Gemfile`, `Gemfile.lock` | Grype + bundler-audit | dep-bump |
| **PHP** | `composer.json`, `composer.lock` | Grype + Trivy | dep-bump |
| **Docker** | `Dockerfile`, `docker-compose.yml`, OCI images | Trivy | base-image-bump, config |
| **IaC** | Terraform, CloudFormation, K8s manifests | Trivy (misconfig) | config |

---

## Fix Generation Strategy

### Tier 1: Dependency Bumps (Confidence: HIGH)

Parse lockfile → find vulnerable version → find minimum safe version (no major version crossing).

```
Before: lodash@4.17.20 (CVE-2025-12345, CVSS 9.8)
After:  lodash@4.17.21 (patched)
```

### Tier 2: Configuration Patches (Confidence: MEDIUM)

- `DEBUG=True` → `DEBUG=False`
- Weak TLS versions → minimum TLS 1.2
- Permissive CORS → restricted origins
- Missing cookie flags → `Secure; HttpOnly; SameSite=Strict`

### Tier 3: Code-Level AST Patches (Confidence: LOW-MEDIUM)

| Vulnerability Class | AST Transform |
|---|---|
| SQL Injection | String concat → parameterized queries |
| XSS | Raw output → escaped/sanitized output |
| Path Traversal | User input in path → sanitized + validated |
| Insecure Deserialization | `pickle.loads` → safe alternatives |
| Command Injection | `os.system` → `subprocess.run(shell=False)` |
| SSRF | Unvalidated URLs → allowlist check |

**Code-level patches always require human review** — never auto-approved.

---

## Observability & History

### Scan History (SQLite)

Every run is recorded in `~/.qip/history.db`:

```sql
-- Runs table
runs(run_id, repo_path, started_at, finished_at, status,
     total_findings, total_patches, approved, rejected, deployed, timing_json)

-- Findings table
findings(id, run_id, cve_id, severity, cvss_score, component,
         ecosystem, reachable, fix_available, patch_id)

-- Patches table
patches(patch_id, run_id, cve_id, file_path, fix_type, confidence,
        test_result, review_status, reviewed_at, deployed_at)
```

### CLI History Views

```bash
$ qip history
RUN ID                    REPO          FINDINGS  PATCHES  STATUS     DATE
qip_2026-05-30_a7f3b2    my-app        12        8        deployed   2026-05-30
qip_2026-05-28_c1d2e3    my-api        3         3        reviewed   2026-05-28
qip_2026-05-25_f4a5b6    my-lib        0         0        clean      2026-05-25

$ qip compare qip_2026-05-28_c1d2e3 qip_2026-05-30_a7f3b2
NEW:      +2 findings (CVE-2025-99991, CVE-2025-99992)
FIXED:    -1 finding  (CVE-2025-88881 — patched in previous deploy)
PERSIST:  2 findings  (CVE-2025-77771, CVE-2025-77772)
```

### Timing Records

Every run records per-stage timing in `timing.json`:

```json
{
  "run_id": "qip_2026-05-30_a7f3b2",
  "total_seconds": 187,
  "stages": {
    "container_start": 3.2,
    "scan": 45.1,
    "deduplicate": 1.8,
    "analyze": 22.4,
    "patch": 15.7,
    "validate": 94.3,
    "report": 4.5
  }
}
```

---

## Plugin / Skill Architecture

Skills extend QIP with custom scanners, analyzers, or patchers.

### Skill Structure

```
~/.qip/skills/my-corp-scanner/
├── SKILL.md            # Manifest (required)
├── scan.py             # Executable
├── requirements.txt    # Dependencies (installed in container)
└── README.md
```

### SKILL.md Manifest

```markdown
---
name: my-corp-scanner
version: 1.0.0
description: Scan for internal compliance violations
type: scanner              # scanner | analyzer | patcher
ecosystems: [python, nodejs]
phase: scan                # which pipeline stage
---
```

### Built-in Skills

| Skill | Type | Description |
|---|---|---|
| `grype-scanner` | scanner | Anchore Grype vulnerability scanner |
| `trivy-scanner` | scanner | Aqua Trivy multi-target scanner |
| `native-audit` | scanner | Language-native audit tools |
| `reachability` | analyzer | Call-graph reachability analysis |
| `dep-bump` | patcher | Dependency version bump generator |
| `config-fix` | patcher | Insecure configuration fixer |
| `ast-patch` | patcher | AST-level code transformation engine |

---

## Project Structure

```
Quantum_infinity_patcher/
│
├── PRD.md                           # This document
├── README.md                        # User-facing readme
├── LICENSE                          # MIT
├── CONTRIBUTING.md                  # Contribution guidelines
├── AGENTS.md                        # Agent coding instructions (for AI tools)
├── CHANGELOG.md
├── .gitignore
│
├── Dockerfile                       # Agent container image
├── docker-compose.yaml              # Dev/test compose
├── pyproject.toml                   # Python project config (PEP 621)
├── .qip.example.yaml               # Example repo-level config
│
├── src/
│   ├── qip/                        # Host-side CLI + services
│   │   ├── __init__.py
│   │   ├── __main__.py             # `python -m qip` entry
│   │   ├── cli.py                  # Click CLI commands
│   │   ├── config.py              # Config resolution
│   │   ├── docker_manager.py      # Container lifecycle
│   │   ├── reviewer.py           # FastAPI review server
│   │   ├── deployer.py           # Git operations
│   │   ├── history.py            # SQLite history + audit
│   │   ├── doctor.py             # System health checks
│   │   ├── models.py             # Pydantic data models
│   │   ├── skill_loader.py       # Skill discovery + loading
│   │   └── utils.py
│   │
│   └── agent/                      # Runs INSIDE Docker container
│       ├── __init__.py
│       ├── main.py                 # Pipeline orchestrator
│       ├── scanner.py             # Scanner wrapper
│       ├── deduplicator.py        # Finding merge
│       ├── analyzer.py            # Reachability + priority
│       ├── patcher.py             # Fix generation dispatch
│       ├── patchers/
│       │   ├── dep_bump.py
│       │   ├── config_fix.py
│       │   └── ast_patch.py
│       ├── validator.py           # Test runner
│       ├── reporter.py            # Output writer
│       └── skill_runner.py        # Custom skill executor
│
├── web/                             # Review UI
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   └── assets/
│
├── skills/                          # Built-in skills
│   ├── grype-scanner/SKILL.md
│   ├── trivy-scanner/SKILL.md
│   └── ...
│
├── tests/
│   ├── conftest.py
│   ├── test_cli.py
│   ├── test_scanner.py
│   ├── test_patcher.py
│   ├── test_deployer.py
│   ├── test_history.py
│   ├── integration/
│   │   ├── test_full_pipeline.py
│   │   └── test_review_deploy.py
│   └── fixtures/
│       ├── sample_repo_python/
│       ├── sample_repo_node/
│       └── sample_findings.json
│
├── docs/
│   ├── getting-started.md
│   ├── architecture.md
│   ├── cli.md
│   ├── configuration.md
│   ├── security.md
│   ├── skills.md
│   └── troubleshooting.md
│
└── scripts/
    ├── build-agent.ps1
    ├── build-agent.sh
    ├── setup.ps1
    ├── setup.sh
    └── release.sh
```

---

## System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10, macOS 12, Ubuntu 20.04 | Windows 11, macOS 14, Ubuntu 22.04 |
| **Docker** | Docker Desktop 4.x or Engine 24+ | Latest stable |
| **Python** | 3.11+ | 3.12+ |
| **Git** | 2.30+ | Latest stable |
| **RAM** | 8 GB total (4 GB free) | 16 GB total |
| **Disk** | 5 GB free | 10 GB free |
| **CPU** | 2 cores | 4+ cores |

### Quick Verify

```bash
$ qip doctor
✅ Docker:  Docker Desktop 4.30.0 (running)
✅ Python:  3.12.3
✅ Git:     2.44.0
✅ Disk:    42 GB free
✅ Image:   qip-agent:latest (built 2026-05-30)
✅ Vuln DB: OSV synced 2026-05-30 (12,847 advisories)
✅ Config:  Valid (~/.qip/config.yaml)
⚠️ Grype:   v0.82.0 (latest: v0.83.1, run `qip agent build` to update)
```

---

## Roadmap & Milestones

### Phase 1 — MVP (Week 1–2) 🎯

- [ ] Dockerfile with Grype + Trivy + pip-audit + npm audit
- [ ] `qip init` — create `.qip/config.yaml` + `.gitignore`
- [ ] `qip scan` — mount repo, run scanners, output report + patches
- [ ] `qip review` — FastAPI + basic HTML diff viewer
- [ ] `qip deploy` — `git apply`, create branch, commit
- [ ] `qip doctor` — verify prerequisites
- [ ] `qip db update` — sync OSV database
- [ ] Dep-bump patcher for Python + Node.js
- [ ] Unit tests + README

### Phase 2 — Hardening (Week 3–4) 🔒

- [ ] Two-phase network (online DB sync → offline scan/patch)
- [ ] Reachability analysis
- [ ] Test validation inside container
- [ ] Side-by-side diff UI with approve/reject/edit
- [ ] Batch actions by severity/confidence
- [ ] Config resolution (flags → env → repo → user → defaults)
- [ ] SQLite history + `qip history` / `qip compare`
- [ ] Per-stage timing records
- [ ] Integration tests with real Docker

### Phase 3 — Ecosystems (Week 5–6) 🌍

- [ ] Go, Rust, Java, .NET, Ruby, PHP support
- [ ] Dockerfile/OCI image scanning
- [ ] Config patcher (insecure defaults)
- [ ] AST patcher (code-level transforms for Python + JS)
- [ ] IaC misconfig scanning (Terraform, K8s)

### Phase 4 — Skills & Automation (Week 7–8) 🔌

- [ ] Skill architecture (SKILL.md manifest + loader + runner)
- [ ] Custom skill support (`qip skill add/remove/list`)
- [ ] Scheduled scans (cron / Task Scheduler)
- [ ] CI mode (`qip scan --ci --exit-code`)
- [ ] SARIF output for GitHub Advanced Security
- [ ] VS Code extension for in-editor review
- [ ] Desktop notifications on scan completion
- [ ] `qip update` — self-update CLI + agent image

---

## Tech Stack

| Component | Technology | Why |
|---|---|---|
| **CLI** | Python 3.12+, Click | Rich CLI framework, wide ecosystem |
| **Agent Runtime** | Docker (Linux containers) | Isolation, reproducibility, cross-platform |
| **Scanners** | Grype, Trivy, OSV-scanner | Best-in-class OSS, offline-capable |
| **Vuln Database** | OSV (local mirror) | Google-maintained, open, comprehensive |
| **Patch Engine** | tree-sitter, lib2to3 | Safe AST transforms, not regex |
| **Review Server** | FastAPI + Uvicorn | Async, fast, Python-native |
| **Review UI** | Vanilla HTML/JS + diff2html | Zero build step, no npm required on host |
| **History DB** | SQLite | Zero-config, single-file, fast |
| **Git Ops** | GitPython | Pythonic git operations |
| **Config** | PyYAML + Pydantic v2 | Validation, defaults, env overrides |
| **Testing** | Pytest + pytest-docker | Unit + integration with real containers |
| **Packaging** | pyproject.toml (PEP 621) | Modern Python packaging |

---

## Success Metrics

| Metric | Target | Measurement |
|---|---|---|
| **Scan time** (avg repo) | < 5 minutes | `timing.json` |
| **False positive rate** | < 15% | Review rejection rate |
| **Auto-fixable CVEs** | > 70% | Patches / findings ratio |
| **Test pass rate** (patches) | > 90% | Validation stage |
| **Review-to-deploy time** | < 10 minutes | History DB timestamps |
| **Zero data exfiltration** | 100% | Network audit + `--network=none` |
| **Container escape** | 0 incidents | Seccomp + cap-drop |
| **Setup time** (first run) | < 10 minutes | Includes image build + DB sync |
| **Cross-platform** | 3 OS | CI matrix |

---

## Contributing

PRs welcome — including AI-assisted contributions 🤖. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

> *Built for developers who believe security scanning shouldn't require uploading your code to someone else's server.* ⚛️🛡️
