"""Data models for QIP — CVE findings, patches, runs, config."""

from __future__ import annotations

import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FixType(str, Enum):
    DEP_BUMP = "dep-bump"
    CONFIG = "config"
    AST = "ast"


class PatchStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"


class TestResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"


class RunStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# ─── Models ───────────────────────────────────────────────────────────────────


class Finding(BaseModel):
    """A single vulnerability finding from a scanner."""

    cve_id: str
    title: str = ""
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: float = 0.0
    component: str = ""
    version: str = ""
    fixed_version: Optional[str] = None
    ecosystem: str = ""
    scanner: str = ""
    file_path: str = ""
    reachable: Optional[bool] = None
    epss_score: Optional[float] = None
    direct_dependency: bool = True


class Patch(BaseModel):
    """A proposed fix for a vulnerability."""

    patch_id: str
    cve_id: str
    component: str = ""
    old_version: str = ""
    new_version: str = ""
    fix_type: FixType
    confidence: Confidence
    diff_content: str = ""
    patch_file: str = ""
    test_result: TestResult = TestResult.SKIP
    review_status: PatchStatus = PatchStatus.PENDING
    description: str = ""


class ScanRun(BaseModel):
    """Record of a complete scan run."""

    run_id: str
    repo_path: str
    started_at: datetime.datetime = Field(default_factory=datetime.datetime.now)
    finished_at: Optional[datetime.datetime] = None
    status: RunStatus = RunStatus.RUNNING
    findings: list[Finding] = Field(default_factory=list)
    patches: list[Patch] = Field(default_factory=list)
    timing: dict[str, float] = Field(default_factory=dict)
    config_snapshot: dict = Field(default_factory=dict)


class ScanSummary(BaseModel):
    """Summary of a scan run for display."""

    run_id: str
    repo_path: str
    status: RunStatus
    total_findings: int = 0
    total_patches: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    approved: int = 0
    rejected: int = 0
    duration_seconds: float = 0.0
    date: str = ""


# ─── Config Models ────────────────────────────────────────────────────────────


class AgentConfig(BaseModel):
    image: str = "qip-agent:latest"
    cpus: int = 2
    memory: str = "4g"
    pids_limit: int = 256
    timeout: int = 1800
    auto_build: bool = True
    pull_policy: str = "never"


class ScanConfig(BaseModel):
    scanners: list[str] = Field(default_factory=lambda: ["grype", "trivy", "native"])
    severity_threshold: Severity = Severity.MEDIUM
    skip_paths: list[str] = Field(
        default_factory=lambda: ["test/", "tests/", "docs/", "vendor/", "node_modules/"]
    )
    max_findings: int = 500
    ecosystems: str = "auto"


class AnalyzeConfig(BaseModel):
    reachability: bool = True
    epss: bool = True
    prioritize_direct_deps: bool = True
    business_critical_paths: list[str] = Field(default_factory=list)


class PatchConfig(BaseModel):
    strategies: list[str] = Field(default_factory=lambda: ["dep-bump", "config", "ast"])
    max_patches: int = 50


class ValidateConfig(BaseModel):
    enabled: bool = True
    test_command: str = ""
    lint_command: str = ""
    timeout: int = 600
    fail_strategy: str = "skip"


class ReviewConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8500
    auto_open_browser: bool = True
    theme: str = "auto"


class DeployConfig(BaseModel):
    create_branch: bool = True
    branch_prefix: str = "fix/qip-"
    auto_push: bool = False
    commit_style: str = "one-per-patch"


class QipConfig(BaseModel):
    """Root configuration model."""

    agent: AgentConfig = Field(default_factory=AgentConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    analyze: AnalyzeConfig = Field(default_factory=AnalyzeConfig)
    patch: PatchConfig = Field(default_factory=PatchConfig)
    validate: ValidateConfig = Field(default_factory=ValidateConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    deploy: DeployConfig = Field(default_factory=DeployConfig)
