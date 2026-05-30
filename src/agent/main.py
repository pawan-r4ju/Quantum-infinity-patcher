"""Agent pipeline orchestrator — main entry point inside Docker container."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from agent.scanner import Scanner
from agent.deduplicator import Deduplicator
from agent.analyzer import Analyzer
from agent.patcher import Patcher
from agent.validator import Validator
from agent.reporter import Reporter


def main():
    """Run the full agent pipeline."""
    # Configuration from environment
    run_id = os.environ.get("QIP_RUN_ID", "unknown")
    severity_threshold = os.environ.get("QIP_SEVERITY_THRESHOLD", "medium")
    scanners = os.environ.get("QIP_SCANNERS", "grype,trivy,native").split(",")
    skip_paths = os.environ.get("QIP_SKIP_PATHS", "test/,tests/,docs/").split(",")
    test_command = os.environ.get("QIP_TEST_COMMAND", "")
    validate_enabled = os.environ.get("QIP_VALIDATE_ENABLED", "true") == "true"

    # Paths (these are the mount points inside the container)
    repo_path = Path("/repo")
    output_path = Path("/output")
    vuln_db_path = Path("/vuln-db")

    timing: dict[str, float] = {}

    print(f"═══════════════════════════════════════════════════")
    print(f"  QIP Agent — Run: {run_id}")
    print(f"  Repo: {repo_path}")
    print(f"  Scanners: {', '.join(scanners)}")
    print(f"  Severity: {severity_threshold}+")
    print(f"═══════════════════════════════════════════════════")
    print()

    # ── Stage 1: SCAN ─────────────────────────────────────────────────────────
    print("▶ Stage 1: SCAN")
    t0 = time.time()
    scanner = Scanner(
        repo_path=repo_path,
        scanners=scanners,
        skip_paths=skip_paths,
    )
    raw_findings = scanner.run()
    timing["scan"] = time.time() - t0
    print(f"  Found {len(raw_findings)} raw findings ({timing['scan']:.1f}s)")
    print()

    # ── Stage 2: DEDUPLICATE ──────────────────────────────────────────────────
    print("▶ Stage 2: DEDUPLICATE")
    t0 = time.time()
    deduplicator = Deduplicator(severity_threshold=severity_threshold)
    deduped_findings = deduplicator.run(raw_findings)
    timing["deduplicate"] = time.time() - t0
    print(f"  Deduped to {len(deduped_findings)} findings ({timing['deduplicate']:.1f}s)")
    print()

    # ── Stage 3: ANALYZE ──────────────────────────────────────────────────────
    print("▶ Stage 3: ANALYZE")
    t0 = time.time()
    analyzer = Analyzer(repo_path=repo_path)
    analyzed_findings = analyzer.run(deduped_findings)
    timing["analyze"] = time.time() - t0
    print(f"  Analyzed {len(analyzed_findings)} findings ({timing['analyze']:.1f}s)")
    print()

    # ── Stage 4: PATCH ────────────────────────────────────────────────────────
    print("▶ Stage 4: PATCH")
    t0 = time.time()
    patcher = Patcher(repo_path=repo_path, output_path=output_path)
    patches = patcher.run(analyzed_findings)
    timing["patch"] = time.time() - t0
    print(f"  Generated {len(patches)} patches ({timing['patch']:.1f}s)")
    print()

    # ── Stage 5: VALIDATE ─────────────────────────────────────────────────────
    print("▶ Stage 5: VALIDATE")
    t0 = time.time()
    if validate_enabled and test_command:
        validator = Validator(
            repo_path=repo_path,
            test_command=test_command,
            output_path=output_path,
        )
        patches = validator.run(patches)
    else:
        print("  Skipped (no test command configured)")
    timing["validate"] = time.time() - t0
    print(f"  Validation done ({timing['validate']:.1f}s)")
    print()

    # ── Stage 6: REPORT ───────────────────────────────────────────────────────
    print("▶ Stage 6: REPORT")
    t0 = time.time()
    reporter = Reporter(
        output_path=output_path,
        run_id=run_id,
    )
    reporter.run(analyzed_findings, patches, timing)
    timing["report"] = time.time() - t0
    print(f"  Reports written ({timing['report']:.1f}s)")
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    total_time = sum(timing.values())
    print(f"═══════════════════════════════════════════════════")
    print(f"  ✅ Pipeline complete in {total_time:.1f}s")
    print(f"  Findings: {len(analyzed_findings)}")
    print(f"  Patches:  {len(patches)}")
    print(f"═══════════════════════════════════════════════════")


if __name__ == "__main__":
    main()
