"""Deduplicator — merge findings across scanners, filter by severity."""

from __future__ import annotations

from agent.scanner import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}


class Deduplicator:
    """Merge and deduplicate findings from multiple scanners."""

    def __init__(self, severity_threshold: str = "medium"):
        self.threshold = SEVERITY_ORDER.get(severity_threshold.lower(), 2)

    def run(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by CVE+component, keep highest severity."""
        # Group by (cve_id, component)
        grouped: dict[tuple[str, str], list[Finding]] = {}
        for f in findings:
            key = (f.cve_id, f.component)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        # Merge: keep highest severity, combine scanner names
        deduped: list[Finding] = []
        for key, group in grouped.items():
            # Sort by severity (most severe first)
            group.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 4))
            best = group[0]

            # Merge scanner info
            scanners = list(set(f.scanner for f in group))
            best.scanner = ",".join(scanners)

            # Take best fixed_version available
            if not best.fixed_version:
                for f in group:
                    if f.fixed_version:
                        best.fixed_version = f.fixed_version
                        break

            # Take best CVSS score
            best.cvss_score = max(f.cvss_score for f in group)

            deduped.append(best)

        # Filter by severity threshold
        filtered = [
            f for f in deduped
            if SEVERITY_ORDER.get(f.severity, 4) <= self.threshold
        ]

        # Sort by severity then CVSS
        filtered.sort(
            key=lambda x: (SEVERITY_ORDER.get(x.severity, 4), -x.cvss_score)
        )

        return filtered
