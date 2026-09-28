"""
checker/reporters/json_reporter.py

Generates a structured JSON export of scan results.
"""

from __future__ import annotations

import json
from collections import defaultdict


def generate_json(scan: dict, results: list[dict]) -> str:
    """Return a pretty-printed JSON string of the full scan report."""

    findings = [r for r in results if r.get("verdict") == "NEEDS_FIX"]
    passes = [r for r in results if r.get("verdict") == "PASSES"]
    inconclusive = [r for r in results if r.get("verdict") == "INCONCLUSIVE"]

    by_severity: dict[str, int] = defaultdict(int)
    by_endpoint: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for r in results:
        sev = r.get("severity", "INFO")
        ep = r.get("endpoint", "unknown")
        v = r.get("verdict", "INCONCLUSIVE")
        by_severity[sev] += 1
        by_endpoint[ep][v] += 1

    report = {
        "scan": {
            "id": scan.get("id"),
            "target_url": scan.get("target_url"),
            "spec_source": scan.get("spec_source"),
            "status": scan.get("status"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
        },
        "summary": {
            "total_checks": len(results),
            "needs_fix": len(findings),
            "passes": len(passes),
            "inconclusive": len(inconclusive),
            "by_severity": dict(by_severity),
            "by_endpoint": {ep: dict(counts) for ep, counts in by_endpoint.items()},
        },
        "findings": _clean_results(findings),
        "passes": _clean_results(passes),
        "inconclusive": _clean_results(inconclusive),
    }

    return json.dumps(report, indent=2, default=str)


def _clean_results(results: list[dict]) -> list[dict]:
    """Return results with only serialisable fields."""
    cleaned = []
    for r in results:
        payload = r.get("payload_json") or r.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                pass
        cleaned.append({
            "id": r.get("id"),
            "endpoint": r.get("endpoint"),
            "method": r.get("method"),
            "module": r.get("module_name"),
            "payload": payload,
            "expected_status": r.get("expected_status"),
            "actual_status": r.get("actual_status"),
            "response_snippet": r.get("response_snippet"),
            "verdict": r.get("verdict"),
            "severity": r.get("severity"),
            "evidence_diff": r.get("evidence_diff"),
            "remediation": r.get("remediation"),
            "created_at": r.get("created_at"),
        })
    return cleaned
