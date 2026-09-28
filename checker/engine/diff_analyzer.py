"""
checker/engine/diff_analyzer.py

Pillar 1: Differential Response Analysis Engine.
Performs semantic JSON tree normalization, structural Jaccard similarity scoring,
sensitive data leakage detection, and differential verdict determination.
"""

from __future__ import annotations

import re
import json
from dataclasses import dataclass, field
from typing import Any

from .utils import safe_json, status_ok, status_denied, snippet


DYNAMIC_FIELDS = {
    "created_at",
    "updated_at",
    "timestamp",
    "date",
    "time",
    "token",
    "access_token",
    "refresh_token",
    "request_id",
    "trace_id",
    "correlation_id",
    "nonce",
    "expires_in",
}

SENSITIVE_KEY_PATTERNS = [
    r"email",
    r"phone",
    r"mobile",
    r"address",
    r"shipping",
    r"tracking",
    r"password",
    r"secret",
    r"ssn",
    r"credit_?card",
    r"full_?name",
    r"private",
    r"balance",
    r"salary",
]


@dataclass
class SimilarityReport:
    field_jaccard: float
    value_match_ratio: float
    combined_score: float
    shared_fields: list[str] = field(default_factory=list)
    baseline_only_fields: list[str] = field(default_factory=list)
    probe_only_fields: list[str] = field(default_factory=list)
    matching_values: list[str] = field(default_factory=list)


class DiffAnalyzer:
    """Analyzes differences between authorized baseline and unauthorized probe responses."""

    def normalize_json(self, data: Any, strip_dynamic: bool = True) -> Any:
        """Recursively normalize JSON structure, optionally stripping volatile dynamic fields."""
        if isinstance(data, dict):
            normalized = {}
            for k, v in sorted(data.items(), key=lambda x: str(x[0])):
                k_lower = str(k).lower()
                if strip_dynamic and k_lower in DYNAMIC_FIELDS:
                    continue
                normalized[k] = self.normalize_json(v, strip_dynamic=strip_dynamic)
            return normalized
        elif isinstance(data, list):
            return [self.normalize_json(item, strip_dynamic=strip_dynamic) for item in data]
        return data

    def flatten_json(self, data: Any, prefix: str = "") -> dict[str, Any]:
        """Flatten a nested JSON object into dot-notation path-to-value pairs."""
        items: dict[str, Any] = {}
        if isinstance(data, dict):
            for k, v in data.items():
                new_prefix = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)) and v:
                    items.update(self.flatten_json(v, new_prefix))
                else:
                    items[new_prefix] = v
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                new_prefix = f"{prefix}[{idx}]"
                if isinstance(item, (dict, list)) and item:
                    items.update(self.flatten_json(item, new_prefix))
                else:
                    items[new_prefix] = item
        return items

    def compute_similarity(self, baseline_raw: Any, probe_raw: Any) -> SimilarityReport:
        """
        Compute structural Jaccard index and value match ratio between normalized JSON payloads.
        Returns a SimilarityReport with scores between 0.0 and 1.0.
        """
        if baseline_raw is None or probe_raw is None:
            return SimilarityReport(0.0, 0.0, 0.0)

        base_norm = self.normalize_json(baseline_raw, strip_dynamic=True)
        probe_norm = self.normalize_json(probe_raw, strip_dynamic=True)

        base_flat = self.flatten_json(base_norm)
        probe_flat = self.flatten_json(probe_norm)

        base_keys = set(base_flat.keys())
        probe_keys = set(probe_flat.keys())

        if not base_keys and not probe_keys:
            return SimilarityReport(1.0, 1.0, 1.0)
        if not base_keys or not probe_keys:
            return SimilarityReport(0.0, 0.0, 0.0)

        shared = sorted(list(base_keys & probe_keys))
        union = base_keys | probe_keys
        field_jaccard = len(shared) / len(union) if union else 0.0

        matches = []
        for k in shared:
            v1, v2 = base_flat[k], probe_flat[k]
            if str(v1).strip().lower() == str(v2).strip().lower():
                matches.append(k)

        value_match_ratio = len(matches) / len(shared) if shared else 0.0
        combined = round(0.4 * field_jaccard + 0.6 * value_match_ratio, 3)

        return SimilarityReport(
            field_jaccard=round(field_jaccard, 3),
            value_match_ratio=round(value_match_ratio, 3),
            combined_score=combined,
            shared_fields=shared,
            baseline_only_fields=sorted(list(base_keys - probe_keys)),
            probe_only_fields=sorted(list(probe_keys - base_keys)),
            matching_values=matches,
        )

    def detect_sensitive_fields(self, data: Any, owner_hints: dict | None = None) -> list[str]:
        """
        Inspect parsed JSON body for PII, credentials, or specific owner values that leaked.
        """
        findings: list[str] = []
        if not data:
            return findings

        flat = self.flatten_json(data)
        regex_patterns = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_KEY_PATTERNS]

        for path, val in flat.items():
            path_str = str(path)
            # Check key name
            if any(rgx.search(path_str) for rgx in regex_patterns):
                val_str = str(val).strip()
                if val_str and val_str not in ("null", "None", ""):
                    findings.append(f"Sensitive attribute leaked: {path_str}='{val_str}'")

            # Check value patterns (email / phone regex)
            if isinstance(val, str):
                if re.search(r"[\w\.-]+@[\w\.-]+\.\w+", val):
                    findings.append(f"Email pattern leaked at {path_str}: {val}")
                elif re.search(r"\b\d{3}[-.\s]??\d{3}[-.\s]??\d{4}\b", val):
                    findings.append(f"Phone pattern leaked at {path_str}: {val}")

        # Check explicit owner hints if available
        if owner_hints:
            for field_name, owner_val in owner_hints.items():
                if owner_val:
                    owner_str = str(owner_val).lower().strip()
                    for path, val in flat.items():
                        if str(val).lower().strip() == owner_str:
                            findings.append(f"Owner's private {field_name} leaked in probe response at {path}: {val}")

        # Deduplicate while preserving order
        deduped = []
        for f in findings:
            if f not in deduped:
                deduped.append(f)
        return deduped

    def evaluate_verdict(
        self,
        baseline_resp_status: int,
        baseline_json: Any,
        probe_resp_status: int,
        probe_json: Any,
        resource_type: str,
        owner_role: str,
        accessor_role: str,
        owner_hints: dict | None = None,
    ) -> tuple[str, str, str, str, float, list[str]]:
        """
        Evaluate authorized baseline vs unauthorized probe response.
        Returns: (verdict, severity, evidence_diff, remediation, similarity_score, sensitive_leaks)
        """
        sensitive_leaks = self.detect_sensitive_fields(probe_json, owner_hints)
        sim = self.compute_similarity(baseline_json, probe_json)

        # Baseline check: If baseline was not 2xx, the resource might not even exist
        if not status_ok(baseline_resp_status):
            if status_denied(probe_resp_status):
                return "PASSES", "INFO", "", "", sim.combined_score, []
            return "INCONCLUSIVE", "INFO", f"Baseline owner request returned {baseline_resp_status}", "", sim.combined_score, []

        # Probe status check
        if status_denied(probe_resp_status):
            if sensitive_leaks:
                # Denial status code returned, but error leaked sensitive fields
                evidence = (
                    f"Denial status {probe_resp_status} returned, but response body disclosed sensitive data:\n"
                    + "\n".join(f"  • {leak}" for leak in sensitive_leaks)
                )
                remediation = (
                    f"Although {accessor_role} received HTTP {probe_resp_status}, the response leaked sensitive "
                    f"information. Sanitize error responses and return generic messages."
                )
                return "NEEDS_FIX", "MEDIUM", evidence, remediation, sim.combined_score, sensitive_leaks

            # Clean denial
            return "PASSES", "INFO", "", "", sim.combined_score, []

        if status_ok(probe_resp_status):
            # Probe returned 2xx!
            if sim.combined_score >= 0.65 or (probe_json and sim.value_match_ratio >= 0.5):
                # Strong structural and value match to owner's data
                leak_details = "\n".join(f"  • {leak}" for leak in sensitive_leaks) if sensitive_leaks else ""
                evidence = (
                    f"Differential Analysis detected BOLA leakage:\n"
                    f"  • Owner ({owner_role}) Status: {baseline_resp_status} | Probe ({accessor_role}) Status: {probe_resp_status}\n"
                    f"  • Structural Similarity: {int(sim.combined_score * 100)}% (Jaccard: {sim.field_jaccard}, Value Match: {sim.value_match_ratio})\n"
                    f"  • Shared Attributes: {', '.join(sim.shared_fields[:6])}\n"
                    f"  • Matching Values: {', '.join(sim.matching_values[:6])}"
                )
                if leak_details:
                    evidence += f"\n  • Leaked Fields:\n{leak_details}"

                remediation = (
                    f"Endpoint returns {owner_role}'s private {resource_type} data to {accessor_role} with "
                    f"{int(sim.combined_score * 100)}% data similarity. Add an explicit authorization check "
                    f"verifying resource ownership before returning data. Return HTTP 404 to avoid ID enumeration."
                )
                severity = "CRITICAL" if sensitive_leaks else "HIGH"
                return "NEEDS_FIX", severity, evidence, remediation, sim.combined_score, sensitive_leaks

            elif sim.combined_score < 0.2 and not probe_json:
                # Server returned 200 with empty body/list
                evidence = f"Probe returned 200 with empty/null payload (similarity {sim.combined_score}). No data leakage."
                return "PASSES", "INFO", evidence, "", sim.combined_score, []

            else:
                # Moderate similarity or partial object returned
                evidence = (
                    f"Probe returned status {probe_resp_status} with partial data similarity ({int(sim.combined_score * 100)}%). "
                    f"Matching fields: {', '.join(sim.matching_values[:4]) if sim.matching_values else 'None'}."
                )
                remediation = f"Verify whether returning this data to {accessor_role} violates authorization policy."
                return "INCONCLUSIVE", "MEDIUM", evidence, remediation, sim.combined_score, sensitive_leaks

        # Unknown or unexpected status
        evidence = f"Unexpected status {probe_resp_status} received (similarity {sim.combined_score})."
        return "INCONCLUSIVE", "INFO", evidence, "Verify manually.", sim.combined_score, sensitive_leaks
