"""
checker/engine/acm_builder.py

Pillar 3: Access Control Matrix (ACM) & Policy Anomaly Detection Engine.
Constructs a Role x Endpoint authorization matrix, evaluates policy symmetry,
detects privilege boundary inversions, and computes an authorization health score (0-100).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .discovery import Endpoint


@dataclass
class Anomaly:
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    endpoints: list[str] = field(default_factory=list)
    roles_involved: list[str] = field(default_factory=list)


class ACMBuilder:
    """Builds and analyzes the Access Control Matrix from scan results."""

    def build_matrix(
        self,
        results: list[dict],
        roles: list[str],
        endpoints: list[Endpoint],
    ) -> dict[str, Any]:
        """
        Aggregate scan results across all roles and endpoints into a structured matrix.
        Returns:
        {
            "roles": ["Alice", "Bob", "Admin", "Unauthenticated"],
            "endpoints": ["GET /api/orders", "GET /api/orders/{id}", ...],
            "matrix": {
                "Alice": {
                    "GET /api/orders/{id}": { "level": "CROSS_ACCESS", "verdict": "NEEDS_FIX", ... }
                }
            },
            "anomalies": [...],
            "policy_score": 72
        }
        """
        all_roles = list(roles)
        if "Unauthenticated" not in all_roles:
            all_roles.append("Unauthenticated")

        ep_keys = [f"{ep.method} {ep.path}" for ep in endpoints]

        # Initialize blank grid
        matrix: dict[str, dict[str, dict[str, Any]]] = {}
        for r in all_roles:
            matrix[r] = {}
            for ep_key in ep_keys:
                matrix[r][ep_key] = {
                    "level": "NOT_TESTED",
                    "status": "gray",
                    "findings": [],
                    "severity": "INFO",
                }

        # Populate matrix from scan results
        for res in results:
            ep_key = f"{res.get('method')} {res.get('endpoint')}"
            if ep_key not in ep_keys:
                continue

            mod = res.get("module_name", "")
            verdict = res.get("verdict", "")
            severity = res.get("severity", "INFO")
            payload = res.get("payload") or {}
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = {}

            accessor = payload.get("accessor_role") or payload.get("accessor") or payload.get("role")

            if mod == "MissingAuth":
                # Applies to Unauthenticated role
                unauth_cell = matrix["Unauthenticated"][ep_key]
                if verdict == "NEEDS_FIX":
                    unauth_cell["level"] = "ALLOWED"
                    unauth_cell["status"] = "red"
                    unauth_cell["findings"].append("Open to unauthenticated callers (Missing Auth Gate)")
                    unauth_cell["severity"] = "HIGH"
                elif verdict == "PASSES":
                    if unauth_cell["level"] == "NOT_TESTED":
                        unauth_cell["level"] = "DENIED"
                        unauth_cell["status"] = "green"

            elif mod in ("HorizontalBOLA", "QueryParamSubstitution", "CrossEndpointGraph"):
                if accessor and accessor in matrix:
                    cell = matrix[accessor][ep_key]
                    if verdict == "NEEDS_FIX":
                        cell["level"] = "CROSS_ACCESS"
                        cell["status"] = "red"
                        cell["severity"] = severity
                        cell["findings"].append(f"{mod}: Can access foreign resources ({res.get('evidence_diff', '')[:100]})")
                    elif verdict == "PASSES" and cell["level"] not in ("CROSS_ACCESS", "ALLOWED"):
                        cell["level"] = "OWN_ONLY"
                        cell["status"] = "green"

            elif mod == "VerticalPrivilege":
                if accessor and accessor in matrix:
                    cell = matrix[accessor][ep_key]
                    if verdict == "NEEDS_FIX":
                        cell["level"] = "CROSS_ACCESS"
                        cell["status"] = "red"
                        cell["severity"] = "CRITICAL"
                        cell["findings"].append("Vertical Privilege Escalation: Non-admin role invoked admin route")
                    elif verdict == "PASSES" and cell["level"] != "CROSS_ACCESS":
                        cell["level"] = "DENIED"
                        cell["status"] = "green"

            elif mod == "MassAssignment":
                if accessor and accessor in matrix:
                    cell = matrix[accessor][ep_key]
                    if verdict == "NEEDS_FIX":
                        cell["level"] = "CROSS_ACCESS"
                        cell["status"] = "red"
                        cell["severity"] = "HIGH"
                        cell["findings"].append("Mass Assignment: Injected privileged fields were honored")

        # Resolve admin baseline
        admin_role = next((r for r in roles if "admin" in r.lower()), None)
        if admin_role and admin_role in matrix:
            for ep_key in ep_keys:
                if matrix[admin_role][ep_key]["level"] == "NOT_TESTED":
                    matrix[admin_role][ep_key]["level"] = "ALLOWED"
                    matrix[admin_role][ep_key]["status"] = "green"

        # Detect Policy Anomalies
        anomalies = self.detect_anomalies(matrix, roles, ep_keys)

        # Compute Authorization Health Score
        policy_score = self.compute_policy_score(matrix, anomalies, results)

        return {
            "roles": all_roles,
            "endpoints": ep_keys,
            "matrix": matrix,
            "anomalies": [a.__dict__ for a in anomalies],
            "policy_score": policy_score,
            "summary": {
                "cross_access_cells": sum(1 for r in matrix.values() for c in r.values() if c["level"] == "CROSS_ACCESS"),
                "own_only_cells": sum(1 for r in matrix.values() for c in r.values() if c["level"] == "OWN_ONLY"),
                "denied_cells": sum(1 for r in matrix.values() for c in r.values() if c["level"] == "DENIED"),
                "allowed_cells": sum(1 for r in matrix.values() for c in r.values() if c["level"] == "ALLOWED"),
            },
        }

    def detect_anomalies(
        self,
        matrix: dict[str, dict[str, dict]],
        roles: list[str],
        endpoints: list[str],
    ) -> list[Anomaly]:
        anomalies: list[Anomaly] = []
        non_admin_roles = [r for r in roles if "admin" not in r.lower()]

        # 1. Privilege Inversion / Boundary Breach (User roles accessing admin endpoints)
        for ep in endpoints:
            if "/admin" in ep.lower():
                breaching_roles = [
                    r for r in non_admin_roles
                    if matrix.get(r, {}).get(ep, {}).get("level") in ("CROSS_ACCESS", "ALLOWED")
                ]
                if breaching_roles:
                    anomalies.append(Anomaly(
                        title="Privilege Boundary Inversion (BFLA)",
                        description=f"Administrative endpoint {ep} is accessible by regular roles: {', '.join(breaching_roles)}.",
                        severity="CRITICAL",
                        endpoints=[ep],
                        roles_involved=breaching_roles,
                    ))

        # 2. Asymmetric Access Policies
        if len(non_admin_roles) >= 2:
            r1, r2 = non_admin_roles[0], non_admin_roles[1]
            for ep in endpoints:
                c1 = matrix.get(r1, {}).get(ep, {}).get("level")
                c2 = matrix.get(r2, {}).get(ep, {}).get("level")
                if (c1 == "CROSS_ACCESS" and c2 in ("OWN_ONLY", "DENIED")) or \
                   (c2 == "CROSS_ACCESS" and c1 in ("OWN_ONLY", "DENIED")):
                    anomalies.append(Anomaly(
                        title="Asymmetric Authorization Policy",
                        description=f"Inconsistent access on {ep}: '{r1}' is {c1} while '{r2}' is {c2}.",
                        severity="MEDIUM",
                        endpoints=[ep],
                        roles_involved=[r1, r2],
                    ))

        # 3. Unauthenticated Exposure
        unauth_exposed = [
            ep for ep in endpoints
            if matrix.get("Unauthenticated", {}).get(ep, {}).get("level") == "ALLOWED"
            and not any(public_word in ep.lower() for public_word in ("/login", "/register", "/health", "/public"))
        ]
        if unauth_exposed:
            anomalies.append(Anomaly(
                title="Unauthenticated Object Exposure",
                description=f"Protected resources are completely open without authentication token: {', '.join(unauth_exposed[:3])}.",
                severity="HIGH",
                endpoints=unauth_exposed,
                roles_involved=["Unauthenticated"],
            ))

        return anomalies

    def compute_policy_score(
        self,
        matrix: dict[str, dict[str, dict]],
        anomalies: list[Anomaly],
        results: list[dict],
    ) -> int:
        score = 100

        # Deduct for vulnerabilities found
        for res in results:
            if res.get("verdict") == "NEEDS_FIX":
                sev = res.get("severity", "HIGH")
                if sev == "CRITICAL":
                    score -= 15
                elif sev == "HIGH":
                    score -= 8
                elif sev == "MEDIUM":
                    score -= 4
                else:
                    score -= 2

        # Deduct for policy anomalies
        for a in anomalies:
            if a.severity == "CRITICAL":
                score -= 12
            elif a.severity == "HIGH":
                score -= 8
            elif a.severity == "MEDIUM":
                score -= 4

        return max(0, min(100, score))
