"""
checker/engine/check_modules.py

Ten authorization check modules for the BOLA/IDOR checker.

Each module is a standalone function that returns a list of CheckResult dicts.
Modules are composed by the scanner orchestrator.

Design principle: every check that finds an issue returns verdict=NEEDS_FIX.
A check that confirms access is correctly denied returns PASSES.
When the outcome is ambiguous (network error, unexpected status) returns INCONCLUSIVE.
"""

from __future__ import annotations

import json
import itertools
from typing import Any

from .discovery import Endpoint
from .auth_manager import AuthManager
from .scan_depth import ScanDepthConfig
from .diff_analyzer import DiffAnalyzer
from .utils import (
    safe_json,
    snippet,
    build_diff,
    detect_data_leakage,
    status_ok,
    status_denied,
    build_url,
    extract_body_field_names,
)


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def _result(
    endpoint: str,
    method: str,
    module_name: str,
    payload: dict,
    expected_status: int,
    actual_status: int,
    response_text: str,
    response_headers: dict,
    verdict: str,
    severity: str,
    evidence_diff: str,
    remediation: str,
    similarity_score: float | None = None,
    baseline_snippet: str = "",
    sensitive_fields: list[str] | None = None,
    poe_curl: str = "",
    poe_python: str = "",
    is_canary: bool = False,
    mutation_verified: int | None = None,
) -> dict:
    return {
        "endpoint": endpoint,
        "method": method,
        "module_name": module_name,
        "payload": payload,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "response_snippet": snippet(response_text),
        "response_headers": dict(response_headers),
        "verdict": verdict,
        "severity": severity,
        "evidence_diff": evidence_diff,
        "remediation": remediation,
        "similarity_score": similarity_score,
        "baseline_snippet": snippet(baseline_snippet) if baseline_snippet else "",
        "sensitive_fields": sensitive_fields or [],
        "poe_curl": poe_curl,
        "poe_python": poe_python,
        "is_canary": is_canary,
        "mutation_verified": mutation_verified,
    }


def _inconclusive(endpoint, method, module_name, payload, reason) -> dict:
    return _result(
        endpoint, method, module_name, payload,
        expected_status=0, actual_status=0,
        response_text=reason, response_headers={},
        verdict="INCONCLUSIVE", severity="INFO",
        evidence_diff="", remediation="Check network connectivity to target.",
    )


# ---------------------------------------------------------------------------
# Helper: pick IDs for a specific resource type owned by a role
# ---------------------------------------------------------------------------

def _ids_for(known_ids: dict, role_name: str, resource: str) -> list[Any]:
    role_ids = known_ids.get(role_name, {})
    return role_ids.get(resource, [])


def _all_resource_types(known_ids: dict) -> set[str]:
    resources: set[str] = set()
    for role_ids in known_ids.values():
        resources.update(role_ids.keys())
    return resources


def _infer_resource_type(endpoint_path: str, known_resource_types: set[str]) -> str | None:
    """
    Match endpoint path to the corresponding resource type so we don't
    plug order IDs into /api/users/{id} or user IDs into /api/orders/{id}.
    e.g. '/api/users/{id}' -> 'user'
         '/api/orders/{id}' -> 'order'
         '/api/products/{id}' -> 'product'
    """
    path_lower = endpoint_path.lower()
    for rt in known_resource_types:
        rt_lower = rt.lower()
        if (
            f"/{rt_lower}s" in path_lower
            or f"/{rt_lower}" in path_lower
            or f"_{rt_lower}" in path_lower
        ):
            return rt
    return None


# ---------------------------------------------------------------------------
# Module 1 — Horizontal BOLA
# Test whether User A's token can access User B's object IDs.
# Employs Differential Response Analysis & Semantic Tree Similarity.
# ---------------------------------------------------------------------------

def check_horizontal_bola(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
    depth: ScanDepthConfig | None = None,
    diff_analyzer: DiffAnalyzer | None = None,
    lifecycle_engine: Any = None,
    **kwargs: Any,
) -> list[dict]:
    """
    For every pair of (owner_role, accessor_role) where they differ,
    substitute the owner's object IDs into the path.
    Establishes an authorized baseline with owner_role, probes with accessor_role,
    and performs Differential Response Analysis.
    """
    if not endpoint.has_id_param:
        return []

    depth_cfg = depth or ScanDepthConfig()
    analyzer = diff_analyzer or DiffAnalyzer()

    results: list[dict] = []
    roles = auth_manager.role_names()

    all_rts = _all_resource_types(known_ids)
    inferred_type = _infer_resource_type(endpoint.path, all_rts)
    target_resource_types = [inferred_type] if inferred_type else list(all_rts)

    pair_count = 0
    max_pairs = depth_cfg.max_role_pairs
    max_ids = depth_cfg.max_ids_per_resource

    for owner_role, accessor_role in itertools.permutations(roles, 2):
        if owner_role == accessor_role:
            continue
        if pair_count >= max_pairs:
            break
        pair_count += 1

        # Find IDs owned by owner_role that match path params
        for resource_type in target_resource_types:
            owner_ids = _ids_for(known_ids, owner_role, resource_type)
            if not owner_ids:
                continue

            for obj_id in owner_ids[:max_ids]:
                # If the accessor also legitimately owns this object under this resource type, skip
                if obj_id in _ids_for(known_ids, accessor_role, resource_type):
                    continue

                path_params = (
                    endpoint.path_params
                    or endpoint.extract_path_params_from_template()
                )
                if not path_params:
                    continue

                param_name = path_params[0]
                concrete_path = endpoint.path.replace(f"{{{param_name}}}", str(obj_id))
                url = build_url(base_url, concrete_path)

                # 1. Establish authorized baseline request as owner
                base_resp = auth_manager.make_request(endpoint.method, url, owner_role)
                base_json = safe_json(base_resp)
                base_snippet = snippet(base_resp.text, 300) if base_resp.text else ""

                # 2. Make unauthorized probe request as accessor
                probe_resp = auth_manager.make_request(endpoint.method, url, accessor_role)

                if probe_resp.status_code == 0:
                    results.append(
                        _inconclusive(
                            endpoint.path, endpoint.method,
                            "HorizontalBOLA",
                            {"path": {param_name: obj_id}, "accessor": accessor_role},
                            probe_resp.text,
                        )
                    )
                    continue

                probe_json = safe_json(probe_resp)

                # 3. Perform Differential Analysis
                owner_hints = {}
                owner_uids = _ids_for(known_ids, owner_role, "user")
                if owner_uids:
                    owner_hints["user_id"] = owner_uids[0]

                verdict, severity, evidence_diff, remediation, sim_score, sens_leaks = analyzer.evaluate_verdict(
                    base_resp.status_code,
                    base_json,
                    probe_resp.status_code,
                    probe_json,
                    resource_type,
                    owner_role,
                    accessor_role,
                    owner_hints=owner_hints,
                )

                # 4. Optional state mutation verification for write endpoints
                mut_verified = None
                if verdict == "NEEDS_FIX" and endpoint.is_write and lifecycle_engine and depth_cfg.run_mutation_verification:
                    mut_persisted = lifecycle_engine.verify_mutation(endpoint.path, obj_id, owner_role, accessor_role)
                    mut_verified = 1 if mut_persisted else 0
                    if mut_persisted:
                        severity = "CRITICAL"
                        evidence_diff += "\n  • [VERIFIED MUTATION] State mutation persisted in target resource!"

                results.append(_result(
                    endpoint.path, endpoint.method, "HorizontalBOLA",
                    payload={"path": {param_name: obj_id}, "accessor_role": accessor_role, "owner_role": owner_role},
                    expected_status=403,
                    actual_status=probe_resp.status_code,
                    response_text=probe_resp.text,
                    response_headers=probe_resp.headers,
                    verdict=verdict,
                    severity=severity,
                    evidence_diff=evidence_diff,
                    remediation=remediation,
                    similarity_score=sim_score,
                    baseline_snippet=base_snippet,
                    sensitive_fields=sens_leaks,
                    mutation_verified=mut_verified,
                ))

    return results


# ---------------------------------------------------------------------------
# Module 2 — Vertical Privilege Escalation
# Non-admin roles accessing admin-only endpoints.
# ---------------------------------------------------------------------------

def check_vertical_privilege(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
) -> list[dict]:
    """
    Identify admin-tagged endpoints and attempt access with every non-admin role.
    """
    is_admin_endpoint = (
        "/admin/" in endpoint.path
        or "admin" in [t.lower() for t in endpoint.tags]
        or endpoint.path.lower().startswith("/admin")
        or "/api/admin" in endpoint.path
    )
    if not is_admin_endpoint:
        return []

    results: list[dict] = []
    # Identify admin roles: those whose name contains 'admin'
    admin_role_names = [
        r for r in auth_manager.role_names() if "admin" in r.lower()
    ]
    non_admin_roles = [
        r for r in auth_manager.role_names() if r not in admin_role_names
    ]

    url = build_url(base_url, endpoint.path)

    for role_name in non_admin_roles:
        resp = auth_manager.make_request(endpoint.method, url, role_name)

        if resp.status_code == 0:
            results.append(_inconclusive(
                endpoint.path, endpoint.method, "VerticalPrivilege",
                {"role": role_name}, resp.text,
            ))
            continue

        if status_ok(resp.status_code):
            verdict, severity = "NEEDS_FIX", "HIGH"
            remediation = (
                f"Endpoint {endpoint.method} {endpoint.path} is admin-only but is accessible "
                f"to role '{role_name}'. Add a role-based access control check "
                f"(e.g. @require_admin decorator) that verifies current_user.role == 'admin' "
                f"on every request."
            )
            evidence_diff = build_diff(
                f"Expected 403/404 for non-admin role '{role_name}'",
                f"Got {resp.status_code}: {snippet(resp.text, 200)}",
            )
        elif status_denied(resp.status_code):
            verdict, severity = "PASSES", "INFO"
            remediation = evidence_diff = ""
        else:
            verdict, severity = "INCONCLUSIVE", "INFO"
            remediation = "Unexpected status — verify manually."
            evidence_diff = f"Status: {resp.status_code}"

        results.append(_result(
            endpoint.path, endpoint.method, "VerticalPrivilege",
            payload={"role": role_name},
            expected_status=403, actual_status=resp.status_code,
            response_text=resp.text, response_headers=resp.headers,
            verdict=verdict, severity=severity,
            evidence_diff=evidence_diff, remediation=remediation,
        ))

    return results


# ---------------------------------------------------------------------------
# Module 3 — Missing Authentication
# Unauthenticated requests to protected endpoints.
# ---------------------------------------------------------------------------

def check_missing_auth(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
) -> list[dict]:
    """
    Make a request with no auth credentials at all.
    If the endpoint returns 2xx, it's missing an auth gate.
    """
    if not endpoint.requires_auth:
        return []

    results: list[dict] = []

    # Build a concrete URL (substitute first known ID if path param exists)
    path = endpoint.path
    path_params = endpoint.extract_path_params_from_template()
    if path_params:
        first_role = auth_manager.role_names()[0] if auth_manager.role_names() else None
        for resource in _all_resource_types(known_ids):
            ids = _ids_for(known_ids, first_role, resource) if first_role else []
            if ids:
                path = path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                break

    url = build_url(base_url, path)
    resp = auth_manager.make_request_no_auth(endpoint.method, url)

    if resp.status_code == 0:
        return [_inconclusive(endpoint.path, endpoint.method, "MissingAuth", {}, resp.text)]

    if status_ok(resp.status_code):
        verdict, severity = "NEEDS_FIX", "HIGH"
        remediation = (
            f"{endpoint.method} {endpoint.path} responded with {resp.status_code} "
            f"to a request with no authentication credentials. Ensure the endpoint "
            f"is protected with an authentication middleware/decorator that returns 401 "
            f"when no valid credentials are supplied."
        )
        evidence_diff = build_diff("Expected 401", f"Got {resp.status_code}: {snippet(resp.text, 200)}")
    elif resp.status_code == 401:
        verdict, severity = "PASSES", "INFO"
        remediation = evidence_diff = ""
    else:
        verdict, severity = "INCONCLUSIVE", "INFO"
        remediation = "Verify this endpoint's auth requirement."
        evidence_diff = f"Status: {resp.status_code}"

    results.append(_result(
        endpoint.path, endpoint.method, "MissingAuth",
        payload={"auth": "none"},
        expected_status=401, actual_status=resp.status_code,
        response_text=resp.text, response_headers=resp.headers,
        verdict=verdict, severity=severity,
        evidence_diff=evidence_diff, remediation=remediation,
    ))
    return results


# ---------------------------------------------------------------------------
# Module 4 — Malformed / Invalid Auth
# Requests with deliberately bad auth tokens.
# ---------------------------------------------------------------------------

def check_malformed_auth(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
) -> list[dict]:
    """
    Try four variants of deliberately invalid auth headers.
    Any 2xx response means the auth gate is not validating the credential.
    """
    if not endpoint.requires_auth:
        return []

    variants = ["invalid", "wrong_scheme"]
    results: list[dict] = []

    path = endpoint.path
    path_params = endpoint.extract_path_params_from_template()
    if path_params:
        first_role = auth_manager.role_names()[0] if auth_manager.role_names() else None
        for resource in _all_resource_types(known_ids):
            ids = _ids_for(known_ids, first_role, resource) if first_role else []
            if ids:
                path = path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                break

    url = build_url(base_url, path)

    for variant in variants:
        resp = auth_manager.make_request_malformed_auth(endpoint.method, url, variant=variant)

        if resp.status_code == 0:
            results.append(_inconclusive(
                endpoint.path, endpoint.method, "MalformedAuth",
                {"variant": variant}, resp.text,
            ))
            continue

        if status_ok(resp.status_code):
            verdict, severity = "NEEDS_FIX", "MEDIUM"
            remediation = (
                f"Endpoint {endpoint.method} {endpoint.path} returned {resp.status_code} "
                f"when given a malformed '{variant}' auth credential. The token validation "
                f"logic should reject all invalid/malformed tokens and return 401."
            )
            evidence_diff = build_diff(
                f"Expected 401 for malformed auth variant '{variant}'",
                f"Got {resp.status_code}: {snippet(resp.text, 200)}",
            )
        elif status_denied(resp.status_code):
            verdict, severity = "PASSES", "INFO"
            remediation = evidence_diff = ""
        else:
            verdict, severity = "INCONCLUSIVE", "INFO"
            remediation = f"Unexpected {resp.status_code} for malformed auth — verify manually."
            evidence_diff = f"Status: {resp.status_code}"

        results.append(_result(
            endpoint.path, endpoint.method, "MalformedAuth",
            payload={"auth_variant": variant},
            expected_status=401, actual_status=resp.status_code,
            response_text=resp.text, response_headers=resp.headers,
            verdict=verdict, severity=severity,
            evidence_diff=evidence_diff, remediation=remediation,
        ))

    return results


# ---------------------------------------------------------------------------
# Module 5 — ID Manipulation / Enumeration
# Try boundary, negative, string, and adjacent IDs.
# ---------------------------------------------------------------------------

_FUZZ_ID_VARIANTS = [
    0, -1, 99999,
]


def check_id_manipulation(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
    depth: ScanDepthConfig | None = None,
    **kwargs: Any,
) -> list[dict]:
    """
    For each role, substitute fuzzed ID values into the path and check:
    - 500 responses → potential server error (information disclosure)
    - 200 responses for IDs that clearly don't belong to the user → NEEDS_FIX
    """
    path_params = endpoint.extract_path_params_from_template()
    if not path_params or not endpoint.has_id_param:
        return []

    depth_cfg = depth or ScanDepthConfig()
    results: list[dict] = []
    param_name = path_params[0]

    for role_name in auth_manager.role_names():
        # Use depth-configured fuzz variants
        fuzz_ids = depth_cfg.fuzz_variants

        for fuzz_id in fuzz_ids:
            concrete_path = endpoint.path.replace(f"{{{param_name}}}", str(fuzz_id))
            url = build_url(base_url, concrete_path)
            resp = auth_manager.make_request(endpoint.method, url, role_name)

            if resp.status_code == 0:
                continue

            if resp.status_code == 500:
                results.append(_result(
                    endpoint.path, endpoint.method, "IDManipulation",
                    payload={"path": {param_name: fuzz_id}, "role": role_name},
                    expected_status=400, actual_status=500,
                    response_text=resp.text, response_headers=resp.headers,
                    verdict="INCONCLUSIVE", severity="MEDIUM",
                    evidence_diff=f"Server returned 500 for ID={fuzz_id!r}",
                    remediation=(
                        "The server returned HTTP 500 for an invalid/boundary ID. "
                        "Add input validation before database queries and return 400/404 "
                        "for malformed IDs. Never expose internal errors in responses."
                    ),
                ))
            elif status_ok(resp.status_code):
                # If the returned object's user_id differs from what we know,
                # or if the ID is clearly not owned by this role — flag it.
                body = safe_json(resp)
                returned_user_id = None
                if isinstance(body, dict):
                    for key in ("user_id", "owner_id", "userId", "ownerId"):
                        if key in body:
                            returned_user_id = body[key]
                            break

                role_user_ids = _ids_for(known_ids, role_name, "user")
                is_own_resource = (
                    returned_user_id is None
                    or (role_user_ids and returned_user_id in role_user_ids)
                )

                if not is_own_resource:
                    results.append(_result(
                        endpoint.path, endpoint.method, "IDManipulation",
                        payload={"path": {param_name: fuzz_id}, "role": role_name},
                        expected_status=404, actual_status=resp.status_code,
                        response_text=resp.text, response_headers=resp.headers,
                        verdict="NEEDS_FIX", severity="HIGH",
                        evidence_diff=build_diff(
                            f"Expected 404 — ID {fuzz_id!r} should not be accessible to {role_name}",
                            f"Got 200 with owner={returned_user_id}",
                        ),
                        remediation=(
                            f"Endpoint {endpoint.method} {endpoint.path} returned a resource "
                            f"owned by user {returned_user_id} to role '{role_name}' who owns "
                            f"user IDs {role_user_ids}. Verify ownership before returning data."
                        ),
                    ))
                # If the resource appears to be their own, it's expected — no result needed.

    return results


# ---------------------------------------------------------------------------
# Module 6 — Mass Assignment
# Inject privilege-escalating fields into POST/PUT request bodies.
# ---------------------------------------------------------------------------

_MASS_ASSIGN_PAYLOADS = [
    {"role": "admin"},
    {"is_admin": True},
]


def check_mass_assignment(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
    depth: ScanDepthConfig | None = None,
    **kwargs: Any,
) -> list[dict]:
    """
    Inject extra privilege-escalating fields alongside a normal payload.
    If the response reflects the injected field as accepted (role changed,
    is_admin=true, etc.), flag NEEDS_FIX.
    """
    if endpoint.method not in {"POST", "PUT", "PATCH"}:
        return []

    depth_cfg = depth or ScanDepthConfig()
    results: list[dict] = []
    roles = auth_manager.role_names()
    non_admin_roles = [r for r in roles if "admin" not in r.lower()]
    if depth_cfg.depth == "quick":
        non_admin_roles = non_admin_roles[:1]

    # Build the base path (substitute first ID param if present)
    path = endpoint.path
    path_params = endpoint.extract_path_params_from_template()
    if path_params:
        first_role = non_admin_roles[0] if non_admin_roles else (roles[0] if roles else None)
        for resource in _all_resource_types(known_ids):
            ids = _ids_for(known_ids, first_role, resource) if first_role else []
            if ids:
                path = path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                break

    url = build_url(base_url, path)

    # Extract known body fields from schema, build minimal valid-looking base body
    schema_fields = extract_body_field_names(endpoint.body_schema)
    base_body: dict = {}
    for field in schema_fields:
        # Provide plausible values for common field names
        if "title" in field.lower() or "name" in field.lower():
            base_body[field] = "Test Item"
        elif "amount" in field.lower() or "price" in field.lower():
            base_body[field] = 1.0
        elif "email" in field.lower():
            base_body[field] = "test@example.com"
        elif "password" in field.lower():
            base_body[field] = "TestPassword1!"
        else:
            base_body[field] = "test"

    for role_name in non_admin_roles:
        for extra_payload in _MASS_ASSIGN_PAYLOADS:
            injected_body = {**base_body, **extra_payload}
            resp = auth_manager.make_request(
                endpoint.method, url, role_name, json=injected_body
            )

            if resp.status_code == 0:
                continue

            body = safe_json(resp)
            # Detect if injected privileged fields appear in response
            field_honored = False
            honored_fields: list[str] = []
            if isinstance(body, dict):
                for inj_key, inj_val in extra_payload.items():
                    if inj_key in body and body[inj_key] == inj_val:
                        field_honored = True
                        honored_fields.append(f"{inj_key}={inj_val!r}")

            if field_honored and status_ok(resp.status_code):
                results.append(_result(
                    endpoint.path, endpoint.method, "MassAssignment",
                    payload={"injected": extra_payload, "role": role_name},
                    expected_status=200, actual_status=resp.status_code,
                    response_text=resp.text, response_headers=resp.headers,
                    verdict="NEEDS_FIX", severity="HIGH",
                    evidence_diff=build_diff(
                        f"Injected fields {honored_fields} should be ignored",
                        f"Response reflected: {honored_fields}",
                    ),
                    remediation=(
                        f"Endpoint {endpoint.method} {endpoint.path} honoured injected fields "
                        f"{honored_fields} in the response. Use an explicit allowlist of "
                        f"accepted body fields and never pass raw request data to your ORM/DB. "
                        f"Fields like 'role', 'is_admin', 'privilege' must never be writable "
                        f"by regular users."
                    ),
                ))
            elif resp.status_code in {400, 422}:
                # Server correctly rejected the payload
                results.append(_result(
                    endpoint.path, endpoint.method, "MassAssignment",
                    payload={"injected": extra_payload, "role": role_name},
                    expected_status=400, actual_status=resp.status_code,
                    response_text=resp.text, response_headers=resp.headers,
                    verdict="PASSES", severity="INFO",
                    evidence_diff="", remediation="",
                ))

    return results


# ---------------------------------------------------------------------------
# Module 7 — Method Substitution
# Try alternate HTTP verbs on the same path.
# ---------------------------------------------------------------------------

_ALL_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
# OPTIONS is excluded — a 200 response is expected CORS preflight behavior, not a finding.
# HEAD is excluded — most frameworks auto-allow HEAD on any GET route.


def check_method_substitution(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
) -> list[dict]:
    """
    For each defined endpoint, try alternate HTTP methods with a
    different role's credentials. Unexpected 2xx = NEEDS_FIX.
    """
    results: list[dict] = []
    roles = auth_manager.role_names()
    alternate_methods = _ALL_METHODS - {endpoint.method}

    path = endpoint.path
    path_params = endpoint.extract_path_params_from_template()

    if path_params:
        first_role = roles[0] if roles else None
        for resource in _all_resource_types(known_ids):
            ids = _ids_for(known_ids, first_role, resource) if first_role else []
            if ids:
                path = path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                break

    url = build_url(base_url, path)

    # Test with first role only — method enforcement is server-side and role-independent
    role_name = roles[0] if roles else None
    if not role_name:
        return []

    for alt_method in alternate_methods:
        resp = auth_manager.make_request(alt_method, url, role_name)

        if resp.status_code == 0:
            continue
        if resp.status_code == 405:  # Method Not Allowed — correct behaviour
            results.append(_result(
                endpoint.path, alt_method, "MethodSubstitution",
                payload={"method": alt_method, "role": role_name},
                expected_status=405, actual_status=405,
                response_text=resp.text, response_headers=resp.headers,
                verdict="PASSES", severity="INFO",
                evidence_diff="", remediation="",
            ))
        elif status_ok(resp.status_code):
            results.append(_result(
                endpoint.path, alt_method, "MethodSubstitution",
                payload={"method": alt_method, "role": role_name},
                expected_status=405, actual_status=resp.status_code,
                response_text=resp.text, response_headers=resp.headers,
                verdict="NEEDS_FIX", severity="LOW",
                evidence_diff=build_diff(
                    f"Expected 405 for {alt_method} {endpoint.path}",
                    f"Got {resp.status_code}: {snippet(resp.text, 200)}",
                ),
                remediation=(
                    f"Endpoint path {endpoint.path} accepted unexpected HTTP method {alt_method}. "
                    f"Explicitly restrict HTTP methods per route and return 405 for disallowed ones."
                ),
                ))

    return results


# ---------------------------------------------------------------------------
# Module 8 — Response Leakage Detection
# Check 403/404 responses for accidental data disclosure.
# ---------------------------------------------------------------------------

def check_response_leakage(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
) -> list[dict]:
    """
    Make a cross-user request that should be denied, then inspect
    the denial response body for other users' data, stack traces, or
    internal path/DB error strings.
    """
    results: list[dict] = []
    roles = auth_manager.role_names()

    for owner_role, accessor_role in itertools.permutations(roles, 2):
        path = endpoint.path
        path_params = endpoint.extract_path_params_from_template()

        owner_ids_found = False
        for resource in _all_resource_types(known_ids):
            ids = _ids_for(known_ids, owner_role, resource)
            if ids and path_params:
                path = endpoint.path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                owner_ids_found = True
                break

        if not owner_ids_found and path_params:
            continue

        url = build_url(base_url, path)
        resp = auth_manager.make_request(endpoint.method, url, accessor_role)

        if resp.status_code == 0 or status_ok(resp.status_code):
            # If 2xx, HorizontalBOLA already covers it — skip leakage check
            continue

        # Build known data about the owner so we can search for it in the response
        owner_user_ids = _ids_for(known_ids, owner_role, "user")
        other_user_data: dict = {}
        if owner_user_ids:
            other_user_data["user_id"] = str(owner_user_ids[0])

        findings = detect_data_leakage(resp, other_user_data)

        if findings:
            results.append(_result(
                endpoint.path, endpoint.method, "ResponseLeakage",
                payload={"accessor": accessor_role, "owner": owner_role},
                expected_status=resp.status_code, actual_status=resp.status_code,
                response_text=resp.text, response_headers=resp.headers,
                verdict="NEEDS_FIX", severity="MEDIUM",
                evidence_diff="\n".join(findings),
                remediation=(
                    "The denial response leaks internal information. "
                    "Return only a generic error message (e.g. {\"error\": \"Not found\"}). "
                    "Never include stack traces, internal paths, or other users' data in error responses."
                ),
            ))
        else:
            results.append(_result(
                endpoint.path, endpoint.method, "ResponseLeakage",
                payload={"accessor": accessor_role, "owner": owner_role},
                expected_status=resp.status_code, actual_status=resp.status_code,
                response_text=resp.text, response_headers=resp.headers,
                verdict="PASSES", severity="INFO",
                evidence_diff="", remediation="",
            ))

    return results


# ---------------------------------------------------------------------------
# Module 9 — Cross-Endpoint Object Graph Traversal
# IDs returned by one endpoint are probed via other endpoints.
# ---------------------------------------------------------------------------

def check_cross_endpoint_graph(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
    all_endpoints: list[Endpoint] | None = None,
) -> list[dict]:
    """
    Collect resource IDs returned by one role's GET requests, then
    probe related endpoints using a different role's token.
    """
    if endpoint.method != "GET":
        return []
    if not all_endpoints:
        return []

    results: list[dict] = []
    roles = auth_manager.role_names()

    for owner_role in roles:
        # Make a GET request as owner to collect IDs from response
        path = endpoint.path
        path_params = endpoint.extract_path_params_from_template()
        if path_params:
            for resource in _all_resource_types(known_ids):
                ids = _ids_for(known_ids, owner_role, resource)
                if ids:
                    path = endpoint.path.replace(f"{{{path_params[0]}}}", str(ids[0]))
                    break

        url = build_url(base_url, path)
        resp = auth_manager.make_request(endpoint.method, url, owner_role)

        if not status_ok(resp.status_code):
            continue

        body = safe_json(resp)
        collected_ids: list[Any] = []

        # Extract IDs from response
        if isinstance(body, dict):
            for key in ("id", "user_id", "order_id", "product_id", "owner_id"):
                if key in body:
                    collected_ids.append(body[key])
        elif isinstance(body, list):
            for item in body[:5]:  # limit to first 5 items
                if isinstance(item, dict) and "id" in item:
                    collected_ids.append(item["id"])

        if not collected_ids:
            continue

        # Now probe all OTHER endpoints that have ID params with a DIFFERENT role
        for other_ep in all_endpoints:
            if other_ep.path == endpoint.path or not other_ep.has_id_param:
                continue
            other_path_params = other_ep.extract_path_params_from_template()
            if not other_path_params:
                continue

            other_inferred_rt = _infer_resource_type(other_ep.path, _all_resource_types(known_ids))

            for accessor_role in roles:
                if accessor_role == owner_role:
                    continue
                for cid in collected_ids[:3]:  # limit combinations
                    if other_inferred_rt and cid in _ids_for(known_ids, accessor_role, other_inferred_rt):
                        continue

                    concrete = other_ep.path.replace(f"{{{other_path_params[0]}}}", str(cid))
                    probe_url = build_url(base_url, concrete)
                    probe_resp = auth_manager.make_request(
                        other_ep.method, probe_url, accessor_role
                    )

                    if probe_resp.status_code == 0:
                        continue

                    if status_ok(probe_resp.status_code):
                        results.append(_result(
                            other_ep.path, other_ep.method, "CrossEndpointGraph",
                            payload={
                                "id_source": f"{endpoint.method} {endpoint.path}",
                                "probed_id": cid,
                                "owner_role": owner_role,
                                "accessor_role": accessor_role,
                            },
                            expected_status=403, actual_status=probe_resp.status_code,
                            response_text=probe_resp.text, response_headers=probe_resp.headers,
                            verdict="NEEDS_FIX", severity="HIGH",
                            evidence_diff=build_diff(
                                f"Expected 403/404 — ID {cid} was discovered from {owner_role}'s response",
                                f"Got {probe_resp.status_code}: {snippet(probe_resp.text, 200)}",
                            ),
                            remediation=(
                                f"An ID ({cid}) obtained from {owner_role}'s response to "
                                f"{endpoint.method} {endpoint.path} was used to access "
                                f"{other_ep.method} {other_ep.path} as '{accessor_role}'. "
                                f"Enforce ownership checks consistently across the entire object graph."
                            ),
                        ))

    return results


# ---------------------------------------------------------------------------
# Module 10 — Query Parameter Substitution
# User-supplied user_id / owner_id query params honored by the server.
# ---------------------------------------------------------------------------

_PRIV_QUERY_PARAMS = ["admin", "debug"]
_USER_ID_QUERY_PARAMS = [
    "user_id", "userId", "uid",
]


def check_query_param_substitution(
    endpoint: Endpoint,
    base_url: str,
    auth_manager: AuthManager,
    scan_config: dict,
    known_ids: dict,
    depth: ScanDepthConfig | None = None,
    **kwargs: Any,
) -> list[dict]:
    """
    Make GET requests with:
    1. ?user_id=<other_user's_id> — if server uses this instead of JWT identity
    2. ?admin=true, ?debug=true — server should ignore these
    """
    if endpoint.method != "GET":
        return []

    depth_cfg = depth or ScanDepthConfig()
    results: list[dict] = []
    roles = auth_manager.role_names()
    pair_count = 0
    max_pairs = depth_cfg.max_role_pairs
    active_params = _USER_ID_QUERY_PARAMS[:depth_cfg.max_query_params]

    for accessor_role, owner_role in itertools.permutations(roles, 2):
        if pair_count >= max_pairs:
            break
        pair_count += 1

        owner_user_ids = _ids_for(known_ids, owner_role, "user")
        if not owner_user_ids:
            continue

        other_uid = owner_user_ids[0]
        path = endpoint.path
        # Remove path param if present (we're focusing on query params here)
        path_params = endpoint.extract_path_params_from_template()
        if path_params:
            accessor_uids = _ids_for(known_ids, accessor_role, "user")
            if accessor_uids:
                path = path.replace(f"{{{path_params[0]}}}", str(accessor_uids[0]))

        # 1. Test user_id-style params
        for qp in active_params:
            url = build_url(base_url, path, **{qp: other_uid})
            resp = auth_manager.make_request(endpoint.method, url, accessor_role)

            if status_ok(resp.status_code):
                body = safe_json(resp)
                # Check if response structured data actually contains other_uid in an ID/user field
                def _has_uid(data, uid):
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if k.lower() in ("id", "user_id", "userid", "owner_id", "ownerid", "account_id"):
                                if str(v) == str(uid):
                                    return True
                            if _has_uid(v, uid):
                                return True
                    elif isinstance(data, list):
                        for item in data:
                            if _has_uid(item, uid):
                                return True
                    return False

                other_uid_present = _has_uid(body, other_uid)

                if other_uid_present:
                    results.append(_result(
                        endpoint.path, endpoint.method, "QueryParamSubstitution",
                        payload={"query": {qp: other_uid}, "accessor": accessor_role},
                        expected_status=200, actual_status=resp.status_code,
                        response_text=resp.text, response_headers=resp.headers,
                        verdict="NEEDS_FIX", severity="HIGH",
                        evidence_diff=build_diff(
                            f"Expected: response filtered by JWT identity ({accessor_role})",
                            f"Got: response contains {owner_role}'s user_id={other_uid}",
                        ),
                        remediation=(
                            f"Endpoint {endpoint.method} {endpoint.path} uses the ?{qp}= query "
                            f"parameter to filter results instead of the authenticated user's identity. "
                            f"Always derive the user identity from the JWT/session — never trust "
                            f"client-supplied ID parameters."
                        ),
                    ))

        # 2. Test privilege-escalation query params
        for qp in _PRIV_QUERY_PARAMS:
            url = build_url(base_url, path, **{qp: "true"})
            resp = auth_manager.make_request(endpoint.method, url, accessor_role)

            if resp.status_code == 0:
                continue
            if status_ok(resp.status_code):
                # Can't easily tell if privilege was granted -- flag as inconclusive
                results.append(_result(
                    endpoint.path, endpoint.method, "QueryParamSubstitution",
                    payload={"query": {qp: "true"}, "accessor": accessor_role},
                    expected_status=200, actual_status=resp.status_code,
                    response_text=resp.text, response_headers=resp.headers,
                    verdict="INCONCLUSIVE", severity="LOW",
                    evidence_diff=f"Param ?{qp}=true returned 200 -- verify manually",
                    remediation=(
                        f"Verify that ?{qp}=true query parameter does not alter access control "
                        f"behavior. Server-side access control must not depend on client-supplied flags."
                    ),
                ))

    return results


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

ALL_MODULES = [
    check_horizontal_bola,
    check_vertical_privilege,
    check_missing_auth,
    check_malformed_auth,
    check_id_manipulation,
    check_mass_assignment,
    check_method_substitution,
    check_response_leakage,
    check_cross_endpoint_graph,
    check_query_param_substitution,
]
