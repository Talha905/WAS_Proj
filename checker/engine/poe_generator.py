"""
checker/engine/poe_generator.py

Pillar 4: Proof-of-Exploit (PoE) / Verification Test Script Generator.
Generates reproducible cURL commands, standalone Python regression test scripts,
and raw HTTP request/response artifacts for confirmed vulnerabilities.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


OWASP_MAPPING = {
    "HorizontalBOLA": "API1:2023 - Broken Object Level Authorization (BOLA)",
    "QueryParamSubstitution": "API1:2023 - Broken Object Level Authorization (Query Param IDOR)",
    "CrossEndpointGraph": "API1:2023 - Broken Object Level Authorization (Chained Object Reference)",
    "VerticalPrivilege": "API5:2023 - Broken Function Level Authorization (BFLA)",
    "MassAssignment": "API6:2023 - Unrestricted Resource Consumption & Mass Assignment",
    "MissingAuth": "API2:2023 - Broken Authentication",
    "MalformedAuth": "API2:2023 - Broken Authentication (Token Integrity)",
    "IDManipulation": "API1:2023 / API8:2023 - Security Misconfiguration & Boundary Tampering",
    "MethodSubstitution": "API8:2023 - Security Misconfiguration (HTTP Verb Tunneling)",
    "ResponseLeakage": "API3:2023 - Broken Object Property Level Authorization (Data Leakage)",
}


class PoEGenerator:
    """Generates reproducible exploit commands and test verification scripts."""

    def _get_role_token(self, role_name: str, scan_config: dict) -> str:
        roles = scan_config.get("roles", [])
        for r in roles:
            if r.get("name") == role_name:
                return r.get("value") or r.get("auth_value", "")
        return "<TOKEN>"

    def generate_curl(self, result: dict, scan_config: dict) -> str:
        """Generate a copy-pasteable, annotated cURL command reproducing the finding."""
        base_url = scan_config.get("target_url", "http://localhost:5001").rstrip("/")
        endpoint = result.get("endpoint", "")
        method = result.get("method", "GET").upper()
        module = result.get("module_name", "BOLA")
        payload = result.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        owasp = OWASP_MAPPING.get(module, "OWASP API Security Top 10")
        accessor_role = payload.get("accessor_role") or payload.get("accessor") or payload.get("role") or "attacker"
        owner_role = payload.get("owner_role") or payload.get("owner")
        accessor_token = self._get_role_token(accessor_role, scan_config)
        owner_token = self._get_role_token(owner_role, scan_config) if owner_role else ""

        # Build path with substituted params
        concrete_path = endpoint
        path_subs = payload.get("path") or {}
        if isinstance(path_subs, dict):
            for k, v in path_subs.items():
                concrete_path = concrete_path.replace(f"{{{k}}}", str(v))

        # Query params
        query_subs = payload.get("query") or {}
        if isinstance(query_subs, dict) and query_subs:
            qs = "&".join(f"{k}={v}" for k, v in query_subs.items())
            concrete_path += ("&" if "?" in concrete_path else "?") + qs

        target_url = f"{base_url}{concrete_path}"

        lines = [
            f"# ===========================================================================",
            f"# PROOF OF EXPLOIT — {module}",
            f"# Category : {owasp}",
            f"# Target   : {method} {target_url}",
            f"# Attacker : Role '{accessor_role}'",
        ]
        if owner_role:
            lines.append(f"# Victim   : Role '{owner_role}'")
        lines.extend([
            f"# Expected : HTTP {result.get('expected_status', 403)} Forbidden",
            f"# Actual   : HTTP {result.get('actual_status', 200)} OK",
            f"# ===========================================================================",
            "",
            f"curl -X {method} \"{target_url}\" \\",
            f"  -H \"Authorization: Bearer {accessor_token}\" \\",
            f"  -H \"Content-Type: application/json\" \\",
        ])

        # Body if present
        body_data = payload.get("injected") or payload.get("body")
        if body_data:
            json_str = json.dumps(body_data)
            lines.append(f"  -d '{json_str}' \\")

        lines.append("  -i")

        if owner_token:
            lines.extend([
                "",
                "# ---------------------------------------------------------------------------",
                f"# VERIFICATION BASELINE: Legitimate access by '{owner_role}'",
                "# ---------------------------------------------------------------------------",
                f"curl -X {method} \"{target_url}\" \\",
                f"  -H \"Authorization: Bearer {owner_token}\" \\",
                "  -H \"Content-Type: application/json\" -i",
            ])

        return "\n".join(lines)

    def generate_python(self, result: dict, scan_config: dict) -> str:
        """Generate a standalone Python test script reproducing and verifying the issue."""
        base_url = scan_config.get("target_url", "http://localhost:5001").rstrip("/")
        endpoint = result.get("endpoint", "")
        method = result.get("method", "GET").upper()
        module = result.get("module_name", "BOLA")
        payload = result.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        owasp = OWASP_MAPPING.get(module, "OWASP API Security Top 10")
        accessor_role = payload.get("accessor_role") or payload.get("accessor") or payload.get("role") or "attacker"
        owner_role = payload.get("owner_role") or payload.get("owner")
        accessor_token = self._get_role_token(accessor_role, scan_config)
        owner_token = self._get_role_token(owner_role, scan_config) if owner_role else ""

        concrete_path = endpoint
        path_subs = payload.get("path") or {}
        if isinstance(path_subs, dict):
            for k, v in path_subs.items():
                concrete_path = concrete_path.replace(f"{{{k}}}", str(v))

        query_subs = payload.get("query") or {}
        if isinstance(query_subs, dict) and query_subs:
            qs = "&".join(f"{k}={v}" for k, v in query_subs.items())
            concrete_path += ("&" if "?" in concrete_path else "?") + qs

        target_url = f"{base_url}{concrete_path}"
        body_data = payload.get("injected") or payload.get("body") or {}

        script = f'''#!/usr/bin/env python3
"""
Automated Verification / Proof-of-Exploit Script
Generated by WAS Mini Analyzer on {datetime.now(timezone.utc).isoformat()}
Vulnerability: {module}
Classification: {owasp}
"""
import requests
import json

TARGET_URL = "{target_url}"
ATTACKER_ROLE = "{accessor_role}"
ATTACKER_TOKEN = "{accessor_token}"
VICTIM_ROLE = "{owner_role or 'N/A'}"
VICTIM_TOKEN = "{owner_token}"

headers_attacker = {{
    "Authorization": f"Bearer {{ATTACKER_TOKEN}}",
    "Content-Type": "application/json"
}}

print(f"[*] Testing {method} {{TARGET_URL}} as '{{ATTACKER_ROLE}}'...")
'''
        if method in ("POST", "PUT", "PATCH") and body_data:
            script += f'''payload = {json.dumps(body_data, indent=4)}
resp = requests.{method.lower()}(TARGET_URL, headers=headers_attacker, json=payload)
'''
        else:
            script += f'''resp = requests.{method.lower()}(TARGET_URL, headers=headers_attacker)
'''

        script += f'''print(f"    Status Code: {{resp.status_code}} (Expected: {result.get('expected_status', 403)})")
try:
    print(f"    Response JSON: {{json.dumps(resp.json(), indent=2)[:500]}}")
except Exception:
    print(f"    Response Body: {{resp.text[:300]}}")

if resp.status_code in (200, 201, 204):
    print("\\n[!] VULNERABILITY CONFIRMED: Unauthorized role gained access to restricted resource!")
elif resp.status_code in (401, 403, 404):
    print("\\n[+] VERIFICATION PASSED: Server rejected unauthorized request (Fix validated).")
else:
    print(f"\\n[?] Ambiguous status: {{resp.status_code}}")
'''

        if owner_token:
            script += f'''
if VICTIM_TOKEN:
    print(f"\\n[*] Baseline Verification: Requesting as legitimate owner '{{VICTIM_ROLE}}'...")
    headers_victim = {{"Authorization": f"Bearer {{VICTIM_TOKEN}}", "Content-Type": "application/json"}}
    resp_victim = requests.{method.lower()}(TARGET_URL, headers=headers_victim)
    print(f"    Owner Status Code: {{resp_victim.status_code}}")
'''
        return script

    def generate_raw_http(self, result: dict, scan_config: dict) -> str:
        """Generate raw HTTP request and response representations."""
        base_url = scan_config.get("target_url", "http://localhost:5001")
        endpoint = result.get("endpoint", "")
        method = result.get("method", "GET").upper()
        payload = result.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        accessor_role = payload.get("accessor_role") or payload.get("accessor") or "user"
        token = self._get_role_token(accessor_role, scan_config)

        concrete_path = endpoint
        path_subs = payload.get("path") or {}
        if isinstance(path_subs, dict):
            for k, v in path_subs.items():
                concrete_path = concrete_path.replace(f"{{{k}}}", str(v))

        raw_req = [
            f"{method} {concrete_path} HTTP/1.1",
            f"Host: {base_url.replace('http://', '').replace('https://', '')}",
            f"Authorization: Bearer {token[:20]}...[truncated]",
            "User-Agent: WAS-Mini-Analyzer/2.0",
            "Accept: application/json",
            "Content-Type: application/json",
        ]
        body = payload.get("injected") or payload.get("body")
        if body:
            raw_req.append("")
            raw_req.append(json.dumps(body, indent=2))

        status = result.get("actual_status", 200)
        snippet_text = result.get("response_snippet", "")
        raw_resp = [
            f"HTTP/1.1 {status} {'OK' if status == 200 else 'Unauthorized' if status == 401 else 'Forbidden' if status == 403 else 'Not Found' if status == 404 else ''}",
            "Content-Type: application/json",
            f"Content-Length: {len(snippet_text)}",
            "",
            snippet_text,
        ]

        return "--- HTTP REQUEST ---\n" + "\n".join(raw_req) + "\n\n--- HTTP RESPONSE ---\n" + "\n".join(raw_resp)
