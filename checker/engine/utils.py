"""
checker/engine/utils.py

Shared helpers used across check modules:
  - safe JSON parsing of responses
  - response snippet truncation
  - building a text diff between two responses
  - detecting sensitive data fields in responses
"""

from __future__ import annotations

import json
import re


def safe_json(response) -> dict | list | None:
    """Return parsed JSON body or None on failure."""
    try:
        return response.json()
    except Exception:
        return None


def snippet(text: str, max_len: int = 800) -> str:
    """Truncate a string for storage/display."""
    if not text:
        return ""
    text = text.strip()
    if len(text) > max_len:
        return text[:max_len] + f"... [truncated {len(text) - max_len} chars]"
    return text


def build_diff(expected_body: str, actual_body: str) -> str:
    """
    Produce a compact textual diff describing what changed between
    an expected (denied) response and the actual response.
    Only line-level — sufficient for short JSON responses.
    """
    exp_lines = (expected_body or "").splitlines()
    act_lines = (actual_body or "").splitlines()

    diff_lines: list[str] = []
    max_lines = max(len(exp_lines), len(act_lines))
    for i in range(max_lines):
        e = exp_lines[i] if i < len(exp_lines) else ""
        a = act_lines[i] if i < len(act_lines) else ""
        if e != a:
            diff_lines.append(f"- {e}")
            diff_lines.append(f"+ {a}")

    return "\n".join(diff_lines) if diff_lines else "(no diff)"


def detect_data_leakage(response, other_user_data: dict | None = None) -> list[str]:
    """
    Inspect a response body for:
      - Other user's known field values (if other_user_data provided)
      - Stack traces
      - Internal file paths
      - Database error strings
    Returns a list of human-readable findings (empty = no leakage found).
    """
    findings: list[str] = []
    body = response.text or ""

    # Stack trace indicators
    if re.search(r"Traceback \(most recent call last\)|at line \d+|Exception in thread", body):
        findings.append("Response contains a stack trace (information disclosure)")

    # Internal path disclosure
    if re.search(r"(/home/|/var/|/app/|C:\\Users\\|C:/Users/|/root/)", body):
        findings.append("Response contains an internal file path")

    # DB error strings
    if re.search(
        r"sqlite3\.|OperationalError|ProgrammingError|SQL syntax|mysql_fetch|ORA-\d{5}",
        body,
        re.IGNORECASE,
    ):
        findings.append("Response contains a database error message")

    # Known other-user data fields
    if other_user_data:
        body_lower = body.lower()
        for field, value in other_user_data.items():
            if value and str(value).lower() in body_lower:
                findings.append(
                    f"Response may contain other user's '{field}' value: {value!r}"
                )

    return findings


def status_ok(status_code: int) -> bool:
    """True if status code indicates a successful response (2xx)."""
    return 200 <= status_code < 300


def status_denied(status_code: int) -> bool:
    """True if status code indicates access was denied.
    Includes 422 because Flask-JWT-Extended returns 422 Unprocessable Entity
    for malformed/invalid tokens instead of 401.
    """
    return status_code in {401, 403, 404, 405, 422}


def build_url(base_url: str, path: str, **query_params) -> str:
    """Construct a full URL, appending query params if given."""
    base_url = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    url = base_url + path
    if query_params:
        qs = "&".join(f"{k}={v}" for k, v in query_params.items())
        url += ("&" if "?" in url else "?") + qs
    return url


def extract_body_field_names(body_schema: dict | None) -> list[str]:
    """Return the list of top-level property names from a JSON Schema object."""
    if not body_schema:
        return []
    if body_schema.get("type") == "object":
        return list(body_schema.get("properties", {}).keys())
    # allOf / oneOf / anyOf
    for key in ("allOf", "oneOf", "anyOf"):
        if key in body_schema:
            names: list[str] = []
            for sub in body_schema[key]:
                names.extend(extract_body_field_names(sub))
            return names
    return []
