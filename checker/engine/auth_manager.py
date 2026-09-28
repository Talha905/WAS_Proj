"""
checker/engine/auth_manager.py

Manages multiple named auth roles and builds authenticated HTTP requests.
Supports Bearer token, session cookie, and API key (header or query).
"""

from __future__ import annotations

import requests
from requests import Response, Session


class AuthManager:
    """
    Holds credentials for N named roles and dispatches HTTP requests
    with the appropriate authentication applied.

    Role dict schema:
        {
          "name": "user_a",
          "type": "bearer" | "cookie" | "apikey",
          "value": "<token or cookie value>",
          "header_name": "Authorization"   # used for apikey type; default X-API-Key
        }
    """

    TIMEOUT = 5  # seconds — all targets are localhost

    def __init__(self, roles: list[dict]) -> None:
        self._roles: dict[str, dict] = {r["name"]: r for r in roles}
        # One persistent session per role for cookie persistence
        self._sessions: dict[str, Session] = {
            name: Session() for name in self._roles
        }

    # ------------------------------------------------------------------
    # Headers / cookies builders
    # ------------------------------------------------------------------

    def get_headers(self, role_name: str) -> dict[str, str]:
        role = self._roles.get(role_name, {})
        rtype = role.get("type", "bearer")
        value = role.get("value", "")

        if rtype == "bearer":
            return {"Authorization": f"Bearer {value}"}
        if rtype == "apikey":
            header = role.get("header_name", "X-API-Key")
            return {header: value}
        # cookie: no auth header needed (sent via session cookie jar)
        return {}

    def get_cookies(self, role_name: str) -> dict[str, str]:
        role = self._roles.get(role_name, {})
        rtype = role.get("type", "cookie")
        if rtype == "cookie":
            key = role.get("header_name", "session")
            return {key: role.get("value", "")}
        return {}

    def role_names(self) -> list[str]:
        return list(self._roles.keys())

    def role_info(self, role_name: str) -> dict:
        return self._roles.get(role_name, {})

    # ------------------------------------------------------------------
    # Request helpers
    # ------------------------------------------------------------------

    def make_request(
        self,
        method: str,
        url: str,
        role_name: str,
        **kwargs,
    ) -> Response:
        """Make an HTTP request authenticated as `role_name`."""
        headers = {**self.get_headers(role_name), **kwargs.pop("headers", {})}
        cookies = {**self.get_cookies(role_name), **kwargs.pop("cookies", {})}
        session = self._sessions.get(role_name, requests)
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                cookies=cookies,
                timeout=self.TIMEOUT,
                allow_redirects=False,
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException as exc:
            return _ErrorResponse(str(exc))

    def make_request_no_auth(self, method: str, url: str, **kwargs) -> Response:
        """Make an unauthenticated request (no headers, no cookies)."""
        kwargs.pop("headers", None)
        kwargs.pop("cookies", None)
        try:
            resp = requests.request(
                method,
                url,
                timeout=self.TIMEOUT,
                allow_redirects=False,
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException as exc:
            return _ErrorResponse(str(exc))

    def make_request_malformed_auth(
        self, method: str, url: str, variant: str = "invalid", **kwargs
    ) -> Response:
        """
        Make a request with deliberately malformed authentication.

        Variants:
          - "invalid"  : Authorization: Bearer invalid.token.here
          - "empty"    : Authorization: Bearer (empty value)
          - "wrong_scheme": Authorization: Basic dXNlcjpwYXNz
          - "null"     : Authorization: null
        """
        bad_headers = {
            "invalid": {"Authorization": "Bearer invalid.token.here"},
            "empty": {"Authorization": "Bearer "},
            "wrong_scheme": {"Authorization": "Basic dXNlcjpwYXNz"},
            "null": {"Authorization": "null"},
        }
        headers = bad_headers.get(variant, bad_headers["invalid"])
        headers.update(kwargs.pop("headers", {}))
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                timeout=self.TIMEOUT,
                allow_redirects=False,
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException as exc:
            return _ErrorResponse(str(exc))


# ---------------------------------------------------------------------------
# Sentinel response for connection errors
# ---------------------------------------------------------------------------

class _ErrorResponse:
    """Mimics requests.Response enough for check modules to handle gracefully."""

    def __init__(self, error: str) -> None:
        self.status_code = 0
        self.text = f"[Connection error] {error}"
        self.headers = {}
        self._error = error

    def json(self):
        return {}
