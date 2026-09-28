"""
checker/engine/discovery.py

Parses API endpoints from three input formats:
  - OpenAPI 3.x / Swagger 2.x (JSON or already-parsed dict)
  - Postman Collection v2.1 (JSON dict)
  - Manual endpoint list (list of dicts)

Returns a list of Endpoint dataclass instances that the scanner uses
to decide which check modules to apply.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_ID_PARAM_PATTERN = re.compile(
    r"(^id$|_id$|Id$|ID$|uuid|key$|ref$|code$|token$|handle$)",
    re.IGNORECASE,
)


@dataclass
class Endpoint:
    path: str
    method: str  # uppercase: GET / POST / PUT / DELETE / PATCH
    path_params: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    body_schema: dict | None = None
    requires_auth: bool = True
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    has_id_param: bool = False  # True if any param looks like an object ID
    is_write: bool = False       # True for POST / PUT / PATCH / DELETE

    def __post_init__(self):
        self.method = self.method.upper()
        self.is_write = self.method in {"POST", "PUT", "PATCH", "DELETE"}
        if not self.has_id_param:
            self.has_id_param = any(
                _is_id_like(p) for p in (self.path_params + self.query_params)
            ) or bool(re.search(r"\{[^}]+\}", self.path))

    def resolved_path(self, **params) -> str:
        """Replace {param} placeholders with concrete values."""
        p = self.path
        for k, v in params.items():
            p = p.replace(f"{{{k}}}", str(v))
        return p

    def extract_path_params_from_template(self) -> list[str]:
        return re.findall(r"\{([^}]+)\}", self.path)


def _is_id_like(name: str) -> bool:
    return bool(_ID_PARAM_PATTERN.search(name))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class EndpointDiscovery:
    """Converts raw spec data into a flat list of Endpoint objects."""

    # ------------------------------------------------------------------
    # OpenAPI 3.x / Swagger 2.x
    # ------------------------------------------------------------------
    def from_openapi(self, spec: dict) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        paths: dict = spec.get("paths", {})

        for path, path_item in paths.items():
            path_params_global = [
                p["name"]
                for p in path_item.get("parameters", [])
                if p.get("in") == "path"
            ]

            for method_lower, operation in path_item.items():
                if method_lower.upper() not in {
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
                }:
                    continue
                if not isinstance(operation, dict):
                    continue

                method = method_lower.upper()
                op_params = operation.get("parameters", [])
                path_params = list(path_params_global)
                query_params: list[str] = []

                for p in op_params:
                    loc = p.get("in", "")
                    name = p.get("name", "")
                    if loc == "path" and name not in path_params:
                        path_params.append(name)
                    elif loc == "query":
                        query_params.append(name)

                # Fall back: extract from path template if spec is thin
                if not path_params:
                    path_params = re.findall(r"\{([^}]+)\}", path)

                # Body schema
                body_schema = None
                req_body = operation.get("requestBody", {})
                for content_type, content in req_body.get("content", {}).items():
                    if "json" in content_type:
                        body_schema = content.get("schema")
                        break

                # Auth requirement: presence of "security" key means auth needed;
                # empty list [] means explicitly public
                security = operation.get(
                    "security",
                    spec.get("security", [{"BearerAuth": []}]),
                )
                requires_auth = bool(security)

                tags = operation.get("tags", [])
                summary = operation.get("summary", "")

                ep = Endpoint(
                    path=path,
                    method=method,
                    path_params=path_params,
                    query_params=query_params,
                    body_schema=body_schema,
                    requires_auth=requires_auth,
                    tags=tags,
                    summary=summary,
                )
                endpoints.append(ep)

        return endpoints

    # ------------------------------------------------------------------
    # Postman Collection v2.1
    # ------------------------------------------------------------------
    def from_postman(self, collection: dict) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        items = collection.get("item", [])
        self._walk_postman_items(items, endpoints, folder_tags=[])
        return endpoints

    def _walk_postman_items(
        self, items: list, endpoints: list[Endpoint], folder_tags: list[str]
    ) -> None:
        for item in items:
            if "item" in item:  # folder — recurse
                tag = item.get("name", "")
                self._walk_postman_items(
                    item["item"], endpoints, folder_tags + ([tag] if tag else [])
                )
            elif "request" in item:
                ep = self._parse_postman_request(item, folder_tags)
                if ep:
                    endpoints.append(ep)

    def _parse_postman_request(
        self, item: dict, tags: list[str]
    ) -> Endpoint | None:
        req = item.get("request", {})
        method = req.get("method", "GET").upper()
        url_data = req.get("url", {})

        if isinstance(url_data, str):
            raw = url_data
            path = "/" + "/".join(
                p for p in raw.split("?")[0].split("/")[3:] if p
            )
            query_params = []
        else:
            path_parts = url_data.get("path", [])
            path = "/" + "/".join(str(p) for p in path_parts)
            # Postman uses :param notation — normalise to {param}
            path = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", path)
            query_params = [
                q["key"]
                for q in url_data.get("query", [])
                if q.get("key")
            ]

        path_params = re.findall(r"\{([^}]+)\}", path)

        # Check for Bearer token in headers
        headers = req.get("header", [])
        has_auth_header = any(
            h.get("key", "").lower() in {"authorization", "x-api-key"}
            for h in headers
        )

        # Body schema: try to extract key names from raw JSON body
        body_schema = None
        body = req.get("body", {})
        if body.get("mode") == "raw":
            try:
                import json
                raw_body = json.loads(body.get("raw", "{}"))
                body_schema = {
                    "type": "object",
                    "properties": {k: {} for k in raw_body.keys()},
                }
            except Exception:
                pass
        elif body.get("mode") == "urlencoded":
            fields = [f["key"] for f in body.get("urlencoded", []) if f.get("key")]
            body_schema = {
                "type": "object",
                "properties": {k: {} for k in fields},
            }

        return Endpoint(
            path=path,
            method=method,
            path_params=path_params,
            query_params=query_params,
            body_schema=body_schema,
            requires_auth=has_auth_header,
            tags=tags,
            summary=item.get("name", ""),
        )

    # ------------------------------------------------------------------
    # Manual list
    # ------------------------------------------------------------------
    def from_manual(self, endpoints: list[dict]) -> list[Endpoint]:
        result: list[Endpoint] = []
        for e in endpoints:
            path = e.get("path", "")
            method = e.get("method", "GET")
            path_params = e.get("path_params") or re.findall(
                r"\{([^}]+)\}", path
            )
            result.append(
                Endpoint(
                    path=path,
                    method=method,
                    path_params=path_params,
                    query_params=e.get("query_params", []),
                    body_schema=e.get("body_schema"),
                    requires_auth=e.get("requires_auth", True),
                    tags=e.get("tags", []),
                    summary=e.get("summary", ""),
                )
            )
        return result
