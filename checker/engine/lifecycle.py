"""
checker/engine/lifecycle.py

Pillar 2: Autonomous Entity Lifecycle Engine.
Autonomously discovers resource graphs, provisions canary test objects with
ground-truth ownership, verifies cross-tenant state mutations, and cleans up after tests.
"""

from __future__ import annotations

import uuid
import logging
from typing import Any

from .discovery import Endpoint
from .auth_manager import AuthManager
from .scan_depth import ScanDepthConfig
from .utils import safe_json, status_ok, build_url

logger = logging.getLogger(__name__)


class LifecycleEngine:
    """
    Manages autonomous discovery of existing resources and provisions
    canary objects for guaranteed ownership testing.
    """

    def __init__(
        self,
        base_url: str,
        auth_manager: AuthManager,
        endpoints: list[Endpoint],
        depth_config: ScanDepthConfig,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_manager = auth_manager
        self.endpoints = endpoints
        self.depth = depth_config
        self.created_canaries: list[dict[str, Any]] = []
        self.lifecycle_log: list[str] = []

    def log(self, message: str) -> None:
        logger.info("[Lifecycle] %s", message)
        self.lifecycle_log.append(message)

    def discover_ids(self) -> dict[str, dict[str, list[Any]]]:
        """
        Phase 1: Discover resources owned by each role by querying list endpoints
        and the /me endpoint.
        Returns: { role_name: { "order": [1, 2], "product": [1, 2], "user": [1] } }
        """
        discovered: dict[str, dict[str, list[Any]]] = {}
        roles = self.auth_manager.role_names()

        for r in roles:
            discovered[r] = {"order": [], "product": [], "user": []}

        # 1. Discover user IDs via /api/auth/me
        me_endpoints = [ep for ep in self.endpoints if "/me" in ep.path.lower()]
        for me_ep in me_endpoints:
            for role in roles:
                url = build_url(self.base_url, me_ep.path)
                resp = self.auth_manager.make_request(me_ep.method, url, role)
                if status_ok(resp.status_code):
                    data = safe_json(resp)
                    if isinstance(data, dict):
                        uid = data.get("id") or data.get("user_id") or data.get("sub")
                        if uid and uid not in discovered[role]["user"]:
                            discovered[role]["user"].append(uid)
                            self.log(f"Discovered user_id {uid} for role '{role}' via {me_ep.path}")

        # 2. Discover list endpoints without path parameters
        list_endpoints = [
            ep for ep in self.endpoints
            if ep.method == "GET" and not ep.has_id_param and "/admin" not in ep.path.lower()
        ]

        for ep in list_endpoints:
            # Infer resource type from path
            rt = None
            path_lower = ep.path.lower()
            if "order" in path_lower:
                rt = "order"
            elif "product" in path_lower:
                rt = "product"
            elif "user" in path_lower:
                rt = "user"

            if not rt:
                continue

            for role in roles:
                url = build_url(self.base_url, ep.path)
                resp = self.auth_manager.make_request("GET", url, role)
                if not status_ok(resp.status_code):
                    continue

                data = safe_json(resp)
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            items = v
                            break

                for item in items:
                    if isinstance(item, dict) and "id" in item:
                        item_id = item["id"]
                        if item_id not in discovered[role][rt]:
                            discovered[role][rt].append(item_id)

                if discovered[role][rt]:
                    self.log(f"Role '{role}' owns {rt} IDs: {discovered[role][rt]} (via {ep.path})")

        return discovered

    def create_canaries(self) -> dict[str, dict[str, list[Any]]]:
        """
        Phase 2: Provision fresh canary objects for testing cross-user authorization.
        Returns canary IDs mapped by role and resource type.
        """
        canary_ids: dict[str, dict[str, list[Any]]] = {}
        roles = self.auth_manager.role_names()
        for r in roles:
            canary_ids[r] = {"order": [], "product": []}

        if not self.depth.run_lifecycle:
            self.log("Skipping canary provisioning due to quick scan depth.")
            return canary_ids

        # Look for POST /api/orders
        order_create_ep = next((ep for ep in self.endpoints if ep.method == "POST" and "/order" in ep.path.lower()), None)
        non_admin_roles = [r for r in roles if "admin" not in r.lower()]

        for role in non_admin_roles[:2]:
            tag = uuid.uuid4().hex[:6]
            if order_create_ep:
                url = build_url(self.base_url, order_create_ep.path)
                payload = {
                    "title": f"CANARY_ORDER_{role}_{tag}",
                    "amount": 19.99,
                    "description": f"Automated canary order for {role}",
                    "shipping_address": "123 Security Lab Way",
                }
                resp = self.auth_manager.make_request("POST", url, role, json=payload)
                if status_ok(resp.status_code):
                    data = safe_json(resp)
                    if isinstance(data, dict) and "id" in data:
                        cid = data["id"]
                        canary_ids[role]["order"].append(cid)
                        self.created_canaries.append({
                            "type": "order",
                            "id": cid,
                            "owner": role,
                            "delete_path": f"/api/orders/{cid}",
                        })
                        self.log(f"Created canary order #{cid} owned by '{role}'")

        return canary_ids

    def verify_mutation(
        self,
        resource_path_template: str,
        resource_id: Any,
        owner_role: str,
        attacker_role: str,
    ) -> bool:
        """
        Phase 4: Verify whether an attacker can execute a state-altering PUT/PATCH mutation,
        and confirm if the modification persisted on the owner's side.
        """
        if not self.depth.run_mutation_verification:
            return False

        path = resource_path_template.replace("{id}", str(resource_id))
        url = build_url(self.base_url, path)

        tampered_title = f"MUTATED_BY_{attacker_role}_{uuid.uuid4().hex[:4]}"
        tamper_payload = {"title": tampered_title, "amount": 999.99}

        # 1. Attacker attempts to mutate
        resp = self.auth_manager.make_request("PUT", url, attacker_role, json=tamper_payload)
        if not status_ok(resp.status_code):
            return False

        # 2. Owner re-fetches to verify if data changed in database
        check_resp = self.auth_manager.make_request("GET", url, owner_role)
        if status_ok(check_resp.status_code):
            data = safe_json(check_resp)
            if isinstance(data, dict):
                current_title = str(data.get("title", ""))
                if tampered_title in current_title:
                    self.log(f"CRITICAL: Mutation verified on {path}! '{attacker_role}' successfully tampered with '{owner_role}' object.")
                    return True
        return False

    def cleanup(self) -> None:
        """
        Phase 5: Safely teardown all canary resources created during the scan.
        """
        if not self.created_canaries:
            return

        self.log(f"Starting teardown of {len(self.created_canaries)} canary objects...")
        for canary in self.created_canaries:
            del_path = canary.get("delete_path")
            owner = canary.get("owner")
            if del_path and owner:
                url = build_url(self.base_url, del_path)
                try:
                    resp = self.auth_manager.make_request("DELETE", url, owner)
                    self.log(f"Deleted canary {canary['type']} #{canary['id']} ({resp.status_code})")
                except Exception as exc:
                    self.log(f"Failed to delete canary {canary['type']} #{canary['id']}: {exc}")
        self.created_canaries.clear()
