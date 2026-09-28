"""
checker/engine/scanner.py

Main scan orchestrator. Runs in a background thread, drives all check modules,
coordinates autonomous lifecycle canary provisioning, differential response analysis,
access control matrix reconstruction, and proof-of-exploit artifact generation.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import queue
import inspect
import concurrent.futures
from pathlib import Path
from datetime import datetime, timezone

# Ensure checker/ root is on sys.path so we can import database.py
_checker_root = str(Path(__file__).parent.parent)
if _checker_root not in sys.path:
    sys.path.insert(0, _checker_root)

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore
from typing import Any

from .discovery import EndpointDiscovery, Endpoint
from .auth_manager import AuthManager
from .scan_depth import ScanDepthConfig
from .diff_analyzer import DiffAnalyzer
from .lifecycle import LifecycleEngine
from .acm_builder import ACMBuilder
from .poe_generator import PoEGenerator
from .check_modules import (
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
)
import database as db

logger = logging.getLogger(__name__)

# Module-level dict of SSE queues keyed by scan_id
_sse_queues: dict[str, queue.Queue] = {}
_sse_lock = threading.Lock()

# Module-level dict of running Scanner instances for cancellation
_active_scanners: dict[str, Any] = {}
_scanners_lock = threading.Lock()


def get_sse_queue(scan_id: str) -> queue.Queue:
    with _sse_lock:
        if scan_id not in _sse_queues:
            _sse_queues[scan_id] = queue.Queue()
        return _sse_queues[scan_id]


def remove_sse_queue(scan_id: str) -> None:
    with _sse_lock:
        _sse_queues.pop(scan_id, None)


def register_active_scanner(scan_id: str, scanner: Any) -> None:
    with _scanners_lock:
        _active_scanners[scan_id] = scanner


def remove_active_scanner(scan_id: str) -> None:
    with _scanners_lock:
        _active_scanners.pop(scan_id, None)


def stop_scan(scan_id: str) -> bool:
    """Signal a running scanner to stop immediately."""
    with _scanners_lock:
        scanner = _active_scanners.get(scan_id)
    if scanner:
        scanner.stop()
        return True
    return False


DEFAULT_MODULES = [
    "HorizontalBOLA",
    "VerticalPrivilege",
    "MissingAuth",
    "MalformedAuth",
    "IDManipulation",
    "MassAssignment",
    "MethodSubstitution",
    "ResponseLeakage",
    "CrossEndpointGraph",
    "QueryParamSubstitution",
]


class Scanner:
    """
    Orchestrates a comprehensive authorization check run.
    Integrates all four pillars: Scan Depth, Differential Analysis,
    Autonomous Lifecycle Canaries, Access Control Matrix, and PoE Generation.
    """

    def __init__(self, scan_id: str, config: dict) -> None:
        self.scan_id = scan_id
        self.config = config
        self.target_url = config["target_url"].rstrip("/")
        self.known_ids: dict[str, dict[str, list[Any]]] = config.get("known_ids", {})
        self.auth_manager = AuthManager(config.get("roles", []))
        self._sse_queue = get_sse_queue(scan_id)
        self._completed = 0
        self._total = 0
        self._stopped = False

        # Pillar 0: Scan Depth Controller
        depth_name = config.get("scan_depth") or "standard"
        self.depth = ScanDepthConfig(depth_name)

        # Pillar 1, 3, 4 engines
        self.diff_analyzer = DiffAnalyzer()
        self.acm_builder = ACMBuilder()
        self.poe_generator = PoEGenerator()
        self.lifecycle: LifecycleEngine | None = None

        # Determine active check modules
        selected = config.get("selected_modules")
        if selected and isinstance(selected, list) and len(selected) > 0:
            self.selected_modules = set(selected)
        else:
            self.selected_modules = set(DEFAULT_MODULES)

    def stop(self) -> None:
        """Flag scanner to cancel execution on the next check cycle."""
        logger.info("Stopping scanner for scan %s", self.scan_id)
        self._stopped = True

    # ------------------------------------------------------------------
    # Public entry point (run in background thread)
    # ------------------------------------------------------------------

    def run(self) -> None:
        register_active_scanner(self.scan_id, self)
        endpoints: list[Endpoint] = []
        try:
            self._emit("status", {"message": f"Starting {self.depth.depth.upper()} scan… Discovering endpoints…"})
            endpoints = self._discover_endpoints()

            if not endpoints:
                self._emit("error", {"message": "No endpoints discovered from spec."})
                db.update_scan(self.scan_id, status="error", completed_at=_now())
                return

            # Pillar 2: Autonomous Entity Lifecycle Engine
            self.lifecycle = LifecycleEngine(self.target_url, self.auth_manager, endpoints, self.depth)
            if self.depth.run_lifecycle:
                self._emit("status", {"message": "Autonomously discovering resource graphs across roles..."})
                auto_ids = self.lifecycle.discover_ids()
                for role, rts in auto_ids.items():
                    if role not in self.known_ids:
                        self.known_ids[role] = {}
                    for rt, ids in rts.items():
                        existing = self.known_ids[role].get(rt, [])
                        combined = list(dict.fromkeys(existing + ids))
                        self.known_ids[role][rt] = combined

                self._emit("status", {"message": "Provisioning canary verification test objects..."})
                canary_map = self.lifecycle.create_canaries()
                for role, rts in canary_map.items():
                    for rt, ids in rts.items():
                        if ids:
                            self.known_ids.setdefault(role, {}).setdefault(rt, []).extend(ids)

            self._emit("status", {
                "message": f"Discovered {len(endpoints)} endpoint(s). Executing {len(self.selected_modules)} test category checks…"
            })

            # Estimate total check count
            self._total = self._estimate_total(endpoints)
            db.update_scan(self.scan_id, total_checks=self._total)
            self._emit("progress", {
                "completed": 0,
                "total": self._total,
                "progress": {"completed": 0, "total": self._total},
                "current_endpoint": endpoints[0].path if endpoints else "",
            })

            self._run_checks(endpoints)

            # Cleanup canary resources
            if self.lifecycle:
                self.lifecycle.cleanup()

            # Pillar 3: Access Control Matrix & Policy Anomaly Construction
            results = db.get_results(self.scan_id)
            summary = _summarise(results)

            acm_data = self.acm_builder.build_matrix(
                results, self.auth_manager.role_names(), endpoints
            )
            policy_score = acm_data.get("policy_score", 100)

            # Check if execution was stopped early by user
            if self._stopped:
                logger.info("Scan %s was stopped by user.", self.scan_id)
                db.update_scan(
                    self.scan_id,
                    status="cancelled",
                    completed_at=_now(),
                    completed_checks=self._completed,
                    acm_json=json.dumps(acm_data),
                    policy_score=policy_score,
                    lifecycle_log=json.dumps(self.lifecycle.lifecycle_log if self.lifecycle else []),
                )
                self._emit("stopped", {
                    "scan_id": self.scan_id,
                    "summary": summary,
                    "policy_score": policy_score,
                    "acm": acm_data,
                    "message": "Scan cancelled by user."
                })
                return

            # Final summary on successful completion
            db.update_scan(
                self.scan_id,
                status="complete",
                completed_at=_now(),
                completed_checks=self._completed,
                acm_json=json.dumps(acm_data),
                policy_score=policy_score,
                lifecycle_log=json.dumps(self.lifecycle.lifecycle_log if self.lifecycle else []),
            )
            self._emit("complete", {
                "scan_id": self.scan_id,
                "summary": summary,
                "policy_score": policy_score,
                "acm": acm_data,
            })

        except Exception as exc:
            logger.exception("Scanner error for scan %s", self.scan_id)
            if self.lifecycle:
                try:
                    self.lifecycle.cleanup()
                except Exception:
                    pass
            db.update_scan(self.scan_id, status="error", completed_at=_now())
            self._emit("error", {"message": str(exc)})
        finally:
            remove_active_scanner(self.scan_id)
            self._sse_queue.put(None)

    # ------------------------------------------------------------------
    # Endpoint discovery
    # ------------------------------------------------------------------

    def _discover_endpoints(self) -> list[Endpoint]:
        discovery = EndpointDiscovery()
        spec_type = self.config.get("spec_type", "manual")
        spec = self.config.get("spec", [])

        if isinstance(spec, str):
            try:
                spec = json.loads(spec)
            except json.JSONDecodeError:
                try:
                    spec = yaml.safe_load(spec)
                except Exception:
                    spec = []

        if spec_type == "openapi":
            return discovery.from_openapi(spec)
        elif spec_type == "postman":
            return discovery.from_postman(spec)
        else:
            return discovery.from_manual(spec if isinstance(spec, list) else [])

    # ------------------------------------------------------------------
    # Check modules runner
    # ------------------------------------------------------------------

    # Max parallel endpoint workers
    _WORKER_THREADS = 6

    def _estimate_total(self, endpoints: list[Endpoint]) -> int:
        multiplier = max(len(self.selected_modules), 1)
        if self.depth.depth == "quick":
            multiplier = min(multiplier, 3)
        return max(len(endpoints) * multiplier, 1)

    def _run_checks(self, endpoints: list[Endpoint]) -> None:
        results_lock = threading.Lock()
        common_kwargs = {
            "depth": self.depth,
            "diff_analyzer": self.diff_analyzer,
            "lifecycle_engine": self.lifecycle,
        }

        def process_endpoint(ep: Endpoint) -> None:
            if self._stopped:
                return

            self._emit("progress", {
                "completed": self._completed,
                "total": self._total,
                "progress": {"completed": self._completed, "total": self._total},
                "current_endpoint": f"{ep.method} {ep.path}",
            })

            self._run_module_locked("MissingAuth", check_missing_auth, ep, results_lock, extra_kwargs=common_kwargs)
            if self._stopped:
                return

            self._run_module_locked("MalformedAuth", check_malformed_auth, ep, results_lock, extra_kwargs=common_kwargs)
            if self._stopped:
                return

            if ep.has_id_param:
                if "HorizontalBOLA" in self.selected_modules:
                    self._run_module_locked("HorizontalBOLA", check_horizontal_bola, ep, results_lock, extra_kwargs=common_kwargs)
                if self._stopped:
                    return

                if "IDManipulation" in self.selected_modules:
                    self._run_module_locked("IDManipulation", check_id_manipulation, ep, results_lock, extra_kwargs=common_kwargs)
                if self._stopped:
                    return

                if "ResponseLeakage" in self.selected_modules:
                    self._run_module_locked("ResponseLeakage", check_response_leakage, ep, results_lock, extra_kwargs=common_kwargs)
                if self._stopped:
                    return

                if "CrossEndpointGraph" in self.selected_modules:
                    self._run_module_locked(
                        "CrossEndpointGraph", check_cross_endpoint_graph, ep, results_lock,
                        extra_kwargs={**common_kwargs, "all_endpoints": endpoints},
                    )
                if self._stopped:
                    return

            if "/admin" in ep.path.lower() or "admin" in [t.lower() for t in ep.tags]:
                if "VerticalPrivilege" in self.selected_modules:
                    self._run_module_locked("VerticalPrivilege", check_vertical_privilege, ep, results_lock, extra_kwargs=common_kwargs)
                if self._stopped:
                    return

            if ep.is_write:
                if "MassAssignment" in self.selected_modules:
                    self._run_module_locked("MassAssignment", check_mass_assignment, ep, results_lock, extra_kwargs=common_kwargs)
                if self._stopped:
                    return

            if "MethodSubstitution" in self.selected_modules:
                self._run_module_locked("MethodSubstitution", check_method_substitution, ep, results_lock, extra_kwargs=common_kwargs)
            if self._stopped:
                return

            if ep.method == "GET":
                if "QueryParamSubstitution" in self.selected_modules:
                    self._run_module_locked("QueryParamSubstitution", check_query_param_substitution, ep, results_lock, extra_kwargs=common_kwargs)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._WORKER_THREADS) as executor:
            futures = {executor.submit(process_endpoint, ep): ep for ep in endpoints}
            for future in concurrent.futures.as_completed(futures):
                if self._stopped:
                    for f in futures:
                        f.cancel()
                    break
                exc = future.exception()
                if exc:
                    ep = futures[future]
                    logger.warning("Endpoint %s %s raised exception: %s", ep.method, ep.path, exc)

        db.update_scan(self.scan_id, total_checks=self._completed)

    def _run_module_locked(
        self,
        module_name: str,
        module_fn,
        endpoint: Endpoint,
        results_lock: threading.Lock,
        extra_kwargs: dict | None = None,
    ) -> None:
        """Run a single module only if selected; persist results under lock."""
        if module_name not in self.selected_modules:
            return
        if self._stopped:
            return
        self._run_module(module_name, module_fn, endpoint, results_lock, extra_kwargs)

    def _run_module(
        self,
        module_name: str,
        module_fn,
        endpoint: Endpoint,
        results_lock: threading.Lock | None = None,
        extra_kwargs: dict | None = None,
    ) -> None:
        if self._stopped:
            return

        kwargs = extra_kwargs or {}
        try:
            sig = inspect.signature(module_fn)
            accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            call_kwargs = kwargs if accepts_var_kw else {k: v for k, v in kwargs.items() if k in sig.parameters}
            check_results = module_fn(
                endpoint,
                self.target_url,
                self.auth_manager,
                self.config,
                self.known_ids,
                **call_kwargs,
            )
        except Exception as exc:
            logger.warning(
                "Module %s failed on %s %s: %s",
                module_name, endpoint.method, endpoint.path, exc,
            )
            check_results = []

        if self._stopped:
            return

        lock = results_lock or threading.Lock()
        with lock:
            for result in check_results:
                # Pillar 4: Generate Proof-of-Exploit reproduction scripts for findings
                if result.get("verdict") == "NEEDS_FIX":
                    if not result.get("poe_curl"):
                        result["poe_curl"] = self.poe_generator.generate_curl(result, self.config)
                    if not result.get("poe_python"):
                        result["poe_python"] = self.poe_generator.generate_python(result, self.config)

                result_id = db.add_result(self.scan_id, result)
                self._completed += 1

                # Emit result for live dashboard feed
                data_item = {
                    **result,
                    "id": result_id,
                    "module": result.get("module_name"),
                }
                if result.get("verdict") in ("NEEDS_FIX", "INCONCLUSIVE"):
                    self._emit("result", {**data_item, "data": data_item})

            db.update_scan(self.scan_id, completed_checks=self._completed)

    # ------------------------------------------------------------------
    # SSE helper
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, payload: dict) -> None:
        event = {"type": event_type, "scan_id": self.scan_id, **payload}
        self._sse_queue.put(json.dumps(event))


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _summarise(results: list[dict]) -> dict:
    summary: dict[str, Any] = {
        "total": len(results),
        "needs_fix": 0,
        "passes": 0,
        "inconclusive": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }
    for r in results:
        v = r.get("verdict", "INCONCLUSIVE")
        if v == "NEEDS_FIX":
            summary["needs_fix"] += 1
        elif v == "PASSES":
            summary["passes"] += 1
        else:
            summary["inconclusive"] += 1
        sev = r.get("severity", "INFO")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
    return summary


def start_scan_thread(scan_id: str, config: dict) -> None:
    """Convenience: create Scanner and start it in a daemon thread."""
    scanner = Scanner(scan_id, config)
    t = threading.Thread(target=scanner.run, daemon=True, name=f"scan-{scan_id[:8]}")
    t.start()
