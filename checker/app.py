"""
checker/app.py

Flask API server for the BOLA/IDOR authorization checker.
Provides scan management, SSE progress streaming, and report download endpoints.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from io import BytesIO

from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS

from database import init_db, create_scan, get_scan, get_results, get_result, list_scans, delete_scan, update_scan
from engine.scanner import get_sse_queue, remove_sse_queue, start_scan_thread, _summarise, stop_scan, DEFAULT_MODULES
from reporters.json_reporter import generate_json
from reporters.pdf_reporter import generate_pdf
from reporters.docx_reporter import generate_docx

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# ---------------------------------------------------------------------------
# DB init on startup
# ---------------------------------------------------------------------------
with app.app_context():
    init_db()


# ---------------------------------------------------------------------------
# JSON error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(_e):
    return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})


# ---------------------------------------------------------------------------
# Scans — CRUD
# ---------------------------------------------------------------------------

@app.post("/api/scans")
def start_scan():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    target_url = body.get("target_url", "").strip()
    if not target_url:
        return jsonify({"error": "target_url is required"}), 400

    # -----------------------------------------------------------------------
    # Support both the dashboard format and the direct API format
    # Dashboard wraps spec info in a "discovery" key:
    #   { discovery: { mode: "openapi", spec: {...} } }
    # Direct API uses flat keys:
    #   { spec_type: "openapi", spec: {...} }
    # -----------------------------------------------------------------------
    discovery = body.get("discovery", {})
    spec_type = discovery.get("mode") or body.get("spec_type", "manual")
    if spec_type not in ("openapi", "postman", "manual"):
        return jsonify({"error": "spec_type must be openapi, postman, or manual"}), 400

    # Spec content — endpoints list for manual, dict for openapi/postman
    if spec_type == "manual":
        spec = discovery.get("endpoints") or body.get("spec", [])
    else:
        spec = discovery.get("spec") or body.get("spec", {})

    # -----------------------------------------------------------------------
    # Roles — dashboard uses auth_type/auth_value; direct API uses type/value
    # -----------------------------------------------------------------------
    raw_roles = body.get("roles", [])
    if not raw_roles:
        return jsonify({"error": "At least one role is required"}), 400

    roles = []
    for r in raw_roles:
        roles.append({
            "name": r.get("name", ""),
            "type": r.get("type") or r.get("auth_type", "bearer"),
            "value": r.get("value") or r.get("auth_value", ""),
        })

    # -----------------------------------------------------------------------
    # Known IDs — dashboard stores per-role as resources.user_ids etc.;
    # direct API sends known_ids: { role_name: { user: [1], order: [1,2] } }
    # -----------------------------------------------------------------------
    known_ids = body.get("known_ids", {})
    if not known_ids:
        # Build from per-role resources if present (dashboard format)
        for r in body.get("roles", []):
            res = r.get("resources", {})
            role_name = r.get("name", "")
            if res and role_name:
                def _parse_ids(val):
                    if isinstance(val, list):
                        return [int(x) for x in val if str(x).strip().isdigit()]
                    if isinstance(val, str):
                        return [int(x.strip()) for x in val.split(",") if x.strip().isdigit()]
                    return []
                known_ids[role_name] = {
                    "user":    _parse_ids(res.get("user_ids", [])),
                    "order":   _parse_ids(res.get("order_ids", [])),
                    "product": _parse_ids(res.get("product_ids", [])),
                }

    # -----------------------------------------------------------------------
    # Selected check modules (separate test categories)
    # -----------------------------------------------------------------------
    # -----------------------------------------------------------------------
    # Scan Depth (Quick, Standard, Deep)
    # -----------------------------------------------------------------------
    scan_depth = body.get("scan_depth") or body.get("depth") or "standard"
    if scan_depth not in ("quick", "standard", "deep"):
        scan_depth = "standard"

    selected_modules = body.get("selected_modules")
    if not selected_modules and "discovery" in body:
        selected_modules = body.get("discovery", {}).get("selected_modules")
    if not selected_modules or not isinstance(selected_modules, list):
        selected_modules = list(DEFAULT_MODULES)

    config = {
        "target_url": target_url,
        "spec_type": spec_type,
        "spec": spec,
        "roles": roles,
        "known_ids": known_ids,
        "selected_modules": selected_modules,
        "scan_depth": scan_depth,
    }

    scan_id = create_scan(target_url, spec_type, config)
    start_scan_thread(scan_id, config)

    return jsonify({"scan_id": scan_id, "status": "running", "scan_depth": scan_depth}), 202


@app.get("/api/scans")
def get_scans():
    scans = list_scans()
    return jsonify(scans)


@app.get("/api/scans/<scan_id>")
def get_scan_detail(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    results = get_results(scan_id)
    summary = _summarise(results)
    scan_dict = dict(scan)

    # Safely parse JSON blobs
    acm_data = None
    if scan_dict.get("acm_json"):
        try:
            acm_data = json.loads(scan_dict["acm_json"])
        except Exception:
            acm_data = None

    lifecycle_log = []
    if scan_dict.get("lifecycle_log"):
        try:
            lifecycle_log = json.loads(scan_dict["lifecycle_log"])
        except Exception:
            lifecycle_log = []

    return jsonify({
        **scan_dict,
        "scan": scan_dict,
        "summary": summary,
        "results": results,
        "acm": acm_data,
        "policy_score": scan_dict.get("policy_score"),
        "lifecycle_log": lifecycle_log,
        "scan_depth": scan_dict.get("scan_depth", "standard"),
    })


@app.get("/api/scans/<scan_id>/acm")
def get_scan_acm(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    acm_data = None
    if scan.get("acm_json"):
        try:
            acm_data = json.loads(scan["acm_json"])
        except Exception:
            acm_data = None
    return jsonify({
        "scan_id": scan_id,
        "acm": acm_data,
        "policy_score": scan.get("policy_score", 100),
    })


@app.get("/api/scans/<scan_id>/results/<result_id>/poe")
def get_result_poe(scan_id: str, result_id: str):
    result = get_result(result_id)
    if not result:
        return jsonify({"error": "Result not found"}), 404
    return jsonify({
        "result_id": result_id,
        "scan_id": scan_id,
        "poe_curl": result.get("poe_curl", ""),
        "poe_python": result.get("poe_python", ""),
        "evidence_diff": result.get("evidence_diff", ""),
        "similarity_score": result.get("similarity_score"),
        "sensitive_fields": result.get("sensitive_fields"),
    })


@app.get("/api/scans/<scan_id>/policy-score")
def get_policy_score_route(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    acm_data = None
    if scan.get("acm_json"):
        try:
            acm_data = json.loads(scan["acm_json"])
        except Exception:
            acm_data = None
    return jsonify({
        "scan_id": scan_id,
        "policy_score": scan.get("policy_score", 100),
        "anomalies": (acm_data or {}).get("anomalies", []),
    })


@app.post("/api/scans/<scan_id>/stop")
@app.post("/api/scans/<scan_id>/cancel")
def stop_scan_route(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    stopped = stop_scan(scan_id)
    # Mark as cancelled in database
    update_scan(scan_id, status="cancelled", completed_at=datetime.now(timezone.utc).isoformat())
    return jsonify({"scan_id": scan_id, "status": "cancelled", "stopped": stopped})


@app.delete("/api/scans/<scan_id>")
def delete_scan_route(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    # Ensure any running scan is stopped first
    stop_scan(scan_id)
    delete_scan(scan_id)
    remove_sse_queue(scan_id)
    return jsonify({"deleted": scan_id})


# ---------------------------------------------------------------------------
# SSE progress stream
# ---------------------------------------------------------------------------

@app.get("/api/scans/<scan_id>/stream")
def scan_stream(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    q = get_sse_queue(scan_id)

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=600)  # 10-minute max wait
                except Exception:
                    break
                if event is None:  # sentinel — scan finished
                    yield "data: {\"type\": \"done\"}\n\n"
                    break
                yield f"data: {event}\n\n"
        except GeneratorExit:
            pass

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/api/scans/<scan_id>/report")
def download_report(scan_id: str):
    fmt = request.args.get("format", "pdf").lower()
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    results = get_results(scan_id)
    scan_dict = dict(scan)

    if fmt == "json":
        json_str = generate_json(scan_dict, results)
        return Response(
            json_str,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.json"},
        )
    elif fmt == "docx":
        docx_bytes = generate_docx(scan_dict, results)
        return Response(
            docx_bytes,
            mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.docx"},
        )
    else:  # pdf (default)
        pdf_bytes = generate_pdf(scan_dict, results)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}.pdf"},
        )


@app.get("/api/scans/<scan_id>/export")
def export_json(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    results = get_results(scan_id)
    json_str = generate_json(dict(scan), results)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}_export.json"},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
