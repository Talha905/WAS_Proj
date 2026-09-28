# How the Authorization Checker Works — Complete Flow

This document walks through the **full end-to-end flow** of the BOLA/IDOR Authorization Checker — from the moment you press "Start Scan" in the dashboard to the final PDF report landing in your browser.

---

## High-Level Overview

```
User fills form          Checker API         Background Thread          Demo App
in Dashboard       →    receives config  →   runs 10 modules       →   HTTP requests
    ↓                        ↓                      ↓                       ↓
Start Scan            Creates scan in         Streams results         Returns 200/403/404
                         SQLite              via SSE → Dashboard
                                                    ↓
                                             Stores each result
                                               in SQLite DB
                                                    ↓
                                         User clicks Download →
                                         PDF / DOCX / JSON report
```

---

## Phase 1 — Configuration (Dashboard → Checker API)

### 1.1 What the user provides in `ScanConfig.jsx`

| Field | Purpose |
|---|---|
| **Target Base URL** | e.g. `http://localhost:5001` — the app being checked |
| **Spec Type** | `openapi` / `postman` / `manual` — how endpoints are discovered |
| **Spec file / list** | The actual OpenAPI JSON, Postman collection, or manual endpoint list |
| **Roles** | 2–N named auth profiles (each has a name, type, and credential value) |
| **Known IDs** | Per-role lists of resource IDs the user owns — used to set up cross-user tests |

**Example roles config:**
```json
[
  { "name": "user_a", "type": "bearer", "value": "eyJhbGciOiJIUzI1NiJ9..." },
  { "name": "user_b", "type": "bearer", "value": "eyJhbGciOiJIUzI1NiJ9..." },
  { "name": "admin",  "type": "bearer", "value": "eyJhbGciOiJIUzI1NiJ9..." }
]
```

**Example known_ids config:**
```json
{
  "user_a": { "user": [1], "order": [1, 2], "product": [1, 2] },
  "user_b": { "user": [2], "order": [3, 4], "product": [3, 4] }
}
```

### 1.2 Dashboard sends `POST /api/scans` to the checker

```
POST http://localhost:5000/api/scans
Content-Type: application/json

{
  "target_url": "http://localhost:5001",
  "spec_type": "openapi",
  "spec": { ...parsed openapi.yaml contents... },
  "roles": [...],
  "known_ids": {...}
}
```

**Checker responds immediately:**
```json
{ "scan_id": "a3f2c1d4-...", "status": "running" }
```

The scan is now in the database with `status = running`. The background thread has started.
The dashboard navigates to `/scans/a3f2c1d4-...` and opens an SSE connection.

---

## Phase 2 — Endpoint Discovery (`engine/discovery.py`)

The scanner's first job is to turn the raw spec into a flat list of typed `Endpoint` objects.

### 2.1 OpenAPI path

```
openapi.yaml (paths section)
        │
        ▼
  For each path (e.g. /api/orders/{id})
    For each HTTP method (GET, PUT, DELETE…)
      Extract:
        - path_params  →  ["id"]          (from {id} in path template)
        - query_params →  ["user_id"]     (from spec parameters)
        - body_schema  →  {type: object, properties: {...}}
        - requires_auth → True / False    (from security field)
        - tags          →  ["orders"]
        │
        ▼
  Endpoint(
    path="/api/orders/{id}",
    method="GET",
    path_params=["id"],
    has_id_param=True,    ← True because "id" matches ID heuristic
    is_write=False,
    requires_auth=True
  )
```

### 2.2 ID detection heuristic

A parameter is flagged as an object identifier (`has_id_param = True`) if its name contains:
`id`, `Id`, `ID`, `uuid`, `key`, `ref`, `code`, `token`, `handle` — or if the path template contains any `{...}` placeholder.

### 2.3 Result

For the `before-fix` demo app's `openapi.yaml`, discovery produces ~14 `Endpoint` objects:

```
GET    /api/auth/me
POST   /api/auth/login
POST   /api/auth/register
GET    /api/users/{id}       ← has_id_param=True
PUT    /api/users/{id}       ← has_id_param=True, is_write=True
GET    /api/orders           ← has query_param user_id
POST   /api/orders           ← is_write=True
GET    /api/orders/{id}      ← has_id_param=True
PUT    /api/orders/{id}      ← has_id_param=True, is_write=True
DELETE /api/orders/{id}      ← has_id_param=True, is_write=True
GET    /api/products/{id}    ← has_id_param=True
PUT    /api/products/{id}    ← has_id_param=True, is_write=True
DELETE /api/products/{id}    ← has_id_param=True, is_write=True
GET    /api/admin/users      ← tags=["admin"]
GET    /api/admin/reports    ← tags=["admin"]
```

---

## Phase 3 — Authentication Setup (`engine/auth_manager.py`)

`AuthManager` is initialised once with the roles config and holds one `requests.Session` per role.

```
Role "user_a"  →  Authorization: Bearer eyJhbGci...alice_token
Role "user_b"  →  Authorization: Bearer eyJhbGci...bob_token
Role "admin"   →  Authorization: Bearer eyJhbGci...admin_token
```

For each HTTP request the scanner needs to make, `AuthManager` provides three variants:

| Method | What it sends | Used by module |
|---|---|---|
| `make_request(role)` | Full valid credentials | HorizontalBOLA, VerticalPrivilege, etc. |
| `make_request_no_auth()` | No headers at all | MissingAuth |
| `make_request_malformed_auth(variant)` | Bad token variants | MalformedAuth |

---

## Phase 4 — Scanner Loop (`engine/scanner.py`)

The background thread iterates over every discovered endpoint and decides which modules to run:

```
for each Endpoint:
    ┌─────────────────────────────────────────────────────┐
    │  ALWAYS run:                                        │
    │    • MissingAuth       (requires_auth endpoints)    │
    │    • MalformedAuth     (requires_auth endpoints)    │
    │    • MethodSubstitution (all endpoints)             │
    ├─────────────────────────────────────────────────────┤
    │  IF has_id_param:                                   │
    │    • HorizontalBOLA                                 │
    │    • IDManipulation                                 │
    │    • ResponseLeakage                                │
    │    • CrossEndpointGraph                             │
    ├─────────────────────────────────────────────────────┤
    │  IF path contains "/admin" OR tags has "admin":     │
    │    • VerticalPrivilege                              │
    ├─────────────────────────────────────────────────────┤
    │  IF method in POST / PUT / PATCH:                   │
    │    • MassAssignment                                 │
    ├─────────────────────────────────────────────────────┤
    │  IF method == GET:                                  │
    │    • QueryParamSubstitution                         │
    └─────────────────────────────────────────────────────┘

    After each module:
      → Introspect module signature with `inspect.signature` to dynamically pass accepted kwargs (`depth`, `diff_analyzer`, `lifecycle_engine`)
      → Save results to SQLite
      → Emit SSE event (if verdict is NEEDS_FIX or INCONCLUSIVE)
      → Update completed_checks counter in DB
```

---

## Phase 5 — The 10 Check Modules (`engine/check_modules.py`)

Each module returns a list of `CheckResult` dicts. Here is exactly what each one does:

---

### Module 1 · HorizontalBOLA

**Question:** Can User A read/modify User B's resources?

```
For every pair (owner_role, accessor_role) where owner ≠ accessor:
  For every resource type in known_ids:
    obj_id = known_ids[owner_role]["order"][0]   # e.g. order ID 1 (owned by alice)

    GET http://localhost:5001/api/orders/1
    Authorization: Bearer <bob's token>           # ← accessor is bob

    Response 200  →  NEEDS_FIX (HIGH)   ← bob can see alice's order!
    Response 403  →  PASSES
    Response 404  →  PASSES
```

**On a vulnerable app:** Bob gets a 200 with Alice's order data → `NEEDS_FIX`.

---

### Module 2 · VerticalPrivilege

**Question:** Can a regular user reach admin-only endpoints?

```
For each non-admin role (user_a, user_b):
  GET http://localhost:5001/api/admin/users
  Authorization: Bearer <user_a's token>

  Response 200  →  NEEDS_FIX (HIGH)   ← regular user got the user list!
  Response 403  →  PASSES
  Response 404  →  PASSES
```

---

### Module 3 · MissingAuth

**Question:** Do protected endpoints reject requests with no credentials at all?

```
GET http://localhost:5001/api/orders/1
(no Authorization header)

Response 200  →  NEEDS_FIX (HIGH)   ← unauthenticated access!
Response 401  →  PASSES             ← correct
```

---

### Module 4 · MalformedAuth

**Question:** Does the app reject malformed/invalid tokens (4 variants)?

```
Variant 1 "invalid":       Authorization: Bearer invalid.token.here
Variant 2 "empty":         Authorization: Bearer
Variant 3 "wrong_scheme":  Authorization: Basic dXNlcjpwYXNz
Variant 4 "null":          Authorization: null

Each sent to GET /api/orders/1

Any 200 response  →  NEEDS_FIX (MEDIUM)
401 / 403         →  PASSES
```

---

### Module 5 · IDManipulation

**Question:** What happens with boundary, negative, and fuzzed IDs?

```
For each role, try these IDs in path:

Static fuzz set:
  0, -1, 99999, 999999999,
  "null", "undefined", "admin", "me", "self",
  "../1", "%00", "' OR 1=1--"

Adjacent to owned IDs (e.g. alice owns order 1):
  0, 2, 11, -9   (±1, ±10 of each owned ID)

GET http://localhost:5001/api/orders/0   with alice's token
GET http://localhost:5001/api/orders/-1  with alice's token
... etc.

Response 200 + returned user_id ≠ alice's user_id  →  NEEDS_FIX (HIGH)
Response 500  →  INCONCLUSIVE (server error = info disclosure risk)
Response 404  →  expected (good)
```

---

### Module 6 · MassAssignment

**Question:** Does the API accept privilege-escalating fields in the request body?

```
Normal POST /api/orders body:
  { "title": "Test", "amount": 1.0 }

Injected variants (sent one at a time):
  { "title": "Test", "amount": 1.0, "role": "admin" }
  { "title": "Test", "amount": 1.0, "is_admin": true }
  { "title": "Test", "amount": 1.0, "user_id": 2 }
  { "title": "Test", "amount": 1.0, "is_superuser": true }
  { "title": "Test", "amount": 1.0, "privilege": "admin" }

If response body reflects injected field at the injected value:
  e.g. response: { "id": 5, "user_id": 2, "role": "admin" }
  →  NEEDS_FIX (HIGH)

If response 400/422 (field rejected):
  →  PASSES
```

---

### Module 7 · MethodSubstitution

**Question:** Do alternate HTTP verbs on the same path unexpectedly succeed?

```
Defined endpoint: GET /api/orders/{id}

Try with each role:
  POST   /api/orders/1  →  expected 405 Method Not Allowed
  PUT    /api/orders/1  →  expected 405 or 403
  DELETE /api/orders/1  →  expected 405 or 403
  HEAD   /api/orders/1  →  expected 405
  PATCH  /api/orders/1  →  expected 405

Any unexpected 200/201  →  NEEDS_FIX (LOW)
405 returned            →  PASSES
```

---

### Module 8 · ResponseLeakage

**Question:** Do error/denial responses leak sensitive information?

```
Make a cross-user request that SHOULD be denied:
  GET /api/orders/1 with bob's token  (alice's order)

If response is 403/404, inspect body for:
  ✗ "Traceback (most recent call last)"  → stack trace
  ✗ "/home/user/app/"                    → internal path
  ✗ "sqlite3.OperationalError"          → DB error
  ✗ alice's user_id "1" in response body → data leakage

Any found  →  NEEDS_FIX (MEDIUM)
Clean body →  PASSES
```

---

### Module 9 · CrossEndpointGraph

**Question:** Can IDs discovered from one endpoint be used to probe a different endpoint?

```
Step 1: Make a legitimate GET request as alice:
  GET /api/orders  →  response: [{"id": 1, ...}, {"id": 2, ...}]
  Collect IDs: [1, 2]

Step 2: Use those IDs on a DIFFERENT endpoint, as bob:
  GET /api/products/1  with bob's token
  GET /api/users/1     with bob's token

Response 200  →  NEEDS_FIX (HIGH)   ← ID from orders graph reaches users graph!
Response 403  →  PASSES
```

---

### Module 10 · QueryParamSubstitution

**Question:** Does the app use `?user_id=` query params instead of JWT identity?

```
Test 1 — user_id override:
  GET /api/orders?user_id=2   with alice's token
  (alice is user 1, but param says 2 = bob)

  Response contains bob's orders  →  NEEDS_FIX (HIGH)

Test 2 — privilege-escalation params:
  GET /api/orders?admin=true   →  INCONCLUSIVE (manual verify)
  GET /api/orders?debug=1      →  INCONCLUSIVE
  GET /api/orders?superuser=1  →  INCONCLUSIVE
```

---

## Phase 6 — Result Storage + SSE Streaming

After each module call, results flow in two directions simultaneously:

```
CheckResult dict
      │
      ├──▶  database.add_result(scan_id, result)
      │         SQLite INSERT into results table
      │         Fields: endpoint, method, module_name, payload,
      │                 expected_status, actual_status, response_snippet,
      │                 verdict, severity, evidence_diff, remediation
      │
      └──▶  sse_queue.put(json.dumps(event))
                │
                ▼
          SSE stream  →  Dashboard EventSource
                │
                ▼
          LiveScan.jsx receives event:
            type="progress"  →  update progress bar
            type="result"    →  append to live results list
            type="complete"  →  show summary + download links
```

### SSE event shapes

```json
// Progress update
{ "type": "progress", "scan_id": "a3f2...", "completed": 14, "total": 80,
  "current_endpoint": "GET /api/orders/{id}" }

// Individual result (NEEDS_FIX or INCONCLUSIVE only, to keep stream light)
{ "type": "result", "endpoint": "/api/orders/{id}", "method": "GET",
  "module_name": "HorizontalBOLA", "verdict": "NEEDS_FIX",
  "severity": "HIGH", "actual_status": 200 }

// Scan finished
{ "type": "complete", "scan_id": "a3f2...",
  "summary": { "needs_fix": 12, "passes": 55, "inconclusive": 6 } }
```

---

## Phase 7 — Verdict Logic

Every check result is scored with one of three verdicts:

| Verdict | Meaning | HTTP status range that triggers it |
|---|---|---|
| **NEEDS_FIX** | Access that should be denied was granted | 200–299 when 403/404 expected |
| **PASSES** | Access correctly denied / behavior correct | 401, 403, 404, 405 as expected |
| **INCONCLUSIVE** | Network error, unexpected code, or ambiguous response | 500, 0 (connection error), unexpected 3xx |

Severity is set per-module:
```
HorizontalBOLA     → HIGH
VerticalPrivilege  → HIGH
MissingAuth        → HIGH
MassAssignment     → HIGH (role change) / MEDIUM (user_id reassignment)
CrossEndpointGraph → HIGH
QueryParamSubstitution → HIGH (user_id) / LOW (debug flags)
MalformedAuth      → MEDIUM
IDManipulation     → MEDIUM / HIGH (cross-user resource)
ResponseLeakage    → MEDIUM (data) / LOW (path disclosure)
MethodSubstitution → LOW
```

---

## Phase 8 — Report Generation

Triggered when user clicks "Download" in the dashboard:

```
GET /api/scans/{scan_id}/report?format=pdf
GET /api/scans/{scan_id}/report?format=docx
GET /api/scans/{scan_id}/export          (JSON)
```

### What each report contains

```
┌────────────────────────────────────────────┐
│             PDF / DOCX Report              │
├────────────────────────────────────────────┤
│  1. Title Page                             │
│     Target URL, scan ID, date, tool name   │
│                                            │
│  2. Executive Summary                      │
│     Table: NEEDS_FIX / PASSES / INCONC.    │
│     Table: findings by severity            │
│                                            │
│  3. Methodology                            │
│     One-line description of each module    │
│                                            │
│  4. Findings Overview                      │
│     Table: all NEEDS_FIX results           │
│     Columns: #, severity, endpoint,        │
│              method, module, actual status │
│                                            │
│  5. Detailed Findings (one section each)  │
│     - Endpoint + method + severity         │
│     - Expected vs actual status code       │
│     - Request payload sent                 │
│     - Response body snippet                │
│     - Evidence diff (what changed)         │
│     - Remediation guidance                 │
│                                            │
│  6. Appendix — Passing Checks              │
│     Summary table of PASSES results        │
└────────────────────────────────────────────┘
```

### JSON export structure

```json
{
  "scan": { "id", "target_url", "started_at", "completed_at", ... },
  "summary": {
    "total_checks": 73,
    "needs_fix": 12,
    "passes": 55,
    "inconclusive": 6,
    "by_severity": { "HIGH": 8, "MEDIUM": 3, "LOW": 1, "INFO": 0 },
    "by_endpoint": { "/api/orders/{id}": { "NEEDS_FIX": 4, "PASSES": 2 } }
  },
  "findings": [ ...NEEDS_FIX results... ],
  "passes":   [ ...PASSES results... ],
  "inconclusive": [ ...INCONCLUSIVE results... ]
}
```

---

## Phase 9 — Before-Fix vs After-Fix Comparison

Running the same scan config against both demo apps produces contrasting results:

### Against `before-fix/` (port 5001)

```
HorizontalBOLA    GET  /api/users/{id}       →  NEEDS_FIX  HIGH
HorizontalBOLA    GET  /api/orders/{id}      →  NEEDS_FIX  HIGH
HorizontalBOLA    PUT  /api/orders/{id}      →  NEEDS_FIX  HIGH
HorizontalBOLA    DELETE /api/orders/{id}    →  NEEDS_FIX  HIGH
VerticalPrivilege GET  /api/admin/users      →  NEEDS_FIX  HIGH
VerticalPrivilege GET  /api/admin/reports    →  NEEDS_FIX  HIGH
MassAssignment    POST /api/orders           →  NEEDS_FIX  HIGH (user_id honored)
QueryParamSubstitution GET /api/orders       →  NEEDS_FIX  HIGH (?user_id= honored)
... (plus IDManipulation, CrossEndpointGraph, MalformedAuth findings)
```

### Against `after-fix/` (port 5002)

```
HorizontalBOLA    GET  /api/users/{id}       →  PASSES   (404 returned)
HorizontalBOLA    GET  /api/orders/{id}      →  PASSES   (404 returned)
VerticalPrivilege GET  /api/admin/users      →  PASSES   (@require_admin returns 404)
MassAssignment    POST /api/orders           →  PASSES   (user_id from body ignored)
QueryParamSubstitution GET /api/orders       →  PASSES   (?user_id= ignored)
```

---

## Complete Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ DASHBOARD (React, port 3000)                                                 │
│                                                                              │
│  ScanConfig.jsx                                                              │
│    Fill: target_url, spec, roles, known_ids                                  │
│    Click "Start Scan"  ──────────────────────────────────────────────────┐  │
│                                                                          │  │
│  LiveScan.jsx                                                            │  │
│    new EventSource("/api/scans/{id}/stream")  ◄──────────────────────┐  │  │
│    On "progress" event → update progress bar                          │  │  │
│    On "result" event   → append to live results list                  │  │  │
│    On "complete" event → show summary cards + download buttons        │  │  │
└───────────────────────────────────────────────────────────────────────┼──┼──┘
                                                                        │  │
                POST /api/scans  ◄──────────────────────────────────────┘  │
                                                                            │
┌──────────────────────────────────────────────────────────────────────────────┐
│ CHECKER ENGINE (Flask, port 5000)                                            │
│                                                                              │
│  app.py                                                                      │
│    create_scan(target_url, spec_source, config) → scan_id                    │
│    start_scan_thread(scan_id, config)           → daemon thread started      │
│    return { scan_id, status: "running" }                                     │
│                                                                              │
│    GET /api/scans/{id}/stream ────────────────────────────────────────────► │
│      reads from sse_queues[scan_id]  (queue.Queue)                           │
│      yields "data: {...}\n\n"                                                │
│                                                                              │
│  ┌── Background Thread ───────────────────────────────────────────────────┐ │
│  │                                                                         │ │
│  │  Scanner.run()                                                          │ │
│  │    │                                                                    │ │
│  │    ▼                                                                    │ │
│  │  discovery.py                                                           │ │
│  │    from_openapi(spec) → [Endpoint, Endpoint, ...]                       │ │
│  │    │                                                                    │ │
│  │    ▼                                                                    │ │
│  │  for each Endpoint:                                                     │ │
│  │    auth_manager.make_request(method, url, role_name)  ──────────────►  │ │
│  │    check_modules.check_*(endpoint, base_url, auth_mgr, known_ids)       │ │
│  │    │                                                                    │ │
│  │    ├──► database.add_result(scan_id, result)  (SQLite INSERT)           │ │
│  │    └──► sse_queue.put(json.dumps(event))      (SSE broadcast)           │ │
│  │                                                                         │ │
│  │  Scanner emits "complete" sentinel → sse_queue.put(None)               │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  GET /api/scans/{id}/report?format=pdf                                       │
│    database.get_results(scan_id) → results list                              │
│    pdf_reporter.generate_pdf(scan, results) → bytes                          │
│    return PDF file download                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
                        │ HTTP requests with auth headers
                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ DEMO APP (Flask, port 5001 or 5002)                                          │
│                                                                              │
│  before-fix/                          after-fix/                            │
│  GET /api/orders/{id}                 GET /api/orders/{id}                  │
│    @jwt_required()          vs          @jwt_required()                     │
│    # no ownership check                 if order.user_id != user_id:       │
│    return order, 200  ← 🔴               return 404  ← ✅                 │
│                                                                              │
│  GET /api/admin/users                 GET /api/admin/users                  │
│    @jwt_required()          vs          @require_admin                      │
│    return all_users, 200 ← 🔴           checks role == "admin"             │
│                                         else return 404  ← ✅              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## SQLite Schema

Two tables persist all state, enhanced with the Four Analytical Pillars:

```sql
-- One row per scan run
CREATE TABLE scans (
    id               TEXT PRIMARY KEY,   -- UUID
    target_url       TEXT NOT NULL,
    spec_source      TEXT NOT NULL,       -- openapi / postman / manual
    config_json      TEXT NOT NULL,       -- full config as JSON string
    status           TEXT NOT NULL DEFAULT 'pending',
    started_at       TEXT,
    completed_at     TEXT,
    total_checks     INTEGER DEFAULT 0,
    completed_checks INTEGER DEFAULT 0,
    scan_depth       TEXT DEFAULT 'standard',  -- quick / standard / deep
    acm_json         TEXT,               -- Reconstructed Access Control Matrix (JSON)
    policy_score     INTEGER,            -- Authorization Health Score (0-100)
    lifecycle_log    TEXT                -- Chronological canary provisioning log
);

-- One row per check result (many per scan)
CREATE TABLE results (
    id                    TEXT PRIMARY KEY,  -- UUID
    scan_id               TEXT NOT NULL,     -- FK → scans.id
    endpoint              TEXT NOT NULL,     -- e.g. /api/orders/{id}
    method                TEXT NOT NULL,     -- GET / POST / etc.
    module_name           TEXT NOT NULL,     -- HorizontalBOLA / etc.
    payload_json          TEXT,              -- request payload sent
    expected_status       INTEGER,
    actual_status         INTEGER,
    response_snippet      TEXT,              -- first 4000 chars of response
    response_headers_json TEXT,
    verdict               TEXT NOT NULL,     -- NEEDS_FIX / PASSES / INCONCLUSIVE
    severity              TEXT NOT NULL,     -- CRITICAL / HIGH / MEDIUM / LOW / INFO
    evidence_diff         TEXT,              -- what changed vs expected
    remediation           TEXT,              -- how to fix
    created_at            TEXT,
    similarity_score      REAL,              -- Normalized Jaccard similarity (0.0 - 1.0)
    baseline_snippet      TEXT,              -- Authorized owner response snippet
    sensitive_fields      TEXT,              -- Leaked PII / confidential attributes (JSON)
    poe_curl              TEXT,              -- Reproducible cURL terminal command
    poe_python            TEXT,              -- Standalone Python verification script
    is_canary             INTEGER DEFAULT 0, -- Provisioned canary indicator
    mutation_verified     INTEGER            -- Verified state tampering indicator (1/0)
);
```

---

## Quick Reference — File Roles

| File | What it does |
|---|---|
| `dashboard/src/components/ScanConfig.jsx` | Form to configure scan, target, depth (quick/standard/deep), and presets |
| `dashboard/src/components/LiveScan.jsx` | Consumes SSE stream, shows live progress and lifecycle phases |
| `dashboard/src/components/ResultsTable.jsx` | Filterable table with similarity and PoE indicators |
| `dashboard/src/components/AccessControlMatrix.jsx` | Interactive Role × Endpoint heatmap and policy anomaly inspector |
| `dashboard/src/components/PolicyScore.jsx` | Circular authorization health gauge (Grade A–F, 0–100 score) |
| `dashboard/src/components/EndpointDetail.jsx` | Detailed result inspector with tabbed cURL/Python PoE reproduction viewer |
| `dashboard/src/components/SummaryCharts.jsx` | Recharts visualizations (verdicts, severities, vulnerable endpoints) |
| `dashboard/src/api.js` | Axios client + API endpoints (`getACM`, `getPoE`, `getPolicyScore`) |
| `checker/app.py` | Flask routes: POST /api/scans, SSE stream, ACM/PoE routes, report download |
| `checker/database.py` | SQLite helpers with automatic schema migrations |
| `checker/engine/scan_depth.py` | Scan depth controller dataclass (`quick`, `standard`, `deep`) |
| `checker/engine/diff_analyzer.py` | Normalized JSON tree differentiator, Jaccard similarity, and PII extractor |
| `checker/engine/lifecycle.py` | Autonomous entity discovery, canary provisioning, mutation verification |
| `checker/engine/acm_builder.py` | Access Control Matrix reconstruction, anomaly detection, policy scoring |
| `checker/engine/poe_generator.py` | Generates reproducible cURL commands and Python regression test scripts |
| `checker/engine/discovery.py` | Converts OpenAPI/Postman/manual → Endpoint objects |
| `checker/engine/auth_manager.py` | Builds auth headers/cookies per role |
| `checker/engine/check_modules.py` | The 10 individual authorization checks (enhanced with differential analysis) |
| `checker/engine/scanner.py` | Concurrent multi-threaded scan orchestrator + SSE event publisher |
| `checker/engine/utils.py` | Diff, dynamic fields, status code, URL building helpers |
| `checker/reporters/pdf_reporter.py` | ReportLab PDF generation |
| `checker/reporters/docx_reporter.py` | python-docx Word generation |
| `checker/reporters/json_reporter.py` | Structured JSON export |
| `demo-apps/before-fix/` | "ShopLite" marketplace with intentional BOLA/BFLA/Mass Assignment gaps |
| `demo-apps/after-fix/` | "ShopLite" secure marketplace with full ownership checks & RBAC |
