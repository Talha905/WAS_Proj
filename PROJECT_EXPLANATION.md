# 🛡️ WAS Mini: Intelligent Multi-Tenant Authorization & BOLA Analysis Engine
## Project Technical Specification & Academic Architecture Documentation

---

## 1. Executive Summary

**WAS Mini** is an automated, multi-tenant authorization security assessment platform designed specifically to detect, analyze, model, and reproduce **Broken Object-Level Authorization (BOLA / IDOR)** and **Broken Function-Level Authorization (BFLA)** flaws in modern RESTful APIs.

Authorization flaws represent the **#1 vulnerability in the OWASP API Security Top 10 (API1:2023)**. Unlike injection flaws (such as SQLi or XSS), which exhibit identifiable syntax anomalies and can be flagged by traditional signature-based web application firewalls (WAFs) or conventional Dynamic Application Security Testing (DAST) scanners, authorization vulnerabilities are **pure business logic flaws**. Standard automated scanners fail to identify BOLA because an unauthorized request often returns a standard `200 OK` response with well-formed JSON that appears identical to a normal, legitimate transaction.

WAS Mini bridges this gap by replacing naive status-code heuristics with a **Four-Pillar Analytical Engine**:
1. **Differential Response Analysis**: Uses semantic JSON tree normalization, Jaccard structural similarity, and sensitive attribute leakage detection.
2. **Autonomous Entity Lifecycle Engine**: Autonomously discovers object graphs, establishes ground-truth ownership via canary objects, and verifies cross-tenant state mutations.
3. **Access Control Matrix (ACM) & Policy Anomaly Detection**: Reconstructs global role-to-resource authorization models and detects privilege boundary inversions and policy asymmetries.
4. **Proof-of-Exploit (PoE) Generation**: Produces standalone, copy-pasteable cURL scripts and executable Python test harnesses for reproducible verification.

---

## 2. Problem Statement & Motivation

### Why Traditional DAST Scanners Fail at Authorization
Standard security scanners (e.g., OWASP ZAP, Nikto, basic vulnerability probes) inspect endpoints using a single security context or unauthenticated probes. When testing an endpoint like:
```http
GET /api/orders/3 HTTP/1.1
Authorization: Bearer <User_A_Token>
```
If the backend does not enforce tenant ownership, it returns:
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 3, "user_id": 2, "title": "Bob's Confidential Order", "amount": 299.99}
```
A standard scanner sees:
- HTTP 200 OK
- Valid JSON headers
- No SQL errors, no script reflections, no server crashes

Consequently, standard scanners mark the endpoint as **Healthy / Pass**. 

### The WAS Mini Approach
WAS Mini approaches authorization through **multi-agent differential modeling**:
1. It requests the resource under the identity of the **legitimate owner (User B)** to capture an **Authorized Baseline**.
2. It requests the exact same resource under the identity of an **unauthorized attacker (User A)** as a **Cross-Tenant Probe**.
3. It performs normalized tree differentiation, Jaccard distance calculation, and field-level matching.
4. If the probe response reflects the owner's private attributes, a confirmed BOLA finding is recorded with mathematical certainty, regardless of whether the status code was `200`, `403`, or `500`.

---

## 3. High-Level System Architecture

The platform consists of three decoupled layers:
```
+-----------------------------------------------------------------------------------+
|                              React 18 Dashboard UI                                |
|  - Real-Time SSE Live Scan Streamer     - Visual Access Control Matrix (ACM)     |
|  - Interactive Endpoint Inspector       - Proof-of-Exploit Reproduction Modal     |
|  - Scan Depth & Category Controller     - Authorization Health Gauge (0-100)      |
+------------------------------------------+----------------------------------------+
                                           | HTTP REST API & Server-Sent Events (SSE)
                                           v
+-----------------------------------------------------------------------------------+
|                         Flask Checker Analysis Engine                             |
|  +---------------------+  +---------------------+  +---------------------------+  |
|  | Scan Depth Control  |  |  Lifecycle Engine   |  |   Differential Analyzer   |  |
|  | Quick/Standard/Deep |  | Canaries & Graph    |  | Jaccard Tree Sim & PII    |  |
|  +---------------------+  +---------------------+  +---------------------------+  |
|  +---------------------+  +---------------------+  +---------------------------+  |
|  |  ACM Anomaly Engine |  | PoE Script Factory  |  |  10 Core Check Modules    |  |
|  | Matrix & Violations |  | cURL & Python PoEs  |  | BOLA, BFLA, MassAssign... |  |
|  +---------------------+  +---------------------+  +---------------------------+  |
+------------------------------------------+----------------------------------------+
                                           | Probing & Verifications
                     +---------------------+---------------------+
                     |                                           |
                     v                                           v
    +----------------------------------+       +-----------------------------------+
    |    Before-Fix Demo (Port 5001)   |       |    After-Fix Demo (Port 5002)     |
    | - Intentional BOLA / BFLA gaps   |       | - Strict resource ownership checks|
    | - Mass Assignment in orders/auth |       | - Role-based function decorators  |
    | - Shared Multi-View Modern UI:   |       | - Shared Multi-View Modern UI:    |
    |   * Storefront & Checkout Modal  |       |   * Storefront & Checkout Modal   |
    |   * Orders & Commercial Invoices |       |   * Orders & Commercial Invoices  |
    |   * Account Profile Editor       |       |   * Account Profile Editor        |
    |   * Executive Admin Portal       |       |   * Executive Admin Portal        |
    |   * In-App Security Lab & Diff   |       |   * In-App Security Lab & Diff    |
    |   * Live HTTP Telemetry Drawer   |       |   * Live HTTP Telemetry Drawer    |
    +----------------------------------+       +-----------------------------------+
```

---

## 4. The Core Engineering Pillars

### Pillar 0: Dynamic Scan Depth Controller
To address the latency of full combinatorial authorization testing across dozens of endpoints, WAS Mini implements a three-tier depth controller:

| Metric | Quick (`quick`) | Standard (`standard`) | Deep (`deep`) |
| :--- | :--- | :--- | :--- |
| **Target Request Volume** | ~15 – 25 requests | ~40 – 60 requests | ~80 – 120+ requests |
| **Typical Runtime** | 15 – 30 seconds | 1 – 2 minutes | 3 – 5 minutes |
| **Role Pairs Evaluated** | 1 primary cross-pair | All active role pairs | Full permutation matrix |
| **IDs per Resource** | First ID only | First 2 IDs | All discovered IDs |
| **Lifecycle Canaries** | Disabled (uses discovered IDs) | Enabled (1 canary/type) | Full Canaries + Mutation |
| **State Mutation Verification** | Skipped | Skipped | Active PUT/PATCH verification |
| **Fuzz Variants** | `[99999]` | `[99999, -1]` | `[99999, -1, "null"]` |

### Pillar 1: Differential Response Analysis Engine
Located in `checker/engine/diff_analyzer.py`, this module implements structural comparison between authorized baselines and unauthorized probes:

1. **JSON Tree Normalization**: Volatile dynamic keys (`created_at`, `updated_at`, `timestamp`, `token`, `nonce`, `request_id`) are stripped recursively to eliminate false deltas.
2. **Flattening**: The nested JSON structure is flattened into dot-notation paths (e.g., `order.items[0].price`).
3. **Structural Jaccard Similarity**:
   $$\text{Jaccard}(A, B) = \frac{|K_A \cap K_B|}{|K_A \cup K_B|}$$
   where $K_A$ and $K_B$ represent the key sets of baseline and probe responses.
4. **Value Match Ratio**:
   $$\text{VMR} = \frac{\sum_{k \in (K_A \cap K_B)} [V_A(k) == V_B(k)]}{|K_A \cap K_B|}$$
5. **Combined Semantic Score**:
   $$\text{Score} = 0.4 \times \text{Jaccard} + 0.6 \times \text{VMR}$$
6. **Sensitive Pattern Extraction**: Scans keys and values against regex patterns for PII (email, phone, address, credit card, SSN) and matches against owner profile hints.
7. **Verdict Resolution**:
   - `Probe == 2xx` AND $\text{Score} \ge 0.65 \implies$ **`NEEDS_FIX` (CRITICAL / HIGH)**
   - `Probe == 4xx` AND Leaked PII $\implies$ **`NEEDS_FIX` (MEDIUM)** (Information Disclosure in error)
   - `Probe == 4xx` AND Clean $\implies$ **`PASSES` (INFO)**
   - `Probe == 2xx` AND $\text{Score} < 0.20$ AND empty body $\implies$ **`PASSES` (INFO)** (Server returned empty list)

### Pillar 2: Autonomous Entity Lifecycle Engine
Located in `checker/engine/lifecycle.py`, this engine eliminates the need for manual ID configuration:

1. **Phase 1: Automated Discovery**: Automatically crawls `/api/auth/me` and collection endpoints (`GET /api/orders`, `GET /api/products`) under each configured role token to build a ground-truth map of existing resource IDs.
2. **Phase 2: Canary Provisioning**: Injects dedicated test records (e.g., `CANARY_ORDER_Alice_e89a`) via write endpoints to guarantee that the scanner possesses an object with 100% known, unambiguous ownership.
3. **Phase 3: Cross-Tenant Probe**: Executes cross-role access tests against the generated canary objects.
4. **Phase 4: State Mutation Verification** (Deep mode): An attacker role issues a `PUT /api/orders/{canary_id}` with a modified payload (`title: "MUTATED_BY_ATTACKER"`). The original owner then re-fetches the object. If the title reflects the attacker's change, the scanner flags a verified state corruption vulnerability.
5. **Phase 5: Automated Teardown**: Issues authenticated `DELETE` requests for all provisioned canaries to leave target databases clean.

### Pillar 3: Access Control Matrix (ACM) & Policy Anomaly Engine
Located in `checker/engine/acm_builder.py`, this module builds an enterprise-grade authorization matrix:

- **Matrix Dimension**: $\text{Roles} \times \text{Endpoints}$
- **Cell Classifications**:
  - `OWN_ONLY` (Green): Role can access its own resources, but is strictly blocked from foreign resources.
  - `DENIED` (Slate): Role has zero access to this endpoint (appropriate for non-admin on admin routes).
  - `ALLOWED` (Blue): Publicly accessible or universally permitted route.
  - `CROSS_ACCESS` (Red): Boundary breach detected — role can view or tamper with foreign tenant data.
  - `NOT_TESTED` (Gray): Endpoint not covered or inapplicable for role.
- **Automated Anomaly Detectors**:
  - **Privilege Boundary Inversion (BFLA)**: Flagged when non-admin roles achieve `CROSS_ACCESS` or `ALLOWED` on `/admin/*` routes.
  - **Policy Asymmetry**: Flagged when User A can access User B's resources, but User B cannot access User A's resources.
  - **Unauthenticated Object Exposure**: Flagged when sensitive business objects return data with no token attached.
- **Authorization Health Index (0 – 100)**: A quantitative scoring algorithm applying weighted deductions for critical breaches, anomalies, and unauthenticated leaks.

### Pillar 4: Proof-of-Exploit (PoE) Generation Suite
Located in `checker/engine/poe_generator.py`, this engine ensures findings are actionable and independently reproducible:

- **Annotated cURL Command**: Generates a terminal command with the attacker's headers, path parameters, payload, and comments showing expected vs actual HTTP status codes. Includes a secondary verification baseline command using the victim's token.
- **Standalone Python Test Harness**: Generates an executable script using `requests` that can be integrated directly into CI/CD regression suites to verify when a patch has resolved the issue.
- **Raw HTTP Wire Artifacts**: Formats the complete HTTP request and response trace for formal security reports.

---

## 5. Check Module Catalog

WAS Mini includes 10 check modules (`checker/engine/check_modules.py`):

1. **`HorizontalBOLA`**: Probes path-parameter object references across tenants using differential analysis.
2. **`VerticalPrivilege`**: Checks if non-administrative tokens can invoke administrative routes (`/api/admin/*`).
3. **`MissingAuth`**: Verifies that endpoints reject requests missing the `Authorization` header with `401 Unauthorized`.
4. **`MalformedAuth`**: Injects truncated tokens, invalid signatures, empty strings, and foreign auth schemes.
5. **`IDManipulation`**: Injects boundary integers (`0`, `-1`, `99999`) and string nulls to check for 500 errors or leaks.
6. **`MassAssignment`**: Injects privileged keys (`{"role": "admin"}`, `{"is_admin": true}`) into JSON request bodies on write endpoints.
7. **`MethodSubstitution`**: Tests HTTP verb tunneling (`PUT`, `DELETE`, `PATCH` on `GET` routes) to identify unguarded route handlers.
8. **`ResponseLeakage`**: Scans denial (403/404) bodies for internal stack traces, database syntax errors, and leaked foreign tenant identifiers.
9. **`CrossEndpointGraph`**: Takes IDs discovered in responses from one endpoint (e.g., `orders`) and attempts to access related entities on separate endpoints (e.g., `products`, `users`).
10. **`QueryParamSubstitution`**: Checks whether query parameters (e.g., `?user_id=X`, `?admin=true`) override identity derivation.

---

## 6. Target Demonstration Environments

To prove detection accuracy and verify remediation, two demo applications are included in `demo-apps/`, powered by a modular shared frontend (`demo-apps/shared-ui`):

### Shared Multi-View Application Structure
Both applications run an identical, offline-resilient web frontend so viewers can observe how identical user interactions produce completely different security behaviors on the wire:
1. **Marketplace & Live Checkout (`/api/products`, `POST /api/orders`)**: Interactive catalog with real-time stock levels and an interactive modal to place orders.
2. **Orders & Commercial Invoices (`/api/orders`, `GET /api/orders/{id}`)**: Itemized order management with printable commercial receipts exposing tenant ownership context.
3. **Account Profile Settings (`/api/users/{id}`, `PUT /api/users/{id}`)**: Profile card and live form editor allowing testing of cross-tenant profile tampering.
4. **Executive Administration Portal (`/api/admin/reports`, `/api/admin/users`)**: High-privilege metrics dashboard and customer directory with account revocation actions.
5. **Security Lab & Vulnerability Inspector**: In-app testbed with one-click presets for BOLA, BFLA, and Mass Assignment, paired with a floating **⚡ Raw Response Telemetry Drawer** capturing status codes, payloads, and network latencies.

### 1. Before-Fix Target (`localhost:5001`) — Vulnerable E-Commerce API
- **Gaps**:
  - `GET/PUT/DELETE /api/orders/{id}`: Missing ownership check (Horizontal BOLA on invoices).
  - `GET/PUT /api/users/{id}`: Missing ownership check (Horizontal BOLA on profile data).
  - `GET /api/orders?user_id=X`: Query parameter overrides identity (Query Param BOLA).
  - `GET /api/admin/*`: Decorated with `@jwt_required()`, but missing role validation (BFLA allows regular users into the executive console).
  - `POST /api/orders`: Reads `user_id` from body without validating against JWT identity (Mass Assignment).
- **Resulting Policy Score**: **~35 / 100 (Grade F - Critical Policy Breaches)**

### 2. After-Fix Target (`localhost:5002`) — Hardened API
- **Fixes**:
  - Validates `order.user_id == current_user_id`, returning `404 Not Found` to prevent existence leakage.
  - Validates `user_id == current_user_id` on user profile routes, blocking cross-tenant tampering.
  - Forces `user_id = get_jwt_identity()`, strictly ignoring client-supplied query parameters and payload identities.
  - Implements `@require_admin` decorator that inspects token claims and rejects non-admin users with an explicit access barrier.
- **Resulting Policy Score**: **~95 – 100 / 100 (Grade A - Strong Authorization Policy)**

### 3. Automated Regression & Fixture Management Tooling
- **`reset_demo_data.py`**: Re-initializes and seeds SQLite databases to their clean baseline state (Alice=1, Bob=2, Admin=3).
- **`smoke_test.py`**: Automated validation suite asserting BOLA/BFLA contrast between before-fix and after-fix, verified XSS escaping hygiene, and OpenAPI integrity.
- **`sync_ui.py`**: Synchronizes the shared UI into both apps, ensuring single-source-of-truth maintenance.

---

## 7. How to Demonstrate the Platform

### Step 1: Start the Applications
Open three terminal windows:
```powershell
# Terminal 1: Checker Backend (Port 5000)
cd checker
python app.py

# Terminal 2: React Dashboard (Port 3000)
cd dashboard
npm run dev

# Terminal 3: Vulnerable Target (Port 5001)
cd demo-apps/before-fix
python app.py
```

### Step 2: Run a Scan
1. Open browser to `http://localhost:3000/new`.
2. Target URL: `http://localhost:5001`.
3. Select **⚡ Quick (~15-25 req)**.
4. Upload `demo-apps/before-fix/openapi.json`.
5. Enter active tokens (obtainable via quick-login buttons on `http://localhost:5001`).
6. Click **Start Scan**.

### Step 3: Inspect Findings
- **Live Stream**: Watch real-time SSE event updates as modules execute.
- **Access Control Matrix**: Open the ACM tab to view the red `CROSS_ACCESS` cells and policy score.
- **Proof-of-Exploit**: Click **Inspect & PoE** on a BOLA finding. Copy the generated cURL command, execute it in any terminal, and observe the unauthorized data retrieval live.
