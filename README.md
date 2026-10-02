# 🛡️ WAS Mini: Intelligent Multi-Tenant Authorization & BOLA Analysis Engine

A production-grade educational and security assessment platform for detecting, analyzing, modeling, and reproducing **Broken Object Level Authorization (BOLA / IDOR)** and **Broken Function Level Authorization (BFLA)** flaws in RESTful APIs (OWASP API Security Top 10, API1:2023 & API5:2023).

---

## 📚 Complete Documentation Suite

All aspects of the project are documented in dedicated guides in the repository root:

| Documentation File | Description |
| :--- | :--- |
| [**`HOW_TO_RUN.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/HOW_TO_RUN.md) | **Step-by-step execution guide**: Port mapping, 4-terminal startup, 1-click token copying, running scans, and comparative demonstration. |
| [**`PROJECT_EXPLANATION.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/PROJECT_EXPLANATION.md) | **Technical architecture specification**: Explains why traditional DAST scanners fail, the 4-pillar algorithmic engine, and academic defense notes. |
| [**`REAL_LIFE_APPLICATION.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/REAL_LIFE_APPLICATION.md) | **Enterprise deployment guide**: CI/CD DevSecOps gates, SaaS multi-tenant isolation, regulatory compliance (PCI-DSS 4.0, HIPAA, SOC 2), and comparative analysis. |
| [**`VULNERABILITY_CATALOG.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/VULNERABILITY_CATALOG.md) | **Vulnerability reference**: Deep breakdown of all 10 detected flaw classes, with vulnerable vs secure code examples and UI verification instructions. |
| [**`TESTER_FLOW.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/TESTER_FLOW.md) | **Engine internal data flow**: Low-level code walkthrough from endpoint discovery through differential comparison and SSE streaming. |
| [**`VULNERABILITY_ANALYSIS.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/VULNERABILITY_ANALYSIS.md) | **Code-level gap analysis**: Line-by-line comparison between `before-fix` and `after-fix` demo application blueprints. |
| [**`PRESENTATION_SCRIPT.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/PRESENTATION_SCRIPT.md) | **Academic presentation & demo script**: Word-for-word walkthrough with synchronized screen and action cues for live demonstrations. |

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             Browser (port 3000)                             │
│       React 18 + Tailwind Dashboard UI (Vite)                               │
│       - Real-time SSE Live Progress Streamer                                │
│       - Interactive Role × Endpoint Access Control Matrix (ACM)             │
│       - Proof-of-Exploit (PoE) Reproduction Inspector (cURL & Python)       │
│       - Scan Depth (Quick/Standard/Deep) & Category Preset Controller       │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ REST API & Server-Sent Events (SSE)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Checker Engine (port 5000)                          │
│   Flask REST API  │  Scan Depth Config  │  Autonomous Lifecycle Engine      │
│   Differential Analyzer (Jaccard Tree)  │  ACM Builder & Anomaly Detector   │
│   PoE Script Generator                  │  10 OWASP API Check Modules       │
│   Dynamic Signature Kwarg Router        │  PDF & Word Report Generators     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Probing & Comparative Testing
                       ┌───────────────┴───────────────┐
                       ▼                               ▼
       ┌───────────────────────────────┐   ┌───────────────────────────────┐
       │   demo-apps/before-fix        │   │    demo-apps/after-fix        │
       │   (port 5001)                 │   │    (port 5002)                │
       │   "ShopLite" Marketplace      │   │    "ShopLite" Secure Edition  │
       │   Vulnerable: 5 BOLA/BFLA gaps│   │    Hardened: 100% Gated       │
       │   Multi-View Interactive UI:  │   │    Multi-View Interactive UI: │
       │   - Storefront & Checkout     │   │   - Storefront & Checkout     │
       │   - Orders & Invoice Receipts │   │   - Orders & Invoice Receipts │
       │   - Account Profile Editor    │   │   - Account Profile Editor    │
       │   - Admin Executive Portal    │   │   - Admin Executive Portal    │
       │   - In-App Security Lab       │   │   - In-App Security Lab       │
       │   - Raw Telemetry Drawer      │   │   - Raw Telemetry Drawer      │
       └───────────────────────────────┘   └───────────────────────────────┘
```

---

## ⚡ The Four Analytical Pillars

Unlike naive probes that simply check `if status_code == 200`, WAS Mini uses a 4-pillar analytical pipeline:

1. **Pillar 0 — Dynamic Scan Depth Controller (`checker/engine/scan_depth.py`)**:
   - **⚡ Quick (~15–25 req, ~20–30s)**: Rapid demo mode; tests primary cross-pair, single ID per resource.
   - **🎯 Standard (~40–60 req, ~1–2m)**: Full non-admin role pairs, autonomous canary discovery, differential scoring.
   - **🔬 Deep (~80–120 req, ~3–4m)**: Full permutation matrix, live state mutation verification, boundary fuzzing.

2. **Pillar 1 — Differential Response Analysis (`checker/engine/diff_analyzer.py`)**:
   - Strips dynamic keys (`created_at`, `timestamp`, `token`, `nonce`).
   - Computes structural Jaccard similarity ($0.4 \times \text{Jaccard} + 0.6 \times \text{ValueMatch}$).
   - Detects PII and sensitive owner attributes (emails, phone numbers, addresses, tracking numbers) leaked in unauthorized responses or error bodies.

3. **Pillar 2 — Autonomous Entity Lifecycle Engine (`checker/engine/lifecycle.py`)**:
   - Autonomously crawls collection endpoints (`GET /api/orders`, `/api/products`) and `/me` to discover existing tenant object graphs without manual input.
   - Provisions isolated **canary test objects** (`CANARY_ORDER_Alice_89f1`) with guaranteed ground-truth ownership.
   - Verifies **state mutations** by having an unauthorized role tamper with a canary via `PUT`, followed by an owner re-read.
   - Automatically deletes and tears down canaries upon scan completion.

4. **Pillar 3 — Access Control Matrix (ACM) & Policy Anomaly Engine (`checker/engine/acm_builder.py`)**:
   - Reconstructs a comprehensive Role $\times$ Endpoint matrix (`OWN_ONLY`, `DENIED`, `ALLOWED`, `CROSS_ACCESS`).
   - Automatically flags **Privilege Boundary Inversions (BFLA)** and **Policy Asymmetries**.
   - Generates an **Authorization Health Index (0–100)** with letter grade (A/B/C/D/F).

5. **Pillar 4 — Proof-of-Exploit (PoE) Generation Suite (`checker/engine/poe_generator.py`)**:
   - Produces copy-pasteable, annotated **cURL terminal commands**.
   - Produces standalone **Python integration test scripts** using `requests` for permanent regression testing.
   - Provides one-click clipboard copy directly from the dashboard.

---

## 🚀 Quick Start Guide

### 1. Launch Services (4 Terminals)

```powershell
# Terminal 1: Vulnerable Demo App (port 5001)
cd demo-apps/before-fix
python app.py

# Terminal 2: Hardened Demo App (port 5002)
cd demo-apps/after-fix
python app.py

# Terminal 3: Checker Backend Engine (port 5000)
cd checker
python app.py

# Terminal 4: React Dashboard Frontend (port 3000)
cd dashboard
npm run dev
```

### 2. Reset or Smoke Test Demo Apps
```powershell
# Reset SQLite databases for both demo apps to baseline fixtures:
python demo-apps/reset_demo_data.py

# Run automated backend contrast, XSS escaping, and OpenAPI contract smoke tests:
python demo-apps/smoke_test.py
```

### 3. Run a Demonstration Scan
1. Open your browser to **`http://localhost:3000/new`**.
2. Target: `http://localhost:5001`.
3. Depth: **⚡ Quick (~15-25 req)**.
4. Upload: `demo-apps/before-fix/openapi.json`.
5. Copy Alice, Bob, and Admin tokens using the quick login buttons on `http://localhost:5001`.
6. Click **Start Security Scan**.
7. View the live SSE feed, inspect the **Access Control Matrix (ACM)** heatmap, and copy the **cURL PoE** from any finding.

---

## 🛠️ Technology Stack

- **Checker Engine**: Python 3.10+, Flask 3.0, Requests, SQLite3, ReportLab (PDF), python-docx (Word), PyYAML.
- **Dashboard UI**: React 18, Vite, Tailwind CSS, Lucide React icons, Recharts, Server-Sent Events (SSE).
- **Demo Applications**: Flask, Flask-JWT-Extended, Flask-Bcrypt, Flask-Limiter, Flask-CORS, SQLite3, Shared Multi-View UI (`demo-apps/shared-ui`).

---

## 📖 Complete Guides
For comprehensive details, refer to [**`HOW_TO_RUN.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/HOW_TO_RUN.md) and [**`PROJECT_EXPLANATION.md`**](file:///c:/Users/thele/OneDrive/Desktop/WAS_Mini/PROJECT_EXPLANATION.md).
