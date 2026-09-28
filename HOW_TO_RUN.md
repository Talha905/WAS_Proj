# 🚀 WAS Mini: Complete Step-by-Step Execution Guide

This guide walks you through setting up, launching, running scans, inspecting analytical findings, and demonstrating the platform to examiners or evaluators.

---

## 1. System Overview & Port Mapping

WAS Mini runs as a coordinated local security laboratory across **4 services**:

| Service | Directory | Port | Purpose |
| :--- | :--- | :--- | :--- |
| **Checker Backend** | `checker/` | `http://localhost:5000` | REST API, Differential Analyzer, ACM Builder, PoE Engine |
| **React Dashboard** | `dashboard/` | `http://localhost:3000` | Web UI, Live SSE Streamer, ACM Heatmap, PoE Inspector |
| **Vulnerable Demo Target** | `demo-apps/before-fix/` | `http://localhost:5001` | ShopLite store with intentional BOLA, BFLA, & Mass Assignment |
| **Hardened Demo Target** | `demo-apps/after-fix/` | `http://localhost:5002` | ShopLite store with strict ownership checks & `@require_admin` |

---

## 2. First-Time Setup (One-Time Only)

### Step 2.1: Python Dependencies
Ensure Python 3.10+ is installed on your machine.

```powershell
# 1. Install Checker dependencies
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\checker
pip install -r requirements.txt

# 2. Install Demo App dependencies
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\demo-apps\before-fix
pip install -r requirements.txt
```

### Step 2.2: Node.js Dependencies for Dashboard
Ensure Node.js 18+ is installed.

```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\dashboard
npm install
```

### Step 2.3: Re-seed Demo Databases (If Needed)
Both demo apps come with pre-seeded SQLite databases (`instance/app.db`). If you ever need to reset the orders, products, and users to fresh seed data:

```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini
python demo-apps/reset_demo_data.py
```
> **Default Test Accounts Seeded**:
> - **Alice** (`user_id = 1`): `alice` / `password123` (Orders #1, #2 | Products #1, #2)
> - **Bob** (`user_id = 2`): `bob` / `password123` (Orders #3, #4 | Products #3, #4)
> - **Admin** (`user_id = 3`): `admin` / `admin123` (Administrative Role)

You can also run the automated smoke test suite to verify baseline functionality and security contrasts:
```powershell
python demo-apps/smoke_test.py
```

---

## 3. How to Launch the System (4 Terminals)

Open **4 separate PowerShell or Command Prompt terminals**:

### Terminal 1: Vulnerable Demo App (Port 5001)
```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\demo-apps\before-fix
python app.py
```
*Expected Output: `* Running on http://127.0.0.1:5001`*

---

### Terminal 2: Hardened Demo App (Port 5002)
```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\demo-apps\after-fix
python app.py
```
*Expected Output: `* Running on http://127.0.0.1:5002`*

---

### Terminal 3: Checker Backend Engine (Port 5000)
```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\checker
python app.py
```
*Expected Output: `* Running on http://127.0.0.1:5000`*

---

### Terminal 4: React Dashboard Frontend (Port 3000)
```powershell
cd c:\Users\thele\OneDrive\Desktop\WAS_Mini\dashboard
npm run dev
```
*Expected Output: `VITE v5.4.x ready in ... Local: http://localhost:3000/`*

---

## 4. How to Obtain Authentication Tokens

WAS Mini requires valid JWT Bearer tokens for each tested role. You can obtain them in seconds using either method:

### Method A: One-Click Storefront Login (Easiest)
1. Open your browser and navigate to **`http://localhost:5001`** (for vulnerable app) or **`http://localhost:5002`** (for secure app).
2. In the top navigation bar, under **"Switch Identity"**, click **Alice**, **Bob**, or **Admin**.
3. The active session pill updates, and the **Active JWT Bar** appears displaying your Bearer token.
4. Click **"Copy JWT"** to copy the token directly to your clipboard for pasting into the Scanner.

### Method B: REST API Login via cURL
```powershell
# Login as Alice:
curl -X POST http://localhost:5001/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"password123"}'

# Login as Bob:
curl -X POST http://localhost:5001/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"bob","password":"password123"}'

# Login as Admin:
curl -X POST http://localhost:5001/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"admin","password":"admin123"}'
```

---

## 5. How to Run a Security Scan (Step-by-Step UI)

### Step 5.1: Open the Configuration Screen
1. Open your browser to **`http://localhost:3000`**.
2. Click **"New Scan"** in the sidebar navigation or top bar (or navigate directly to `http://localhost:3000/new`).

### Step 5.2: Configure Target & Depth
1. **Target Base URL**: Enter `http://localhost:5001` (to test the vulnerable target).
2. **Scan Depth & Request Volume (Pillar 0)**:
   - Select **⚡ Quick (~15-25 req)** for a fast ~20-30s demonstration.
   - Select **🎯 Standard (~40-60 req)** for full role pairs and autonomous canary discovery.
   - Select **🔬 Deep (~80-120 req)** for mutation verification and boundary fuzzing.

### Step 5.3: Upload Endpoint Specification
1. Under **Endpoint Discovery**, select **OpenAPI JSON (Recommended)**.
2. Click **"Choose File"** and upload:
   `c:\Users\thele\OneDrive\Desktop\WAS_Mini\demo-apps\before-fix\openapi.json`
   *(Alternatively, copy-paste the text content into the spec area).*

### Step 5.4: Test Suite Preset
Choose one of the one-click presets:
- **⚡ Core BOLA Only (~15-30s)**: Tests Horizontal BOLA, Query Param IDOR, and Vertical Privilege (BFLA).
- **🎯 Recommended OWASP Suite (~45s)**: Core BOLA + Mass Assignment + Missing Authentication.
- **🔍 Full Comprehensive Scan**: Runs all 10 authorization modules.

### Step 5.5: Enter Role Tokens & Known IDs
Under **Authentication Roles**, ensure you have 3 roles configured:
1. **Admin**:
   - Auth Value: Paste Admin's JWT token.
   - User IDs: `3`
2. **UserA** (Alice):
   - Auth Value: Paste Alice's JWT token.
   - User IDs: `1` | Order IDs: `1, 2` | Product IDs: `1, 2`
3. **UserB** (Bob):
   - Auth Value: Paste Bob's JWT token.
   - User IDs: `2` | Order IDs: `3, 4` | Product IDs: `3, 4`

*(Note: In Standard/Deep mode, the Autonomous Lifecycle Engine discovers these IDs automatically even if left blank).*

### Step 5.6: Launch Execution
Click **"Start Security Scan"**. The browser navigates automatically to the **Live Scan** screen (`/scans/<scan_id>`).

---

## 6. How to Interpret the Scan Results

Once the scan completes, WAS Mini presents a multi-tab analytical suite:

```
[ Detailed Results (N) ]  [ Access Control Matrix (ACM) ]  [ Visual Analytics ]  [ Lifecycle Engine Logs ]
```

### Tab 1: Detailed Results Table
- **Severity Badges**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
- **Verdict**: `NEEDS_FIX` (Vulnerability confirmed) vs `PASSES` (Access strictly gated).
- **Differential Indicators**: Shows Jaccard semantic similarity percentage (`95% Sim`) and `PoE Ready` status.
- **Action**: Click **"Inspect & PoE"** on any row to open the detailed evidence modal.

### Tab 2: Access Control Matrix (ACM) (Pillar 3)
- **Heatmap Grid**: Displays roles as rows (`Alice`, `Bob`, `Admin`, `Unauthenticated`) and API endpoints as columns.
- **Color Meanings**:
  - 🔴 **Cross-Access**: The role can read or tamper with foreign tenant resources (BOLA / BFLA breach).
  - 🟢 **Own Only**: Access is restricted strictly to the user's own data.
  - 🔒 **Denied**: Route is properly gated (returns HTTP 401/403/404).
  - 🔵 **Allowed**: Permitted public or administrative action.
- **Policy Anomalies Banner**: Highlights detected architectural anomalies (e.g. *Privilege Boundary Inversion: regular user roles can invoke `/api/admin/users`*).
- **Authorization Health Index**: Displays the overall system security grade (e.g., **35/100 Grade F** on the vulnerable app).

### Tab 3: Inspect & Proof-of-Exploit Modal (Pillars 1 & 4)
Click **"Inspect & PoE"** on any finding:
1. **Pillar 1 Differential Analysis Banner**: Displays the exact structural similarity percentage between the owner's baseline and the unauthorized probe.
2. **Confidential Attributes Leaked**: Highlights leaked owner data (emails, shipping addresses, phone numbers, tracking numbers).
3. **Pillar 4 Reproduction Suite**:
   - **cURL Tab**: Click **"Copy Script"** to copy an annotated terminal command reproducing the exact exploit.
   - **Python Test Tab**: Click **"Copy Script"** to copy a standalone Python test script using `requests`.
4. **Differential Evidence Diff**: Shows line-by-line what the server returned vs what was expected.

### Tab 4: Lifecycle Engine Logs (Pillar 2)
Displays the step-by-step chronological log of:
- Autonomous resource crawling across roles
- Canary object provisioning (e.g. `CANARY_ORDER_Alice_89f1`)
- State mutation verification results
- Automated teardown and deletion operations

---

## 7. The Ultimate Academic Demonstration (Before vs After Comparison)

To impress evaluators or examiners, follow this 5-minute comparative demonstration:

### Part 1: Scan the Vulnerable Target (Port 5001)
1. Run a **⚡ Quick** scan against `http://localhost:5001`.
2. **Show the ACM Heatmap**: Point out the red `CROSS_ACCESS` cells across `/api/orders/{id}` and `/api/admin/users`.
3. **Show the Policy Score**: Note the **Grade F (~35/100)** indicating severe authorization failures.
4. **Live Terminal Proof**: Open a finding, copy the generated **cURL PoE**, paste it into your PowerShell terminal, and press Enter:
   ```powershell
   curl -X GET "http://localhost:5001/api/orders/3" -H "Authorization: Bearer <Alice_Token>" -i
   ```
   **Result**: HTTP `200 OK` — Alice successfully downloads Bob's private order #3.

---

### Part 2: Scan the Hardened Target (Port 5002)
1. Run a new **⚡ Quick** scan, but set Target URL to `http://localhost:5002`.
2. Use the exact same spec and tokens (from `http://localhost:5002`).
3. **Show the ACM Heatmap**: All cells are now green (`OWN_ONLY`) or slate (`DENIED`). Zero red cells!
4. **Show the Policy Score**: The score jumps to **Grade A (95 – 100/100)**.
5. **Live Terminal Verification**: Re-run the exact same cURL command against Port 5002:
   ```powershell
   curl -X GET "http://localhost:5002/api/orders/3" -H "Authorization: Bearer <Alice_Token>" -i
   ```
   **Result**: HTTP `404 Not Found` — The hardened server denies access and hides resource existence, completely mitigating BOLA!
 
---

### Part 3: Interactive In-Browser Demonstration (Zero Terminal Commands Required)
You can also demonstrate all authorization vulnerabilities directly within the ShopLite web UI without touching a terminal:

1. **Demonstrating BOLA on Invoices**:
   - Navigate to `http://localhost:5001`.
   - Click **Bob** to log in as Customer #2.
   - Click the **"Security Lab"** tab in the navigation bar.
   - Under **Cross-Tenant BOLA Inspector**, select `Order` and enter Object ID `1` (owned by Alice).
   - Click **"Test Access as Current User"**.
   - **On Port 5001**: A red alert banner confirms the BOLA leak, displaying Alice's private invoice, shipping address, and tracking number directly on Bob's screen!
   - Repeat the exact same test on `http://localhost:5002` (Secured App): The system immediately displays a green **"ACCESS SAFELY DENIED (HTTP 404)"** alert.

2. **Demonstrating Vertical Privilege Escalation (BFLA)**:
   - On `http://localhost:5001`, while still logged in as **Bob** (regular user), click the **"Admin Portal"** tab.
   - **On Port 5001**: Bob gains unrestricted access to the executive metrics dashboard (total revenue, order counts) and the user database with user deletion actions!
   - Now switch to `http://localhost:5002` and click **"Admin Portal"** as Bob: An **"Access Denied (HTTP 404): Administrator Credentials Required"** barrier blocks access completely.
   - Click **Admin** on Port 5002: The admin dashboard unlocks legitimately.

3. **Demonstrating Mass Assignment**:
   - In the **Security Lab** tab, select the preset **"Mass Assignment (Injected user_id in POST /api/orders)"**.
   - Click **"Send Raw Request"**.
   - **On Port 5001**: The order is created and attributed to User #1 (Alice) instead of Bob.
   - **On Port 5002**: The server ignores the injected `user_id` and binds ownership strictly to the token identity.

4. **Live HTTP Telemetry**:
   - Click the floating **"⚡ Raw Response"** button in the bottom right corner of the screen at any time to open the live telemetry drawer, showing the exact HTTP method, response code, round-trip latency, and formatted JSON payload.

---

## 8. Troubleshooting & Common Questions

### Q: Port 5000 / 5001 / 5002 is already in use?
Identify and terminate the lingering process:
```powershell
netstat -ano | findstr :5000
taskkill /PID <PID_NUMBER> /F
```

### Q: How do I cancel or stop a running scan?
On the **Live Scan** screen, click the red **"Stop Scan"** button in the header. Execution terminates immediately, and all partial findings up to that point are saved and rendered in the ACM.

### Q: Can I export reports for submission?
Yes! On any completed scan page, click **"Download PDF"** in the top right to generate a formatted PDF report with executive summaries, finding tables, and remediation guidance, or **"Export JSON"** for machine-readable output.
