# 🎤 WAS Mini: Live Demonstration & Continuation Script

---

## Presentation Metadata & Context
* **Presenter:** Mohd Talha Patrwala (Member 3: Analysis, Reporting & Live Demonstration)
* **Preceding Speakers:** 
  * **Speaker 1 (Shashwat):** Covered Slides 1–7 (The Problem, IDOR vs BOLA, OWASP API Top 10, Why existing scanners fail).
  * **Speaker 2 (Shoib):** Covered Slides 8–11 (Framework Objectives, 3-Stage Pipeline Architecture, Step-by-Step Detection Flow, Authorization Oracle Decision Table).
* **Tone:** Professional, technical, academic, and authoritative.
* **Strict Rule:** **Zero interrogative sentences** (no rhetorical or conversational questions). Every line is a clear, declarative statement.
* **Environment Status:** All four project services are already active and initialized:
  * Vulnerable Application: `http://localhost:5001`
  * Hardened Application: `http://localhost:5002`
  * Analysis Engine: `http://localhost:5000`
  * Management Dashboard: `http://localhost:3000`

---

## Section 1: Handover & Architecture Alignment

**[Action: Step forward as Speaker 2 (Shoib) finishes Slide 11 "The Authorization Oracle"]**

**Spoken Presentation:**

"Thank you, Shoib. 

Now that we have established the theoretical foundations of the authorization oracle and our decision table, I will demonstrate how our framework translates these concepts into an automated, production-grade security testing pipeline.

As Shoib highlighted, identifying BOLA cannot rely on generic status codes. It requires multi-identity cross-replay, structural JSON normalization, and differential similarity scoring. To demonstrate our framework's capabilities, we have deployed two distinct environments:
First, a vulnerable multi-tenant enterprise marketplace running on port 5001.
Second, a hardened, zero-trust implementation running on port 5002.

Both applications share the exact same user-facing interface, allowing us to observe how identical user interactions produce completely different security outcomes on the wire."

---

## Section 2: Live Vulnerability Demonstration in the Target App

**[Screen: Switch browser to `http://localhost:5001` — ShopLite Vulnerable Edition]**

**Spoken Presentation:**

"This is **ShopLite Marketplace**, running on port 5001. The platform models a commercial multi-tenant e-commerce system with buyers, sellers, orders, and an administrative control panel.

The database is seeded with three distinct user tiers:
* Alice, Customer Number 1, who legitimately owns Orders 1 and 2.
* Bob, Customer Number 2, who legitimately owns Orders 3 and 4.
* An Administrator, User Number 3.

I will now log in as Bob by selecting his identity from our quick-switch session bar."

**[Action: Click 'Bob' under Switch Identity. Navigate to the 'Security Lab' tab]**

**Spoken Presentation:**

"Bob is now authenticated with his own valid JSON Web Token. 

I will now simulate an adversary executing an object-level authorization attack using our in-app Security Lab. I am selecting the Order resource type and specifying Object ID 1, which belongs entirely to Alice."

**[Action: Enter Object ID '1' and click 'Test Access as Current User']**

**Spoken Presentation:**

"The backend confirms that Bob is authenticated, but it completely omits the resource ownership check.

As displayed on the screen, Bob is immediately granted full access to Alice's confidential commercial invoice. The response exposes Alice's full legal name, home delivery address, amount paid, and shipping tracking number. This is a direct exploitation of OWASP API1:2023, Broken Object-Level Authorization.

Next, I will navigate to the Admin Portal tab while remaining logged in as Bob."

**[Action: Click on the 'Admin Portal' tab in the navigation bar]**

**Spoken Presentation:**

"Notice that the application allows Bob—a standard consumer—to enter the executive administrative dashboard. The backend route verifies that a valid token exists, but fails to enforce a role validation check. Bob can view total company gross revenues, aggregate transaction volumes, and the complete user directory with account deletion controls. This demonstrates OWASP API5:2023, Broken Function-Level Authorization."

---

## Section 3: Orchestrating the Automated Detection Engine

**[Screen: Switch browser tab to `http://localhost:3000/new` — Security Dashboard]**

**Spoken Presentation:**

"Having witnessed these vulnerabilities manually, I will now demonstrate how our automated framework discovers and verifies them systematically without human intervention.

This is the WAS Mini Security Dashboard, running on port 3000. 

I will configure our scan against the vulnerable target on port 5001."

**[Action: Enter Target URL `http://localhost:5001`. Select 'Quick' scan depth. Upload `openapi.json` from `demo-apps/before-fix`. Ensure Alice, Bob, and Admin tokens are entered.]**

**Spoken Presentation:**

"Our execution pipeline incorporates four core analytical pillars:

* **Pillar 0 is the Dynamic Scan Depth Controller.** To balance thoroughness against network load, the engine provides Quick, Standard, and Deep execution tiers. I have selected Quick mode, which targets primary role-pair permutations in under thirty seconds.
* **Pillar 1 is Differential Response Analysis.** The engine strips volatile fields such as dates and tokens, computes a structural Jaccard index alongside a value-matching ratio, and flags data leakage mathematically.
* **Pillar 2 is the Autonomous Entity Lifecycle Engine.** In production pipelines, the engine provisions isolated canary objects, tests unauthorized mutation, and deletes the test fixtures automatically.
* **Pillar 3 is the Access Control Matrix.** The engine reconstructs the entire role-to-endpoint authorization topology and scores system health from 0 to 100.
* **Pillar 4 is the Proof-of-Exploit Suite.** Every finding generates standalone cURL and Python reproduction harnesses.

I will now initiate the scan."

**[Action: Click 'Start Security Scan'. The UI navigates to the Live Scan view.]**

---

## Section 4: Live Results & Access Control Matrix (ACM)

**[Screen: Live Scan executes via SSE and completes, displaying the Scan Detail view]**

**Spoken Presentation:**

"The scan has completed, and the dashboard connects directly to the recorded telemetry.

In the Detailed Results table, multiple high and critical severity vulnerabilities are confirmed with the label 'NEEDS FIX'.

Beside each confirmed BOLA finding, notice the badge marked '100% Sim'. This indicates that our differential tree analyzer calculated a 100 percent structural and semantic match between Alice's legitimate baseline response and Bob's unauthorized request, confirming complete data exfiltration.

I will now switch to the Access Control Matrix tab."

**[Action: Click the 'Access Control Matrix' tab]**

**Spoken Presentation:**

"This heatmap represents the global authorization policy of the target system. Each row corresponds to a user role, and each column corresponds to an API endpoint.

The prominent red cells marked 'CROSS ACCESS' immediately highlight that regular customer tokens can read and modify foreign tenant data across the orders and users endpoints.

Furthermore, the Policy Anomaly engine flags a Privilege Boundary Inversion on the admin routes, warning that low-privileged roles possess administrative powers. 

Because of these structural authorization failures, our engine calculates an overall Authorization Health Score of 35 out of 100, assigning the target a failing grade of F."

**[Action: Switch back to Detailed Results. Click 'Inspect & PoE' on `GET /api/orders/{id}`.]**

**Spoken Presentation:**

"Opening the finding modal reveals our Proof-of-Exploit suite. The engine highlights the exact personal data attributes that leaked, presents the side-by-side JSON tree diff, and provides a ready-to-run terminal cURL command that allows developers to reproduce the breach on demand."

---

## Section 5: Verification Against the Hardened Environment

**[Screen: Navigate to `http://localhost:3000/new`. Configure a scan against `http://localhost:5002` (Hardened Target)]**

**Spoken Presentation:**

"To demonstrate the effectiveness of proper remediation, I will now run the exact same analysis against our hardened target running on port 5002.

In this secured version, all object endpoints enforce strict ownership validation by checking that the requested resource identifier matches the user identity extracted from the verified token claims. When an unauthorized access attempt occurs, the server responds with an HTTP 404 rather than 403, preventing resource existence enumeration. Additionally, administrative endpoints enforce a dedicated server-side role check decorator."

**[Action: Click 'Start Security Scan' against port 5002, then navigate to the completed scan's ACM tab]**

**Spoken Presentation:**

"The scan against the secured application is complete.

Examining the Access Control Matrix demonstrates a complete security remediation. Every red cross-access cell has been eliminated. All user endpoints are now shaded green for 'OWN ONLY', and administrative endpoints are shaded slate for 'DENIED' when evaluated against regular customer tokens.

The Authorization Health Index has risen from 35 percent to a perfect 100 percent Grade A score. This confirms that all authorization boundaries are enforced correctly."

---

## Section 6: Tool Comparison, CI/CD Integration & Conclusion

**[Action: Transition to presentation slides 14, 15, and 17]**

**Spoken Presentation:**

"Connecting back to our comparative analysis on Slide 14, standard tools such as Burp Suite and OWASP ZAP rely on manual intervention or single-identity heuristics that miss business logic authorization flaws. Commercial tools often require proprietary cloud agents. Our framework provides a lightweight, automated, and self-hosted solution that performs multi-identity differential analysis end-to-end.

Regarding integration, our scanner exposes a headless REST API that drops directly into modern CI/CD pipelines. Development teams can establish quality gates that automatically block pull requests whenever an authorization regression or policy inversion is detected.

As summarized on Slide 17, authorization testing should not be a manual, error-prone exercise. By automating identity swapping, differential tree analysis, and exploit generation, our framework provides a deterministic method for eliminating the industry's most critical API security risk.

Thank you. We are now ready for the evaluation committee's questions."
