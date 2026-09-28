/**
 * ShopLite Shared UI - Security Lab Module
 * Provides BOLA Object Inspector and Raw Payload Manipulation Panel.
 */

const LabModule = {
  async init() {
    this.setupListeners();
  },

  setupListeners() {
    const runBolaBtn = document.getElementById('lab-run-bola-btn');
    if (runBolaBtn) {
      runBolaBtn.addEventListener('click', () => this.runBolaTest());
    }

    const runRawBtn = document.getElementById('lab-run-raw-btn');
    if (runRawBtn) {
      runRawBtn.addEventListener('click', () => this.runRawTest());
    }

    const payloadPreset = document.getElementById('lab-payload-preset');
    if (payloadPreset) {
      payloadPreset.addEventListener('change', (e) => this.applyPreset(e.target.value));
    }
  },

  applyPreset(presetKey) {
    const methodSelect = document.getElementById('lab-raw-method');
    const urlInput = document.getElementById('lab-raw-url');
    const bodyInput = document.getElementById('lab-raw-body');

    if (presetKey === 'mass-assignment-order') {
      if (methodSelect) methodSelect.value = 'POST';
      if (urlInput) urlInput.value = '/api/orders';
      if (bodyInput) {
        bodyInput.value = JSON.stringify({
          title: "Injected Drone Delivery",
          amount: 899.99,
          product_id: 1,
          description: "Testing Mass Assignment vulnerability.",
          user_id: 1, // Attributing to Alice!
          shipping_address: "Attacker Drop Point, Secret Warehouse 99"
        }, null, 2);
      }
    } else if (presetKey === 'query-bola') {
      if (methodSelect) methodSelect.value = 'GET';
      if (urlInput) urlInput.value = '/api/orders?user_id=1';
      if (bodyInput) bodyInput.value = '';
    } else if (presetKey === 'admin-privilege') {
      if (methodSelect) methodSelect.value = 'GET';
      if (urlInput) urlInput.value = '/api/admin/reports';
      if (bodyInput) bodyInput.value = '';
    } else if (presetKey === 'user-bola-put') {
      if (methodSelect) methodSelect.value = 'PUT';
      if (urlInput) urlInput.value = '/api/users/1';
      if (bodyInput) {
        bodyInput.value = JSON.stringify({
          full_name: "Tampered by Attacker",
          phone: "+1-999-HACKED",
          email: "hacked@attacker.com"
        }, null, 2);
      }
    }
  },

  async runBolaTest() {
    const targetType = document.getElementById('lab-bola-type').value;
    const targetId = document.getElementById('lab-bola-id').value;
    const resultBox = document.getElementById('lab-bola-result');
    if (!resultBox) return;

    if (!Api.token) {
      resultBox.innerHTML = `
        <div class="alert alert-danger">
          ⚠️ Please select a user profile (Alice, Bob, or Admin) above before running authorization probes.
        </div>
      `;
      return;
    }

    resultBox.innerHTML = `<div class="spinner" style="margin: 30px auto;"></div>`;

    const endpoint = targetType === 'order' ? `/api/orders/${targetId}` : `/api/users/${targetId}`;

    try {
      const res = await Api.request(endpoint);
      const isAllowed = res.ok;
      const callerId = Api.user ? Api.user.id : null;
      const callerName = Api.user ? Api.user.username : 'Unknown';

      let diffBanner = '';
      if (isAllowed) {
        const ownerId = targetType === 'order' ? res.data.user_id : res.data.id;
        const isCrossTenant = callerId !== null && ownerId !== callerId;

        if (isCrossTenant) {
          diffBanner = `
            <div class="alert alert-danger" style="margin-bottom: 16px;">
              <div style="font-weight: 700; font-size: 1rem;">🚨 VULNERABILITY CONFIRMED: BOLA (OWASP API1:2023)</div>
              <div>
                Logged-in user <strong>${escapeHtml(callerName)} (User #${escapeHtml(callerId)})</strong> was granted unrestricted access to confidential ${escapeHtml(targetType)} <strong>#${escapeHtml(targetId)}</strong> belonging to <strong>User #${escapeHtml(ownerId)}</strong>!
              </div>
            </div>
          `;
        } else {
          diffBanner = `
            <div class="alert alert-success" style="margin-bottom: 16px;">
              <div style="font-weight: 700;">✓ Legitimate Owner Access</div>
              <div>You requested your own ${escapeHtml(targetType)} (#${escapeHtml(targetId)}).</div>
            </div>
          `;
        }
      } else {
        diffBanner = `
          <div class="alert alert-success" style="margin-bottom: 16px;">
            <div style="font-weight: 700;">🛡️ ACCESS SAFELY DENIED (HTTP ${escapeHtml(res.status)})</div>
            <div>
              Server verified resource ownership and rejected unauthorized caller <strong>${escapeHtml(callerName)}</strong>. Response: <code>${escapeHtml(res.data.error || 'Access Denied')}</code>.
            </div>
          </div>
        `;
      }

      resultBox.innerHTML = `
        ${diffBanner}
        <div style="font-size: 0.85rem; font-weight: 600; margin-bottom: 6px; color: var(--text-muted);">
          Server Response Payload (${isAllowed ? '200 OK' : `HTTP ${res.status}`}):
        </div>
        <pre class="code-box">${escapeHtml(JSON.stringify(res.data, null, 2))}</pre>
      `;
    } catch (err) {
      console.error('BOLA test error:', err);
      resultBox.innerHTML = `
        <div class="alert alert-danger">
          Network error: ${escapeHtml(err.message)}
        </div>
      `;
    }
  },

  async runRawTest() {
    const method = document.getElementById('lab-raw-method').value;
    const url = document.getElementById('lab-raw-url').value.trim();
    const rawBody = document.getElementById('lab-raw-body').value.trim();
    const resultBox = document.getElementById('lab-raw-result');
    if (!resultBox) return;

    let parsedBody = null;
    if (rawBody && method !== 'GET') {
      try {
        parsedBody = JSON.parse(rawBody);
      } catch (e) {
        alert('Invalid JSON body: ' + e.message);
        return;
      }
    }

    resultBox.innerHTML = `<div class="spinner" style="margin: 30px auto;"></div>`;

    try {
      const res = await Api.request(url, {
        method: method,
        body: parsedBody
      });

      let massAssignmentInsight = '';
      if (url.includes('/api/orders') && method === 'POST' && res.ok && res.data) {
        if (parsedBody && parsedBody.user_id) {
          // Check who owns the newly created order
          const checkRes = await Api.getOrder(res.data.id);
          if (checkRes.ok) {
            const actualOwner = checkRes.data.user_id;
            if (actualOwner === parsedBody.user_id && actualOwner !== Api.user.id) {
              massAssignmentInsight = `
                <div class="alert alert-danger" style="margin-bottom: 14px;">
                  ⚠️ <strong>MASS ASSIGNMENT (OWASP API3:2023) SUCCESSFUL:</strong>
                  The order was attributed to <strong>User #${escapeHtml(actualOwner)}</strong> instead of the authenticated caller (User #${escapeHtml(Api.user.id)})!
                </div>
              `;
            } else {
              massAssignmentInsight = `
                <div class="alert alert-success" style="margin-bottom: 14px;">
                  🛡️ <strong>MASS ASSIGNMENT PREVENTED:</strong>
                  The server ignored client-supplied <code>user_id=${escapeHtml(parsedBody.user_id)}</code> and forced ownership to authenticated user (User #${escapeHtml(actualOwner)}).
                </div>
              `;
            }
          }
        }
      }

      resultBox.innerHTML = `
        ${massAssignmentInsight}
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-size: 0.85rem; font-weight: 700; color: ${res.ok ? '#10b981' : '#ef4444'};">
            HTTP Status: ${res.status}
          </span>
          <span style="font-size: 0.8rem; color: var(--text-muted);">
            Latency: ${Api.lastTelemetry ? Api.lastTelemetry.durationMs : 0}ms
          </span>
        </div>
        <pre class="code-box">${escapeHtml(JSON.stringify(res.data, null, 2))}</pre>
      `;
    } catch (err) {
      console.error('Raw test error:', err);
      resultBox.innerHTML = `<div class="alert alert-danger">Error: ${escapeHtml(err.message)}</div>`;
    }
  }
};

window.LabModule = LabModule;
