/**
 * ShopLite Shared UI - Admin Management Center Module
 * Exhibits Vertical Privilege Escalation (BFLA) in before-fix vs proper denial in after-fix.
 */

const AdminModule = {
  reports: null,
  users: [],

  async init() {
    this.setupListeners();
  },

  setupListeners() {
    const refreshBtn = document.getElementById('admin-refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => this.loadAdminData());
    }
  },

  async loadAdminData() {
    const container = document.getElementById('admin-content-area');
    if (!container) return;

    if (!Api.token) {
      container.innerHTML = `
        <div class="empty-state" style="padding: 40px;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <h4>Authentication Required</h4>
          <p>Please log in as an administrator or test user above to query administrative endpoints.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = `<div class="spinner" style="margin: 40px auto;"></div>`;

    try {
      // Fire requests to both admin endpoints
      const [reportsRes, usersRes] = await Promise.all([
        Api.getAdminReports(),
        Api.getAdminUsers()
      ]);

      // If both fail with authorization errors (e.g. 403 or 404 in after-fix)
      if (!reportsRes.ok && !usersRes.ok) {
        this.renderAccessDenied(reportsRes.status, reportsRes.data);
        return;
      }

      this.reports = reportsRes.data || {};
      this.users = Array.isArray(usersRes.data) ? usersRes.data : [];
      this.renderDashboard();
    } catch (err) {
      console.error('Admin portal fetch error:', err);
      container.innerHTML = `
        <div class="empty-state" style="padding: 30px;">
          <h4 style="color: #ef4444;">Network Communication Error</h4>
          <p>Unable to connect to admin API endpoints.</p>
        </div>
      `;
    }
  },

  renderAccessDenied(status, responseData) {
    const container = document.getElementById('admin-content-area');
    if (!container) return;

    const errMsg = responseData && responseData.error ? responseData.error : 'Unauthorized';

    container.innerHTML = `
      <div class="card" style="padding: 40px; text-align: center; border: 1px solid #ef444455; background: rgba(239, 68, 68, 0.04);">
        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5" style="margin: 0 auto 16px; display: block;">
          <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
        </svg>
        <h2 style="color: #ef4444; margin: 0 0 8px;">Access Denied (HTTP ${escapeHtml(status)})</h2>
        <p style="color: var(--text-muted); max-width: 500px; margin: 0 auto 20px;">
          Server returned: <code>${escapeHtml(errMsg)}</code>. You do not possess the necessary administrative privileges (<code>role == 'admin'</code>) to access executive reports or user management.
        </p>
        
        <div style="max-width: 550px; margin: 0 auto; text-align: left; padding: 14px 18px; background: rgba(15, 23, 42, 0.6); border-radius: 8px; border: 1px solid var(--border);">
          <strong style="color: #10b981; font-size: 0.85rem;">🛡️ Secure Authorization Guard Active:</strong>
          <p style="font-size: 0.8rem; color: #94a3b8; margin: 4px 0 0;">
            The endpoint is protected by the <code>@require_admin</code> decorator. Non-admin identities receive an immediate HTTP 404/403 rejection with zero data leakage.
          </p>
        </div>

        <div style="margin-top: 24px;">
          <button class="btn btn-outline" onclick="App.quickLogin('admin', 'admin123')">🔑 Switch to Admin Identity</button>
        </div>
      </div>
    `;
  },

  renderDashboard() {
    const container = document.getElementById('admin-content-area');
    if (!container) return;

    const r = this.reports;
    const avgOrder = r.total_orders > 0 ? (r.total_revenue / r.total_orders) : 0;
    const isVulnerableAccess = Api.user && Api.user.role !== 'admin';

    container.innerHTML = `
      ${isVulnerableAccess ? `
        <div class="alert alert-danger" style="margin-bottom: 24px;">
          <div style="font-weight: 700; font-size: 0.95rem; margin-bottom: 4px;">
            ⚠️ CRITICAL BFLA VULNERABILITY (OWASP API5:2023) EXPOSED
          </div>
          <div>
            You are logged in as <strong>${escapeHtml(Api.user.username)}</strong> (Role: <code>${escapeHtml(Api.user.role)}</code>), but the server served the entire executive administration database without verifying administrative permissions!
          </div>
        </div>
      ` : ''}

      <!-- Metrics Row -->
      <div class="admin-metrics-grid">
        <div class="card metric-card">
          <span class="metric-label">Total Users</span>
          <div class="metric-val" style="color: #38bdf8;">${Number(r.total_users || 0)}</div>
          <span class="metric-sub">Registered accounts</span>
        </div>
        <div class="card metric-card">
          <span class="metric-label">Total Orders</span>
          <div class="metric-val" style="color: #818cf8;">${Number(r.total_orders || 0)}</div>
          <span class="metric-sub">Lifetime placed</span>
        </div>
        <div class="card metric-card">
          <span class="metric-label">Total Gross Revenue</span>
          <div class="metric-val" style="color: #10b981;">${formatCurrency(r.total_revenue || 0)}</div>
          <span class="metric-sub">Across all tenants</span>
        </div>
        <div class="card metric-card">
          <span class="metric-label">Avg Order Value</span>
          <div class="metric-val" style="color: #f59e0b;">${formatCurrency(avgOrder)}</div>
          <span class="metric-sub">Calculated per transaction</span>
        </div>
      </div>

      <!-- Users Directory Table -->
      <div class="card" style="margin-top: 24px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <div>
            <h3 style="margin: 0; font-size: 1.15rem;">Platform User Directory</h3>
            <span style="font-size: 0.8rem; color: var(--text-muted);">Loaded via <code>GET /api/admin/users</code></span>
          </div>
          <button class="btn btn-sm btn-outline" onclick="AdminModule.loadAdminData()">🔄 Refresh Directory</button>
        </div>

        <div style="overflow-x: auto;">
          <table class="orders-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Role</th>
                <th>Registered</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${this.users.map(u => `
                <tr>
                  <td><strong>#${Number(u.id)}</strong></td>
                  <td><code>${escapeHtml(u.username)}</code></td>
                  <td>${escapeHtml(u.full_name || 'N/A')}</td>
                  <td>${escapeHtml(u.email)}</td>
                  <td>${escapeHtml(u.phone || 'N/A')}</td>
                  <td>
                    <span class="badge ${u.role === 'admin' ? 'badge-danger' : 'badge-primary'}">
                      ${escapeHtml(u.role)}
                    </span>
                  </td>
                  <td style="font-size: 0.8rem; color: var(--text-muted);">${formatDate(u.created_at)}</td>
                  <td>
                    <button class="btn btn-sm btn-danger" onclick="AdminModule.deleteUser(${Number(u.id)}, '${escapeHtml(u.username)}')">
                      🗑️ Delete
                    </button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  async deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to permanently delete user #${userId} (${username})?`)) return;

    try {
      const res = await Api.deleteAdminUser(userId);
      if (res.ok) {
        showToast(`User #${userId} deleted successfully.`, 'success');
        await this.loadAdminData();
      } else {
        showToast(`Delete failed: ${res.data.error || 'Server rejected request'} (Status ${res.status})`, 'error');
      }
    } catch (err) {
      console.error('Delete user error:', err);
      showToast('Network error deleting user.', 'error');
    }
  }
};

window.AdminModule = AdminModule;
