/**
 * ShopLite Shared UI - Orders & Invoice Module
 * Displays user order history, commercial invoice view modal, and cancellation flow.
 */

const OrdersModule = {
  orders: [],
  selectedOrder: null,

  async init() {
    this.setupListeners();
    if (Api.token) {
      await this.loadOrders();
    } else {
      this.renderLoggedOut();
    }
  },

  setupListeners() {
    const refreshBtn = document.getElementById('orders-refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => this.loadOrders());
    }

    const modalClose = document.getElementById('invoice-modal-close');
    if (modalClose) {
      modalClose.addEventListener('click', () => this.closeInvoiceModal());
    }

    const printBtn = document.getElementById('invoice-print-btn');
    if (printBtn) {
      printBtn.addEventListener('click', () => window.print());
    }
  },

  async loadOrders() {
    const tbody = document.getElementById('orders-tbody');
    if (!tbody) return;

    if (!Api.token) {
      this.renderLoggedOut();
      return;
    }

    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">
          <div class="spinner"></div> Loading orders from API...
        </td>
      </tr>
    `;

    try {
      const res = await Api.getOrders();
      if (res.ok && Array.isArray(res.data)) {
        this.orders = res.data;
        this.render();
      } else {
        tbody.innerHTML = `
          <tr>
            <td colspan="7" style="text-align: center; color: #ef4444; padding: 24px;">
              Failed to load orders: ${escapeHtml(res.data.error || 'Server error')} (Status: ${res.status})
            </td>
          </tr>
        `;
      }
    } catch (err) {
      console.error('Error fetching orders:', err);
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: #ef4444; padding: 24px;">
            Network error loading orders.
          </td>
        </tr>
      `;
    }
  },

  renderLoggedOut() {
    const tbody = document.getElementById('orders-tbody');
    if (!tbody) return;
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 36px;">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5" style="margin: 0 auto 12px; display: block;">
            <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
          </svg>
          <span style="font-size: 1rem; font-weight: 500;">Authentication Required</span>
          <p style="font-size: 0.85rem; margin-top: 4px;">Select Alice, Bob, or Admin in the top banner to inspect authenticated orders.</p>
        </td>
      </tr>
    `;
  },

  render() {
    const tbody = document.getElementById('orders-tbody');
    if (!tbody) return;

    if (this.orders.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">
            No orders found for this user account. Browse the Marketplace to place one!
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = this.orders.map(o => `
      <tr>
        <td><strong>#${Number(o.id)}</strong></td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(o.title)}</div>
          ${o.description ? `<div style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(o.description)}</div>` : ''}
        </td>
        <td>${getStatusBadge(o.status)}</td>
        <td><strong style="color: var(--text-accent);">${formatCurrency(o.amount)}</strong></td>
        <td><code class="code-pill">${escapeHtml(o.tracking_number || 'N/A')}</code></td>
        <td style="max-width: 220px; font-size: 0.85rem;" class="truncate" title="${escapeHtml(o.shipping_address)}">
          ${escapeHtml(o.shipping_address || 'Standard Delivery')}
        </td>
        <td style="white-space: nowrap;">
          <button class="btn btn-sm btn-outline" onclick="OrdersModule.openInvoiceModal(${Number(o.id)})" title="View Commercial Invoice">
            📄 Invoice
          </button>
          <button class="btn btn-sm btn-danger" style="margin-left: 6px;" onclick="OrdersModule.cancelOrder(${Number(o.id)})" title="Cancel this Order">
            ✕ Cancel
          </button>
        </td>
      </tr>
    `).join('');
  },

  async openInvoiceModal(orderId) {
    const modal = document.getElementById('invoice-modal');
    const container = document.getElementById('invoice-content-area');
    if (!modal || !container) return;

    modal.style.display = 'flex';
    container.innerHTML = `<div class="spinner" style="margin: 40px auto;"></div>`;

    try {
      const res = await Api.getOrder(orderId);
      if (res.ok && res.data) {
        this.selectedOrder = res.data;
        const o = res.data;
        container.innerHTML = `
          <div class="invoice-printable" id="printable-invoice">
            <div class="invoice-header">
              <div>
                <h2 style="margin: 0; font-size: 1.5rem; color: var(--brand-indigo);">ShopLite Invoice</h2>
                <span style="font-size: 0.85rem; color: var(--text-muted);">Official Commercial Receipt</span>
              </div>
              <div style="text-align: right;">
                <div style="font-size: 1.1rem; font-weight: 700;">INV-${String(o.id).padStart(5, '0')}</div>
                <div style="font-size: 0.85rem; color: var(--text-muted);">${formatDate(o.created_at)}</div>
              </div>
            </div>

            <hr style="border: 0; border-top: 1px solid var(--border); margin: 20px 0;">

            <div class="invoice-meta-grid">
              <div>
                <span class="label">Billed To (Tenant ID #${escapeHtml(o.user_id)})</span>
                <div style="font-weight: 600;">Customer Account #${escapeHtml(o.user_id)}</div>
                <div style="color: var(--text-muted); font-size: 0.85rem; margin-top: 4px;">
                  ${escapeHtml(o.shipping_address || 'No shipping address recorded')}
                </div>
              </div>
              <div>
                <span class="label">Fulfillment & Delivery</span>
                <div>Tracking: <code class="code-pill">${escapeHtml(o.tracking_number || 'SL-PENDING')}</code></div>
                <div style="margin-top: 4px;">Status: ${getStatusBadge(o.status)}</div>
              </div>
            </div>

            <table class="invoice-items-table" style="margin-top: 24px;">
              <thead>
                <tr>
                  <th>Description</th>
                  <th>Quantity</th>
                  <th>Status</th>
                  <th style="text-align: right;">Amount</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>${escapeHtml(o.title)}</strong>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(o.description || 'Standard fulfillment')}</div>
                  </td>
                  <td>1</td>
                  <td>${escapeHtml(o.status || 'pending')}</td>
                  <td style="text-align: right; font-weight: 700;">${formatCurrency(o.amount)}</td>
                </tr>
              </tbody>
              <tfoot>
                <tr>
                  <td colspan="3" style="text-align: right; font-weight: 600;">Grand Total:</td>
                  <td style="text-align: right; font-size: 1.1rem; font-weight: 800; color: var(--brand-indigo);">${formatCurrency(o.amount)}</td>
                </tr>
              </tfoot>
            </table>

            <div class="invoice-security-notice" style="margin-top: 24px; padding: 12px; background: rgba(99, 102, 241, 0.08); border-radius: 6px; font-size: 0.8rem; border: 1px solid rgba(99, 102, 241, 0.2);">
              🔐 <strong>Authorization Context:</strong> Retrieved via <code>GET /api/orders/${Number(o.id)}</code> under active token identity <strong>User #${Api.user ? escapeHtml(Api.user.id) : 'Anon'}</strong>.
              ${(Api.user && Api.user.id !== o.user_id) 
                ? '<br><span style="color: #ef4444; font-weight: 700;">⚠️ BOLA IN EFFECT: Viewing invoice belonging to User #' + escapeHtml(o.user_id) + '!</span>' 
                : '<br><span style="color: #10b981;">✓ Legitimate Owner Access.</span>'}
            </div>
          </div>
        `;
      } else {
        container.innerHTML = `
          <div class="empty-state" style="padding: 30px;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
            </svg>
            <h4 style="color: #ef4444;">Access Denied (HTTP ${res.status})</h4>
            <p>${escapeHtml(res.data.error || 'You do not have permission to view this invoice.')}</p>
          </div>
        `;
      }
    } catch (err) {
      console.error('Invoice error:', err);
      container.innerHTML = `
        <div class="empty-state" style="padding: 30px;">
          <h4 style="color: #ef4444;">Network Error</h4>
          <p>Unable to retrieve invoice from server.</p>
        </div>
      `;
    }
  },

  closeInvoiceModal() {
    const modal = document.getElementById('invoice-modal');
    if (modal) modal.style.display = 'none';
    this.selectedOrder = null;
  },

  async cancelOrder(orderId) {
    if (!confirm(`Are you sure you want to cancel Order #${orderId}?`)) return;

    try {
      const res = await Api.deleteOrder(orderId);
      if (res.ok) {
        showToast(`Order #${orderId} deleted successfully.`, 'success');
        await this.loadOrders();
      } else {
        showToast(`Failed to cancel order: ${res.data.error || 'Server rejected request'} (Status ${res.status})`, 'error');
      }
    } catch (err) {
      console.error('Cancel order error:', err);
      showToast('Network error canceling order.', 'error');
    }
  }
};

window.OrdersModule = OrdersModule;
