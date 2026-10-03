/**
 * ShopLite Shared UI - Main App Orchestrator
 * Controls session management, role switching, tab routing, and telemetry drawer.
 */

const App = {
  activeTab: 'store',

  async init() {
    this.setupNavigation();
    this.setupSessionBar();
    this.setupTelemetryDrawer();

    // Verify existing token if stored
    if (Api.token) {
      try {
        const res = await Api.getMe();
        if (res.ok && res.data) {
          Api.setSession(Api.token, res.data);
        } else {
          Api.clearSession();
        }
      } catch (e) {
        Api.clearSession();
      }
    }

    this.updateSessionUI();

    // Initialize all domain modules
    if (window.StoreModule) await window.StoreModule.init();
    if (window.OrdersModule) await window.OrdersModule.init();
    if (window.ProfileModule) await window.ProfileModule.init();
    if (window.AdminModule) await window.AdminModule.init();
    if (window.LabModule) await window.LabModule.init();

    // Handle URL hash routing if present
    const hash = window.location.hash.replace('#', '');
    const isAdmin = Boolean(Api.user && Api.user.role === 'admin');
    if (['store', 'orders', 'profile', 'lab'].includes(hash) || (hash === 'admin' && isAdmin)) {
      this.switchTab(hash);
    } else {
      this.switchTab('store');
    }
  },

  setupNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', (e) => {
        const targetTab = tab.getAttribute('data-tab');
        if (targetTab) {
          this.switchTab(targetTab);
        }
      });
    });
  },

  switchTab(tabId) {
    // Restrict admin portal to users with admin role only
    if (tabId === 'admin') {
      const isAdmin = Boolean(Api.user && Api.user.role === 'admin');
      if (!isAdmin) {
        showToast('Admin Portal is restricted to administrator accounts.', 'warning');
        tabId = 'store';
      }
    }

    this.activeTab = tabId;
    window.location.hash = tabId;

    // Update active class on nav tabs
    document.querySelectorAll('.nav-tab').forEach(t => {
      if (t.getAttribute('data-tab') === tabId) {
        t.classList.add('active');
      } else {
        t.classList.remove('active');
      }
    });

    // Update visible view containers
    document.querySelectorAll('.tab-view').forEach(v => {
      if (v.id === `view-${tabId}`) {
        v.style.display = 'block';
      } else {
        v.style.display = 'none';
      }
    });

    // Refresh active module data
    if (tabId === 'orders' && window.OrdersModule) {
      window.OrdersModule.loadOrders();
    } else if (tabId === 'admin' && window.AdminModule) {
      window.AdminModule.loadAdminData();
    } else if (tabId === 'profile' && window.ProfileModule) {
      const targetId = Api.user ? Api.user.id : 1;
      window.ProfileModule.loadProfile(targetId);
    }
  },

  setupSessionBar() {
    const copyBtn = document.getElementById('btn-copy-token');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => this.copyToken());
    }

    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => this.logout());
    }

    const loginModalBtn = document.getElementById('btn-login-modal');
    const loginModal = document.getElementById('login-modal');
    const loginModalClose = document.getElementById('login-modal-close');
    const loginModalCancel = document.getElementById('login-modal-cancel');
    const loginForm = document.getElementById('login-form');

    if (loginModalBtn && loginModal) {
      loginModalBtn.addEventListener('click', () => {
        loginModal.style.display = 'flex';
        const userInp = document.getElementById('login-username');
        if (userInp) {
          userInp.value = '';
          userInp.focus();
        }
        const passInp = document.getElementById('login-password');
        if (passInp) passInp.value = '';
      });
    }

    const closeModal = () => {
      if (loginModal) loginModal.style.display = 'none';
    };

    if (loginModalClose) loginModalClose.addEventListener('click', closeModal);
    if (loginModalCancel) loginModalCancel.addEventListener('click', closeModal);

    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value.trim();
        const password = document.getElementById('login-password').value;
        if (!username || !password) return;
        closeModal();
        await this.quickLogin(username, password);
      });
    }
  },

  fillLoginForm(username, password) {
    const u = document.getElementById('login-username');
    const p = document.getElementById('login-password');
    if (u) u.value = username;
    if (p) p.value = password;
  },

  async quickLogin(username, password) {
    try {
      const res = await Api.login(username, password);
      if (res.ok && res.data.token) {
        Api.setSession(res.data.token, null);
        const meRes = await Api.getMe();
        if (meRes.ok && meRes.data) {
          Api.setSession(res.data.token, meRes.data);
          showToast(`Logged in as ${username.toUpperCase()}`, 'success');
          this.updateSessionUI();

          // Refresh current view
          this.switchTab(this.activeTab);
        }
      } else {
        showToast(`Login failed: ${res.data.error || 'Invalid credentials'}`, 'error');
      }
    } catch (err) {
      console.error('Quick login error:', err);
      showToast('Network error logging in', 'error');
    }
  },

  logout() {
    Api.clearSession();
    this.updateSessionUI();
    showToast('Logged out of session', 'info');
    this.switchTab(this.activeTab);
  },

  updateSessionUI() {
    const userDisplay = document.getElementById('user-session-text');
    const tokenDisplay = document.getElementById('active-token-text');
    const logoutBtn = document.getElementById('btn-logout');
    const tokenBox = document.getElementById('token-bar-container');
    const adminTab = document.getElementById('nav-tab-admin') || document.querySelector('.nav-tab[data-tab="admin"]');

    const isAdmin = Boolean(Api.token && Api.user && Api.user.role === 'admin');

    if (adminTab) {
      adminTab.style.display = isAdmin ? 'inline-flex' : 'none';
    }

    // If currently on admin tab but logged-in user is not admin, redirect to store
    if (this.activeTab === 'admin' && !isAdmin) {
      this.switchTab('store');
    }

    const loginModalBtn = document.getElementById('btn-login-modal');

    if (Api.token && Api.user) {
      if (userDisplay) {
        userDisplay.innerHTML = `
          <span class="user-pill ${isAdmin ? 'pill-admin' : 'pill-user'}">
            👤 ${escapeHtml(Api.user.username.toUpperCase())}
          </span>
          <span style="font-size: 0.8rem; color: var(--text-muted); margin-left: 6px;">
            ID #${Number(Api.user.id)} (${escapeHtml(Api.user.role)})
          </span>
        `;
      }
      if (loginModalBtn) loginModalBtn.style.display = 'none';
      if (logoutBtn) logoutBtn.style.display = 'inline-flex';
      if (tokenBox) tokenBox.style.display = 'flex';
      if (tokenDisplay) tokenDisplay.textContent = Api.token;
    } else {
      if (userDisplay) {
        userDisplay.innerHTML = `<span style="color: var(--text-muted); font-size: 0.85rem;">Not Authenticated</span>`;
      }
      if (loginModalBtn) loginModalBtn.style.display = 'inline-flex';
      if (logoutBtn) logoutBtn.style.display = 'none';
      if (tokenBox) tokenBox.style.display = 'none';
      if (tokenDisplay) tokenDisplay.textContent = '';
    }
  },

  copyToken() {
    if (!Api.token) return;
    navigator.clipboard.writeText(Api.token).then(() => {
      const btn = document.getElementById('btn-copy-token');
      if (btn) {
        btn.textContent = '✅ Copied!';
        setTimeout(() => { btn.textContent = '📋 Copy JWT'; }, 2000);
      }
      showToast('JWT copied to clipboard! Paste into WAS Mini Dashboard.', 'success');
    });
  },

  setupTelemetryDrawer() {
    const toggleBtn = document.getElementById('telemetry-toggle-btn');
    const drawer = document.getElementById('telemetry-drawer');
    const closeBtn = document.getElementById('telemetry-close-btn');

    if (toggleBtn && drawer) {
      toggleBtn.addEventListener('click', () => {
        const isHidden = drawer.style.display === 'none' || drawer.style.display === '';
        drawer.style.display = isHidden ? 'block' : 'none';
      });
    }

    if (closeBtn && drawer) {
      closeBtn.addEventListener('click', () => {
        drawer.style.display = 'none';
      });
    }

    // Hook API telemetry updates
    Api.onTelemetryUpdate = (t) => {
      const badge = document.getElementById('telemetry-status-pill');
      const urlText = document.getElementById('telemetry-url-text');
      const timeText = document.getElementById('telemetry-time-text');
      const content = document.getElementById('telemetry-json-content');

      if (badge) {
        badge.textContent = `${t.method} ${t.status || 'ERR'}`;
        badge.className = `status-pill ${t.status >= 200 && t.status < 300 ? 'status-ok' : 'status-err'}`;
      }
      if (urlText) urlText.textContent = t.url;
      if (timeText) timeText.textContent = `${t.durationMs}ms`;
      if (content) {
        content.textContent = JSON.stringify({
          endpoint: t.url,
          method: t.method,
          status: t.status,
          duration: `${t.durationMs}ms`,
          requestBody: t.requestBody,
          responseBody: t.responseBody
        }, null, 2);
      }
    };
  }
};

window.App = App;

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
