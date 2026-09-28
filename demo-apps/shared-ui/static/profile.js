/**
 * ShopLite Shared UI - Profile & Account Settings Module
 * Handles profile viewing and live editing via PUT /api/users/<id>.
 */

const ProfileModule = {
  profileData: null,

  async init() {
    this.setupListeners();
    if (Api.token && Api.user) {
      await this.loadProfile(Api.user.id);
    } else {
      this.renderLoggedOut();
    }
  },

  setupListeners() {
    const form = document.getElementById('profile-edit-form');
    if (form) {
      form.addEventListener('submit', (e) => this.handleProfileSubmit(e));
    }

    const reloadBtn = document.getElementById('profile-reload-btn');
    if (reloadBtn) {
      reloadBtn.addEventListener('click', () => {
        const idInput = document.getElementById('profile-target-id');
        const targetId = idInput ? parseInt(idInput.value) : (Api.user ? Api.user.id : 1);
        this.loadProfile(targetId);
      });
    }
  },

  renderLoggedOut() {
    const card = document.getElementById('profile-container');
    if (!card) return;
    card.innerHTML = `
      <div class="empty-state" style="padding: 40px;">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5">
          <circle cx="12" cy="7" r="4"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/>
        </svg>
        <h4>Please Log In</h4>
        <p>Select a user profile above to view and edit your account settings.</p>
      </div>
    `;
  },

  async loadProfile(userId) {
    const card = document.getElementById('profile-container');
    if (!card) return;

    if (!Api.token) {
      this.renderLoggedOut();
      return;
    }

    card.innerHTML = `<div class="spinner" style="margin: 40px auto;"></div>`;

    try {
      const res = await Api.getUser(userId);
      if (res.ok && res.data) {
        this.profileData = res.data;
        this.render(res.data);
      } else {
        card.innerHTML = `
          <div class="empty-state" style="padding: 30px;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
            </svg>
            <h4 style="color: #ef4444;">Failed to Load User #${escapeHtml(userId)}</h4>
            <p>${escapeHtml(res.data.error || 'User not found or access denied')} (HTTP ${res.status})</p>
          </div>
        `;
      }
    } catch (err) {
      console.error('Profile fetch error:', err);
      card.innerHTML = `
        <div class="empty-state" style="padding: 30px;">
          <h4 style="color: #ef4444;">Network Error</h4>
          <p>Unable to load user profile.</p>
        </div>
      `;
    }
  },

  render(u) {
    const card = document.getElementById('profile-container');
    if (!card) return;

    const isOwnProfile = Api.user && Api.user.id === u.id;

    card.innerHTML = `
      <div class="profile-layout">
        <!-- Profile Overview Card -->
        <div class="card profile-card">
          <div class="profile-avatar">
            <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="#6366f1" stroke-width="1.8">
              <circle cx="12" cy="8" r="4"/><path d="M6 20v-1a6 6 0 0 1 12 0v1"/>
            </svg>
          </div>
          <h3 style="margin: 12px 0 4px; font-size: 1.25rem;">${escapeHtml(u.full_name || u.username)}</h3>
          <span style="color: var(--text-muted); font-size: 0.9rem;">@${escapeHtml(u.username)}</span>
          <div style="margin: 10px 0;">
            <span class="badge ${u.role === 'admin' ? 'badge-danger' : 'badge-primary'}">${escapeHtml(u.role)}</span>
            <span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #cbd5e1; margin-left: 6px;">ID #${escapeHtml(u.id)}</span>
          </div>

          <div class="profile-details-list">
            <div class="detail-item">
              <span class="detail-label">Email Address</span>
              <span class="detail-val">${escapeHtml(u.email)}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Contact Phone</span>
              <span class="detail-val">${escapeHtml(u.phone || 'Not specified')}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Member Since</span>
              <span class="detail-val">${formatDate(u.created_at)}</span>
            </div>
          </div>

          ${!isOwnProfile ? `
            <div class="alert alert-danger" style="margin-top: 16px; font-size: 0.8rem;">
              ⚠️ <strong>BOLA Warning:</strong> You are currently viewing User #${escapeHtml(u.id)}'s private profile while authenticated as User #${Api.user ? escapeHtml(Api.user.id) : 'Anon'}!
            </div>
          ` : ''}
        </div>

        <!-- Profile Edit Form -->
        <div class="card profile-edit-card">
          <h3 style="margin-top: 0; font-size: 1.15rem; color: var(--text-primary); display: flex; justify-content: space-between; align-items: center;">
            <span>Edit Account Details</span>
            <span style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted);">
              Target: <code>PUT /api/users/<span id="edit-user-id-badge">${Number(u.id)}</span></code>
            </span>
          </h3>

          <form id="profile-edit-form" onsubmit="ProfileModule.handleProfileSubmit(event, ${Number(u.id)})">
            <div class="form-group">
              <label class="form-label" for="edit-profile-target-id">Target User ID (BOLA Testing)</label>
              <input type="number" id="edit-profile-target-id" class="input-field" value="${Number(u.id)}" required style="max-width: 140px;">
              <span style="font-size: 0.75rem; color: var(--text-muted);">Change this ID to test modifying other tenants' accounts.</span>
            </div>

            <div class="form-row">
              <div class="form-group" style="flex: 1;">
                <label class="form-label" for="edit-profile-fullname">Full Name</label>
                <input type="text" id="edit-profile-fullname" class="input-field" value="${escapeHtml(u.full_name || '')}" required>
              </div>
              <div class="form-group" style="flex: 1;">
                <label class="form-label" for="edit-profile-username">Username</label>
                <input type="text" id="edit-profile-username" class="input-field" value="${escapeHtml(u.username || '')}" required>
              </div>
            </div>

            <div class="form-row">
              <div class="form-group" style="flex: 1;">
                <label class="form-label" for="edit-profile-email">Email Address</label>
                <input type="email" id="edit-profile-email" class="input-field" value="${escapeHtml(u.email || '')}" required>
              </div>
              <div class="form-group" style="flex: 1;">
                <label class="form-label" for="edit-profile-phone">Phone Number</label>
                <input type="text" id="edit-profile-phone" class="input-field" value="${escapeHtml(u.phone || '')}">
              </div>
            </div>

            <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 20px;">
              <button type="button" class="btn btn-outline" onclick="ProfileModule.loadProfile(${Number(u.id)})">Revert</button>
              <button type="submit" class="btn btn-primary" id="profile-save-btn">💾 Save Profile Changes</button>
            </div>
          </form>
        </div>
      </div>
    `;
  },

  async handleProfileSubmit(e, originalUserId) {
    if (e && e.preventDefault) e.preventDefault();

    const targetIdInput = document.getElementById('edit-profile-target-id');
    const targetUserId = targetIdInput ? parseInt(targetIdInput.value) : originalUserId;

    const fullNameInput = document.getElementById('edit-profile-fullname');
    const usernameInput = document.getElementById('edit-profile-username');
    const emailInput = document.getElementById('edit-profile-email');
    const phoneInput = document.getElementById('edit-profile-phone');

    const payload = {
      full_name: fullNameInput ? fullNameInput.value.trim() : '',
      username: usernameInput ? usernameInput.value.trim() : '',
      email: emailInput ? emailInput.value.trim() : '',
      phone: phoneInput ? phoneInput.value.trim() : ''
    };

    const saveBtn = document.getElementById('profile-save-btn');
    if (saveBtn) saveBtn.disabled = true;

    try {
      const res = await Api.updateUser(targetUserId, payload);
      if (res.ok) {
        showToast(`Profile #${targetUserId} updated successfully!`, 'success');
        await this.loadProfile(targetUserId);
        // If we updated our own profile, refresh session cache
        if (Api.user && Api.user.id === targetUserId) {
          const meRes = await Api.getMe();
          if (meRes.ok) {
            Api.setSession(Api.token, meRes.data);
            if (window.App) window.App.updateSessionUI();
          }
        }
      } else {
        showToast(`Update rejected (HTTP ${res.status}): ${res.data.error || 'Access Denied'}`, 'error');
      }
    } catch (err) {
      console.error('Profile update error:', err);
      showToast('Error communicating with user API', 'error');
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  }
};

window.ProfileModule = ProfileModule;
