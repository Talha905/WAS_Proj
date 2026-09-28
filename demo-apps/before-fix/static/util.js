/**
 * ShopLite Shared UI - Utility Helpers
 * Enforces strict XSS escaping and offline resilience.
 */

// Strict HTML escaping for all user-controlled text
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Currency formatting
function formatCurrency(amount) {
  const num = Number(amount);
  if (isNaN(num)) return '$0.00';
  return '$' + num.toFixed(2);
}

// Date formatting
function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return escapeHtml(dateStr);
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (e) {
    return escapeHtml(dateStr);
  }
}

// Status badge helper
function getStatusBadge(status) {
  const s = String(status || '').toLowerCase();
  let bg = '#64748b';
  let label = status || 'Unknown';

  if (s === 'delivered') {
    bg = '#10b981';
  } else if (s === 'shipped') {
    bg = '#0ea5e9';
  } else if (s === 'processing') {
    bg = '#f59e0b';
  } else if (s === 'pending') {
    bg = '#8b5cf6';
  } else if (s === 'cancelled') {
    bg = '#ef4444';
  }

  return `<span class="status-pill" style="background-color: ${bg}22; color: ${bg}; border: 1px solid ${bg}55;">${escapeHtml(label)}</span>`;
}

// Offline SVG placeholder for product cards (no external image CDN required)
function getProductSvg(category, name) {
  const cat = String(category || '').toLowerCase();
  let iconPath = '';

  if (cat.includes('electr')) {
    // Headphones / gadgets icon
    iconPath = '<rect x="4" y="6" width="16" height="12" rx="2" stroke="#6366f1" stroke-width="2" fill="none"/><circle cx="9" cy="12" r="1.5" fill="#818cf8"/><circle cx="15" cy="12" r="1.5" fill="#818cf8"/><path d="M12 2v4" stroke="#6366f1" stroke-width="2"/>';
  } else if (cat.includes('access')) {
    // Bag / briefcase icon
    iconPath = '<rect x="3" y="7" width="18" height="14" rx="2" stroke="#ec4899" stroke-width="2" fill="none"/><path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" stroke="#ec4899" stroke-width="2" fill="none"/><line x1="3" y1="12" x2="21" y2="12" stroke="#ec4899" stroke-width="1.5"/>';
  } else {
    // Package / general box icon
    iconPath = '<path d="M12 2 3 7l9 5 9-5-9-5Z" stroke="#0ea5e9" stroke-width="2" fill="none"/><path d="m3 17 9 5 9-5" stroke="#0ea5e9" stroke-width="2" fill="none"/><path d="m3 12 9 5 9-5" stroke="#0ea5e9" stroke-width="2" fill="none"/>';
  }

  return `
    <div class="product-svg-wrapper">
      <svg width="64" height="64" viewBox="0 0 24 24" fill="none">
        ${iconPath}
      </svg>
    </div>
  `;
}

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-fadeout');
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}
