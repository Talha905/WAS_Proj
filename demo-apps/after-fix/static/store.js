/**
 * ShopLite Shared UI - Marketplace & Checkout Module
 * Handles product listing, filtering, and interactive order placement.
 */

const StoreModule = {
  products: [],
  selectedProduct: null,
  activeCategory: 'all',
  searchQuery: '',

  async init() {
    await this.loadProducts();
    this.setupListeners();
  },

  setupListeners() {
    const searchInput = document.getElementById('store-search-input');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.render();
      });
    }

    const catSelect = document.getElementById('store-category-filter');
    if (catSelect) {
      catSelect.addEventListener('change', (e) => {
        this.activeCategory = e.target.value;
        this.render();
      });
    }

    // Modal listeners
    const modalClose = document.getElementById('checkout-modal-close');
    if (modalClose) {
      modalClose.addEventListener('click', () => this.closeCheckoutModal());
    }

    const checkoutForm = document.getElementById('checkout-form');
    if (checkoutForm) {
      checkoutForm.addEventListener('submit', (e) => this.handleCheckoutSubmit(e));
    }
  },

  async loadProducts() {
    try {
      const res = await Api.getProducts();
      if (res.ok && Array.isArray(res.data)) {
        this.products = res.data;
        this.populateCategories();
        this.render();
      } else {
        showToast('Failed to load products from API', 'error');
      }
    } catch (err) {
      console.error('Products load error:', err);
      showToast('Network error loading products', 'error');
    }
  },

  populateCategories() {
    const catSelect = document.getElementById('store-category-filter');
    if (!catSelect) return;
    const cats = new Set(['all']);
    this.products.forEach(p => {
      if (p.category) cats.add(p.category);
    });

    catSelect.innerHTML = Array.from(cats).map(c => `
      <option value="${escapeHtml(c)}">${c === 'all' ? 'All Categories' : escapeHtml(c)}</option>
    `).join('');
    catSelect.value = this.activeCategory;
  },

  render() {
    const container = document.getElementById('products-grid');
    if (!container) return;

    let filtered = this.products;
    if (this.activeCategory !== 'all') {
      filtered = filtered.filter(p => p.category === this.activeCategory);
    }
    if (this.searchQuery) {
      filtered = filtered.filter(p => 
        (p.name && p.name.toLowerCase().includes(this.searchQuery)) ||
        (p.description && p.description.toLowerCase().includes(this.searchQuery)) ||
        (p.category && p.category.toLowerCase().includes(this.searchQuery))
      );
    }

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
          </svg>
          <h4>No products found</h4>
          <p>Try modifying your search query or category filter.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(p => {
      const svgIcon = getProductSvg(p.category, p.name);
      return `
        <div class="product-card">
          <div class="product-visual">
            ${svgIcon}
            <span class="product-badge">${escapeHtml(p.category || 'General')}</span>
          </div>
          <div class="product-body">
            <h3 class="product-title">${escapeHtml(p.name)}</h3>
            <p class="product-desc">${escapeHtml(p.description || 'No description provided.')}</p>
            <div class="product-meta-row">
              <span class="product-price">${formatCurrency(p.price)}</span>
              <span class="product-stock ${p.stock > 0 ? 'stock-in' : 'stock-out'}">
                ${p.stock > 0 ? `${escapeHtml(p.stock)} in stock` : 'Out of Stock'}
              </span>
            </div>
            <button class="btn btn-primary btn-block" style="margin-top: 14px;" 
                    onclick="StoreModule.openCheckoutModal(${Number(p.id)})" 
                    ${p.stock <= 0 ? 'disabled' : ''}>
              🛒 Order Now
            </button>
          </div>
        </div>
      `;
    }).join('');
  },

  openCheckoutModal(productId) {
    if (!Api.token) {
      showToast('Please select a user (Alice, Bob, or Admin) above to place an order.', 'warning');
      return;
    }

    const product = this.products.find(p => p.id === productId);
    if (!product) return;
    this.selectedProduct = product;

    const modal = document.getElementById('checkout-modal');
    const modalTitle = document.getElementById('checkout-modal-product-title');
    const modalPrice = document.getElementById('checkout-modal-unit-price');
    const modalTotal = document.getElementById('checkout-modal-total-price');
    const qtyInput = document.getElementById('checkout-quantity');
    const addressInput = document.getElementById('checkout-shipping-address');

    if (modalTitle) modalTitle.textContent = product.name;
    if (modalPrice) modalPrice.textContent = formatCurrency(product.price);
    if (qtyInput) qtyInput.value = '1';
    if (modalTotal) modalTotal.textContent = formatCurrency(product.price);

    // Default address based on current logged in user
    if (addressInput) {
      if (Api.user && Api.user.username === 'bob') {
        addressInput.value = '1042 Elm Street, Suite 4B, Dallas TX 75201';
      } else {
        addressInput.value = '742 Evergreen Terrace, Springfield OR 97477';
      }
    }

    if (qtyInput) {
      qtyInput.oninput = () => {
        const qty = Math.max(1, parseInt(qtyInput.value) || 1);
        modalTotal.textContent = formatCurrency(product.price * qty);
      };
    }

    if (modal) modal.style.display = 'flex';
  },

  closeCheckoutModal() {
    const modal = document.getElementById('checkout-modal');
    if (modal) modal.style.display = 'none';
    this.selectedProduct = null;
  },

  async handleCheckoutSubmit(e) {
    e.preventDefault();
    if (!this.selectedProduct || !Api.token) return;

    const qtyInput = document.getElementById('checkout-quantity');
    const addressInput = document.getElementById('checkout-shipping-address');
    const qty = Math.max(1, parseInt(qtyInput.value) || 1);
    const shippingAddress = addressInput ? addressInput.value.trim() : '';

    const orderPayload = {
      product_id: this.selectedProduct.id,
      title: `${this.selectedProduct.name} (x${qty})`,
      amount: parseFloat((this.selectedProduct.price * qty).toFixed(2)),
      description: `Online order placed via ShopLite Marketplace.`,
      status: 'pending',
      shipping_address: shippingAddress
    };

    try {
      const res = await Api.createOrder(orderPayload);
      if (res.ok) {
        showToast(`Order #${res.data.id || ''} created successfully!`, 'success');
        this.closeCheckoutModal();
        if (window.OrdersModule) {
          await window.OrdersModule.loadOrders();
        }
        // Switch tab to Orders so user sees the newly placed order
        if (window.App) {
          window.App.switchTab('orders');
        }
      } else {
        showToast(`Order failed: ${res.data.error || 'Server rejected request'}`, 'error');
      }
    } catch (err) {
      console.error('Checkout error:', err);
      showToast('Error communicating with checkout API', 'error');
    }
  }
};

window.StoreModule = StoreModule;
