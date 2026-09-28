/**
 * ShopLite Shared UI - API Client & Raw Inspector Tracker
 * Wraps all API interactions, provides automatic Bearer auth injection,
 * and maintains the last request/response telemetry for the Raw Response Toggle.
 */

const Api = {
  token: localStorage.getItem('shoplite_token') || '',
  user: JSON.parse(localStorage.getItem('shoplite_user') || 'null'),
  lastTelemetry: null,
  onTelemetryUpdate: null,

  setSession(token, user) {
    this.token = token || '';
    this.user = user || null;
    if (token) {
      localStorage.setItem('shoplite_token', token);
    } else {
      localStorage.removeItem('shoplite_token');
    }
    if (user) {
      localStorage.setItem('shoplite_user', JSON.stringify(user));
    } else {
      localStorage.removeItem('shoplite_user');
    }
  },

  clearSession() {
    this.setSession('', null);
  },

  async request(endpoint, options = {}) {
    const startTime = performance.now();
    const headers = options.headers ? { ...options.headers } : {};

    if (!headers['Content-Type'] && !(options.body instanceof FormData) && options.method && options.method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }

    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const config = {
      method: options.method || 'GET',
      headers: headers,
    };

    if (options.body) {
      config.body = typeof options.body === 'object' && !(options.body instanceof FormData) 
        ? JSON.stringify(options.body) 
        : options.body;
    }

    let response;
    let responseData = null;
    let rawText = '';
    let isJson = false;

    try {
      response = await fetch(endpoint, config);
      const contentType = response.headers.get('content-type') || '';
      rawText = await response.text();

      if (contentType.includes('application/json')) {
        try {
          responseData = JSON.parse(rawText);
          isJson = true;
        } catch (e) {
          responseData = { error: 'Failed to parse JSON response', raw: rawText };
        }
      } else {
        responseData = rawText;
      }
    } catch (networkError) {
      const duration = Math.round(performance.now() - startTime);
      this.lastTelemetry = {
        timestamp: new Date().toISOString(),
        url: endpoint,
        method: config.method,
        requestBody: config.body || null,
        status: 0,
        statusText: 'Network Error',
        durationMs: duration,
        responseHeaders: {},
        responseBody: networkError.message
      };
      if (this.onTelemetryUpdate) this.onTelemetryUpdate(this.lastTelemetry);
      throw networkError;
    }

    const duration = Math.round(performance.now() - startTime);
    const respHeadersObj = {};
    response.headers.forEach((val, key) => { respHeadersObj[key] = val; });

    this.lastTelemetry = {
      timestamp: new Date().toISOString(),
      url: endpoint,
      method: config.method,
      requestHeaders: headers,
      requestBody: config.body || null,
      status: response.status,
      statusText: response.statusText,
      durationMs: duration,
      responseHeaders: respHeadersObj,
      responseBody: responseData
    };

    if (this.onTelemetryUpdate) {
      this.onTelemetryUpdate(this.lastTelemetry);
    }

    return {
      ok: response.ok,
      status: response.status,
      data: responseData,
      isJson: isJson
    };
  },

  // Auth Endpoints
  async login(username, password) {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: { username, password }
    });
  },

  async getMe() {
    return this.request('/api/auth/me');
  },

  // Product Endpoints
  async getProducts() {
    return this.request('/api/products');
  },

  async createProduct(productData) {
    return this.request('/api/products', {
      method: 'POST',
      body: productData
    });
  },

  // Order Endpoints
  async getOrders(userIdFilter = null) {
    let url = '/api/orders';
    if (userIdFilter !== null && userIdFilter !== undefined) {
      url += `?user_id=${encodeURIComponent(userIdFilter)}`;
    }
    return this.request(url);
  },

  async getOrder(id) {
    return this.request(`/api/orders/${id}`);
  },

  async createOrder(orderData) {
    return this.request('/api/orders', {
      method: 'POST',
      body: orderData
    });
  },

  async updateOrder(id, orderData) {
    return this.request(`/api/orders/${id}`, {
      method: 'PUT',
      body: orderData
    });
  },

  async deleteOrder(id) {
    return this.request(`/api/orders/${id}`, {
      method: 'DELETE'
    });
  },

  // User Profile Endpoints
  async getUser(id) {
    return this.request(`/api/users/${id}`);
  },

  async updateUser(id, userData) {
    return this.request(`/api/users/${id}`, {
      method: 'PUT',
      body: userData
    });
  },

  // Admin Endpoints
  async getAdminReports() {
    return this.request('/api/admin/reports');
  },

  async getAdminUsers() {
    return this.request('/api/admin/users');
  },

  async deleteAdminUser(id) {
    return this.request(`/api/admin/users/${id}`, {
      method: 'DELETE'
    });
  },

  // Raw Custom Call (for Security Lab)
  async rawCall(endpoint, method, payloadJson = null) {
    const opts = { method };
    if (payloadJson) {
      opts.body = payloadJson;
    }
    return this.request(endpoint, opts);
  }
};
