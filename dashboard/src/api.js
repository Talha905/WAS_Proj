import axios from 'axios';

const API_BASE_URL = (
  import.meta.env.VITE_API_URL || 'http://localhost:5000'
).replace(/\/+$/, '');

const api = axios.create({ baseURL: API_BASE_URL });

export const startScan = (config) => api.post('/api/scans', config);
export const listScans = () => api.get('/api/scans');
export const getScan = (id) => api.get(`/api/scans/${id}`);
export const deleteScan = (id) => api.delete(`/api/scans/${id}`);
export const stopScan = (id) => api.post(`/api/scans/${id}/stop`);
export const cancelScan = (id) => api.post(`/api/scans/${id}/cancel`);
export const getACM = (id) => api.get(`/api/scans/${id}/acm`);
export const getPoE = (scanId, resultId) =>
  api.get(`/api/scans/${scanId}/results/${resultId}/poe`);
export const getPolicyScore = (id) =>
  api.get(`/api/scans/${id}/policy-score`);

export const getReportUrl = (id, format) =>
  `${API_BASE_URL}/api/scans/${id}/report?format=${encodeURIComponent(format)}`;

export const getExportUrl = (id) =>
  `${API_BASE_URL}/api/scans/${id}/export`;

export const subscribeToScan = (id, onEvent) => {
  const es = new EventSource(
    `${API_BASE_URL}/api/scans/${id}/stream`
  );

  es.onmessage = (e) => {
    try {
      onEvent(JSON.parse(e.data));
    } catch (error) {
      console.error('Failed to parse scan event:', error);
    }
  };

  es.onerror = () => es.close();

  return es;
};