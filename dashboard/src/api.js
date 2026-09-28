import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:5000' });

export const startScan = (config) => api.post('/api/scans', config);
export const listScans = () => api.get('/api/scans');
export const getScan = (id) => api.get(`/api/scans/${id}`);
export const deleteScan = (id) => api.delete(`/api/scans/${id}`);
export const stopScan = (id) => api.post(`/api/scans/${id}/stop`);
export const cancelScan = (id) => api.post(`/api/scans/${id}/cancel`);
export const getACM = (id) => api.get(`/api/scans/${id}/acm`);
export const getPoE = (scanId, resultId) => api.get(`/api/scans/${scanId}/results/${resultId}/poe`);
export const getPolicyScore = (id) => api.get(`/api/scans/${id}/policy-score`);
export const getReportUrl = (id, format) => `http://localhost:5000/api/scans/${id}/report?format=${format}`;
export const getExportUrl = (id) => `http://localhost:5000/api/scans/${id}/export`;
export const subscribeToScan = (id, onEvent) => {
  const es = new EventSource(`http://localhost:5000/api/scans/${id}/stream`);
  es.onmessage = (e) => onEvent(JSON.parse(e.data));
  es.onerror = () => es.close();
  return es;
};
