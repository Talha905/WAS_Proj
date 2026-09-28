import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { listScans, deleteScan, stopScan, getReportUrl, getExportUrl } from '../api';
import StatusBadge from './StatusBadge';
import { RefreshCw, Eye, Download, Trash2, FileText, FileJson, StopCircle } from 'lucide-react';

const ScanList = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const fetchScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await listScans();
      setScans(data || []);
    } catch (err) {
      setError('Failed to load scans. Ensure the backend is running.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleStop = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm('Cancel and stop this running scan?')) return;
    try {
      await stopScan(id);
      fetchScans();
    } catch (err) {
      alert('Failed to stop scan.');
    }
  };

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm('Delete this scan?')) return;
    try {
      await deleteScan(id);
      fetchScans();
    } catch (err) {
      alert('Failed to delete scan.');
    }
  };

  const handleDownload = (e, url) => {
    e.stopPropagation();
    window.open(url, '_blank');
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <button
          onClick={fetchScans}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-300 rounded-lg shadow-sm hover:bg-gray-50 text-sm font-medium text-gray-700 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-50 text-red-700 p-4 rounded-lg border border-red-200">
          {error}
        </div>
      )}

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Target</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Started</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Results</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {scans.length === 0 && !loading && (
              <tr>
                <td colSpan="6" className="px-6 py-8 text-center text-gray-500">
                  No scans found. Create a new scan to get started.
                </td>
              </tr>
            )}
            {scans.map((scan) => (
              <tr 
                key={scan.id} 
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="hover:bg-gray-50 cursor-pointer transition-colors"
              >
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-indigo-600">
                  {scan.id.substring(0, 8)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 truncate max-w-xs">
                  {scan.target_url}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <StatusBadge type="status" value={scan.status} />
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {new Date(scan.started_at).toLocaleString()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  <div className="flex items-center space-x-1.5 font-mono text-xs">
                    <span className="text-gray-900 font-semibold" title="Total Results">
                      {scan.summary?.total ?? (Object.values(scan.verdict_counts || {}).reduce((a, b) => a + b, 0))}
                    </span>
                    <span className="text-gray-300">|</span>
                    <span className="text-red-600 font-semibold" title="Needs Fix">
                      {scan.summary?.needs_fix ?? (scan.verdict_counts?.NEEDS_FIX || 0)}
                    </span>
                    <span className="text-gray-300">/</span>
                    <span className="text-green-600 font-semibold" title="Passes">
                      {scan.summary?.passes ?? (scan.verdict_counts?.PASSES || 0)}
                    </span>
                    <span className="text-gray-300">/</span>
                    <span className="text-yellow-600 font-semibold" title="Inconclusive">
                      {scan.summary?.inconclusive ?? (scan.verdict_counts?.INCONCLUSIVE || 0)}
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                  <div className="flex justify-end gap-2">
                    <button 
                      onClick={(e) => { e.stopPropagation(); navigate(`/scans/${scan.id}`); }}
                      className="text-indigo-600 hover:text-indigo-900 p-1 rounded hover:bg-indigo-50"
                      title="View"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    {scan.status === 'running' && (
                      <button 
                        onClick={(e) => handleStop(e, scan.id)}
                        className="text-amber-600 hover:text-amber-900 p-1 rounded hover:bg-amber-50"
                        title="Stop / Cancel Scan"
                      >
                        <StopCircle className="w-4 h-4 text-amber-600" />
                      </button>
                    )}
                    {(scan.status === 'complete' || scan.status === 'cancelled') && (
                      <>
                        <button 
                          onClick={(e) => handleDownload(e, getReportUrl(scan.id, 'pdf'))}
                          className="text-gray-500 hover:text-gray-900 p-1 rounded hover:bg-gray-100"
                          title="Download PDF"
                        >
                          <FileText className="w-4 h-4" />
                        </button>
                        <button 
                          onClick={(e) => handleDownload(e, getExportUrl(scan.id))}
                          className="text-gray-500 hover:text-gray-900 p-1 rounded hover:bg-gray-100"
                          title="Download JSON"
                        >
                          <FileJson className="w-4 h-4" />
                        </button>
                      </>
                    )}
                    <button 
                      onClick={(e) => handleDelete(e, scan.id)}
                      className="text-red-500 hover:text-red-900 p-1 rounded hover:bg-red-50"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScanList;
