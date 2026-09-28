import React, { useState, useEffect } from 'react';
import { subscribeToScan, stopScan, getReportUrl, getExportUrl } from '../api';
import StatusBadge from './StatusBadge';
import { FileText, FileJson, CheckCircle, Square, AlertTriangle, ArrowRight } from 'lucide-react';

const LiveScan = ({ scanId, initialData, onComplete }) => {
  const [scanState, setScanState] = useState(initialData.scan || initialData);
  const [results, setResults] = useState(initialData.results || []);
  const [stopping, setStopping] = useState(false);
  const [statusMessage, setStatusMessage] = useState('Initializing scan engine...');

  useEffect(() => {
    const es = subscribeToScan(scanId, (event) => {
      if (event.type === 'status' || event.type === 'lifecycle') {
        setStatusMessage(event.message || `Lifecycle phase: ${event.phase}`);
      } else if (event.type === 'progress') {
        const prog = event.progress || { completed: event.completed || 0, total: event.total || 0 };
        setScanState(prev => ({ ...prev, progress: prog, current_endpoint: event.current_endpoint }));
      } else if (event.type === 'result') {
        const item = event.data || event;
        const normalized = {
          ...item,
          module: item.module_name || item.module || 'Check',
        };
        setResults(prev => [normalized, ...prev]);
      } else if (event.type === 'stopped' || event.type === 'cancelled') {
        setScanState(prev => ({ ...prev, status: 'cancelled' }));
        setStopping(false);
        es.close();
      } else if (event.type === 'complete' || event.type === 'error') {
        setScanState(prev => ({ ...prev, status: event.type }));
        if (event.type === 'complete' && onComplete) {
          setTimeout(onComplete, 2000); // Give user a moment to see completion before redirect
        }
        es.close();
      }
    });

    return () => es.close();
  }, [scanId, onComplete]);

  const handleStopScan = async () => {
    if (!window.confirm('Are you sure you want to stop this running scan? Partial results will be saved.')) {
      return;
    }
    setStopping(true);
    try {
      await stopScan(scanId);
      setScanState(prev => ({ ...prev, status: 'cancelled' }));
    } catch (err) {
      alert('Failed to stop scan: ' + (err.response?.data?.error || err.message));
    } finally {
      setStopping(false);
    }
  };

  const { progress = { completed: 0, total: 0 }, current_endpoint } = scanState;
  const percent = progress.total > 0 ? Math.min(100, Math.round((progress.completed / progress.total) * 100)) : 0;
  
  // Calculate live stats
  const stats = results.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] || 0) + 1;
    return acc;
  }, { NEEDS_FIX: 0, PASSES: 0, INCONCLUSIVE: 0 });

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 mb-1">Live Scan</h1>
            <p className="text-gray-500 text-sm">Target: {scanState.target_url}</p>
          </div>
          <div className="flex items-center gap-3">
            {scanState.status === 'running' && (
              <button
                type="button"
                onClick={handleStopScan}
                disabled={stopping}
                className="flex items-center gap-1.5 px-3.5 py-1.5 bg-red-50 border border-red-300 text-red-700 hover:bg-red-100 rounded-lg text-sm font-medium transition-colors shadow-sm disabled:opacity-50 cursor-pointer"
                title="Cancel and stop test execution immediately"
              >
                <Square className="w-3.5 h-3.5 fill-red-600 text-red-600" />
                {stopping ? 'Stopping…' : 'Stop Scan'}
              </button>
            )}
            <StatusBadge type="status" value={scanState.status} />
          </div>
        </div>

        {scanState.status === 'running' && (
          <div className="space-y-2 mb-8">
            <div className="flex justify-between text-sm text-gray-600">
              <span>Checking: <span className="font-mono text-xs bg-gray-100 px-1 py-0.5 rounded">{current_endpoint || 'Initializing...'}</span></span>
              <span>{percent}% ({progress.completed}/{progress.total})</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
              <div 
                className="bg-indigo-600 h-2.5 rounded-full transition-all duration-300 relative"
                style={{ width: `${percent}%` }}
              >
                <div className="absolute top-0 left-0 right-0 bottom-0 bg-white opacity-25" style={{ backgroundImage: 'linear-gradient(45deg, rgba(255,255,255,.15) 25%, transparent 25%, transparent 50%, rgba(255,255,255,.15) 50%, rgba(255,255,255,.15) 75%, transparent 75%, transparent)', backgroundSize: '1rem 1rem' }}></div>
              </div>
            </div>
            <div className="flex items-center gap-2 pt-1 text-xs text-indigo-700 font-medium">
              <span className="w-2 h-2 rounded-full bg-indigo-500 animate-ping inline-block" />
              <span>{statusMessage}</span>
            </div>
          </div>
        )}

        {(scanState.status === 'cancelled' || scanState.status === 'stopped') && (
          <div className="bg-amber-50 border border-amber-200 p-4 rounded-lg mb-8 flex items-center justify-between">
            <div className="flex items-center gap-3 text-amber-800">
              <AlertTriangle className="w-6 h-6 text-amber-600" />
              <div>
                <p className="font-medium">Scan Stopped by User</p>
                <p className="text-xs text-amber-700">Test execution was cancelled. Partial findings collected so far are preserved below.</p>
              </div>
            </div>
            <div className="flex gap-2">
              {onComplete && (
                <button
                  onClick={onComplete}
                  className="flex items-center gap-1 bg-amber-600 text-white px-3 py-1.5 rounded text-sm font-medium hover:bg-amber-700"
                >
                  View Report <ArrowRight className="w-4 h-4" />
                </button>
              )}
              <a href={getReportUrl(scanId, 'pdf')} target="_blank" rel="noreferrer" className="flex items-center gap-1 bg-white border border-amber-300 text-amber-800 px-3 py-1.5 rounded text-sm font-medium hover:bg-amber-100">
                <FileText className="w-4 h-4" /> PDF Report
              </a>
              <a href={getExportUrl(scanId)} target="_blank" rel="noreferrer" className="flex items-center gap-1 bg-white border border-amber-300 text-amber-800 px-3 py-1.5 rounded text-sm font-medium hover:bg-amber-100">
                <FileJson className="w-4 h-4" /> JSON
              </a>
            </div>
          </div>
        )}

        {scanState.status === 'complete' && (
          <div className="bg-green-50 border border-green-200 p-4 rounded-lg mb-8 flex items-center justify-between">
            <div className="flex items-center gap-3 text-green-800">
              <CheckCircle className="w-6 h-6" />
              <span className="font-medium">Scan Completed Successfully</span>
            </div>
            <div className="flex gap-2">
              {onComplete && (
                <button
                  onClick={onComplete}
                  className="flex items-center gap-1 bg-green-600 text-white px-3 py-1.5 rounded text-sm font-medium hover:bg-green-700"
                >
                  View Full Report <ArrowRight className="w-4 h-4" />
                </button>
              )}
              <a href={getReportUrl(scanId, 'pdf')} target="_blank" rel="noreferrer" className="flex items-center gap-1 bg-white border border-green-300 text-green-700 px-3 py-1.5 rounded text-sm font-medium hover:bg-green-50">
                <FileText className="w-4 h-4" /> PDF Report
              </a>
              <a href={getExportUrl(scanId)} target="_blank" rel="noreferrer" className="flex items-center gap-1 bg-white border border-green-300 text-green-700 px-3 py-1.5 rounded text-sm font-medium hover:bg-green-50">
                <FileJson className="w-4 h-4" /> JSON
              </a>
            </div>
          </div>
        )}

        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-red-50 p-4 rounded-lg border border-red-100 flex flex-col items-center">
            <span className="text-3xl font-bold text-red-600">{stats.NEEDS_FIX}</span>
            <span className="text-xs font-semibold text-red-800 uppercase mt-1">Needs Fix</span>
          </div>
          <div className="bg-green-50 p-4 rounded-lg border border-green-100 flex flex-col items-center">
            <span className="text-3xl font-bold text-green-600">{stats.PASSES}</span>
            <span className="text-xs font-semibold text-green-800 uppercase mt-1">Passes</span>
          </div>
          <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-100 flex flex-col items-center">
            <span className="text-3xl font-bold text-yellow-600">{stats.INCONCLUSIVE}</span>
            <span className="text-xs font-semibold text-yellow-800 uppercase mt-1">Inconclusive</span>
          </div>
        </div>

        <h3 className="text-lg font-semibold mb-4 border-b pb-2">Live Feed (Latest First)</h3>
        <div className="bg-gray-50 rounded-lg border border-gray-200 max-h-96 overflow-y-auto">
          {results.length === 0 ? (
            <div className="p-8 text-center text-gray-500 text-sm">No results yet.</div>
          ) : (
            <ul className="divide-y divide-gray-200">
              {results.map((res, idx) => (
                <li key={idx} className="p-3 text-sm flex items-center justify-between hover:bg-gray-100">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <StatusBadge type="method" value={res.method} />
                    <span className="font-mono text-gray-700 truncate">{res.endpoint}</span>
                    <span className="text-xs text-gray-500 bg-white px-2 py-0.5 border rounded-full">{res.module}</span>
                  </div>
                  <div>
                    <StatusBadge type="verdict" value={res.verdict} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
};

export default LiveScan;
