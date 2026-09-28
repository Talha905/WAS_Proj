import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { getScan, getReportUrl, getExportUrl } from '../api';
import LiveScan from './LiveScan';
import ResultsTable from './ResultsTable';
import SummaryCharts from './SummaryCharts';
import AccessControlMatrix from './AccessControlMatrix';
import PolicyScore from './PolicyScore';
import StatusBadge from './StatusBadge';
import { FileText, FileJson, Shield, Table, BarChart3, Activity } from 'lucide-react';

const ScanDetail = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [liveCompleted, setLiveCompleted] = useState(false);
  const [activeTab, setActiveTab] = useState('results'); // 'results', 'acm', 'charts', 'lifecycle'

  const fetchScan = async () => {
    try {
      const { data } = await getScan(scanId);
      const scanData = data.scan
        ? {
            ...data.scan,
            results: data.results,
            summary: data.summary,
            acm: data.acm,
            policy_score: data.policy_score,
            lifecycle_log: data.lifecycle_log,
            scan_depth: data.scan_depth,
          }
        : data;
      setScan(scanData);
      if (scanData.status === 'complete' || scanData.status === 'cancelled') {
        setLiveCompleted(true);
      }
    } catch (err) {
      setError('Failed to load scan details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScan();
  }, [scanId, liveCompleted]);

  useEffect(() => {
    let interval;
    if (scan && scan.status === 'running') {
      interval = setInterval(fetchScan, 3000);
    }
    return () => clearInterval(interval);
  }, [scan]);

  if (loading) return <div className="p-8 text-center text-gray-500">Loading scan...</div>;
  if (error) return <div className="p-8 text-center text-red-500">{error}</div>;
  if (!scan) return <div className="p-8 text-center text-gray-500">Scan not found.</div>;

  if (scan.status === 'running' && !liveCompleted) {
    return (
      <LiveScan
        scanId={scanId}
        initialData={scan}
        onComplete={() => {
          setLiveCompleted(true);
          fetchScan();
        }}
      />
    );
  }

  const results = scan.results || [];
  const needsFixCount = results.filter((r) => r.verdict === 'NEEDS_FIX').length;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-white p-6 rounded-xl shadow-sm border border-gray-200 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-1.5">
            <h1 className="text-2xl font-bold text-gray-900">Scan Analysis: {scanId.substring(0, 8)}</h1>
            <StatusBadge type="status" value={scan.status} />
            <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase bg-indigo-100 text-indigo-800">
              Depth: {scan.scan_depth || 'standard'}
            </span>
            {scan.policy_score !== undefined && (
              <PolicyScore score={scan.policy_score} size="sm" />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500">
            <span>Target: <span className="font-semibold text-gray-900">{scan.target_url}</span></span>
            <span>•</span>
            <span>Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}</span>
            {scan.completed_at && (
              <>
                <span>•</span>
                <span>Finished: {new Date(scan.completed_at).toLocaleString()}</span>
              </>
            )}
          </div>
        </div>

        <div className="flex gap-2">
          <a
            href={getReportUrl(scanId, 'pdf')}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 bg-indigo-50 border border-indigo-200 text-indigo-700 px-3.5 py-2 rounded-lg text-xs font-semibold hover:bg-indigo-100 transition-colors"
          >
            <FileText className="w-4 h-4" /> Download PDF
          </a>
          <a
            href={getExportUrl(scanId)}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 bg-gray-50 border border-gray-300 text-gray-700 px-3.5 py-2 rounded-lg text-xs font-semibold hover:bg-gray-100 transition-colors"
          >
            <FileJson className="w-4 h-4" /> Export JSON
          </a>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200 flex gap-2">
        {[
          { id: 'results', label: 'Detailed Results', icon: Table, count: results.length },
          { id: 'acm', label: 'Access Control Matrix (ACM)', icon: Shield, badge: 'Pillar 3' },
          { id: 'charts', label: 'Visual Analytics', icon: BarChart3 },
          { id: 'lifecycle', label: 'Lifecycle Engine Logs', icon: Activity, count: (scan.lifecycle_log || []).length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-bold border-b-2 transition-all cursor-pointer ${
                isActive
                  ? 'border-indigo-600 text-indigo-600 bg-indigo-50/50'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${isActive ? 'bg-indigo-100 text-indigo-800' : 'bg-gray-100 text-gray-600'}`}>
                  {tab.count}
                </span>
              )}
              {tab.badge && (
                <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-100 text-amber-800 uppercase">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      {activeTab === 'results' && (
        <div className="space-y-6">
          <ResultsTable scan={scan} />
        </div>
      )}

      {activeTab === 'acm' && (
        <AccessControlMatrix acm={scan.acm} policyScore={scan.policy_score} />
      )}

      {activeTab === 'charts' && (
        <SummaryCharts results={results} />
      )}

      {activeTab === 'lifecycle' && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-indigo-600" />
            <h3 className="text-sm font-bold text-gray-900">Pillar 2 Autonomous Lifecycle & Provisioning Log</h3>
          </div>
          <p className="text-xs text-gray-500 mb-4">
            Detailed record of autonomous object-graph discovery, canary creation with ground-truth ownership, mutation verification, and teardown operations.
          </p>
          {scan.lifecycle_log && scan.lifecycle_log.length > 0 ? (
            <div className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs space-y-1.5 max-h-96 overflow-y-auto">
              {scan.lifecycle_log.map((logMsg, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="text-slate-500 select-none">[{i + 1}]</span>
                  <span className={logMsg.includes('CRITICAL') ? 'text-red-400 font-bold' : logMsg.includes('Discovered') ? 'text-emerald-400' : 'text-slate-300'}>
                    {logMsg}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-400 text-xs">
              No lifecycle canary logs recorded for this scan profile.
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default ScanDetail;
