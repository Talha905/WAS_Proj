import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Info, Lock, Search } from 'lucide-react';
import PolicyScore from './PolicyScore';

const LEVEL_STYLES = {
  OWN_ONLY: {
    bg: 'bg-emerald-50 border-emerald-200 text-emerald-800',
    icon: CheckCircle,
    label: 'Own Only',
    badge: 'bg-emerald-600 text-white',
  },
  DENIED: {
    bg: 'bg-slate-50 border-slate-200 text-slate-700',
    icon: Lock,
    label: 'Denied',
    badge: 'bg-slate-600 text-white',
  },
  ALLOWED: {
    bg: 'bg-blue-50 border-blue-200 text-blue-800',
    icon: CheckCircle,
    label: 'Allowed',
    badge: 'bg-blue-600 text-white',
  },
  CROSS_ACCESS: {
    bg: 'bg-red-50 border-red-300 text-red-900 animate-pulse',
    icon: AlertTriangle,
    label: 'Cross-Access',
    badge: 'bg-red-600 text-white',
  },
  NOT_TESTED: {
    bg: 'bg-gray-50 border-gray-100 text-gray-400',
    icon: Info,
    label: '–',
    badge: 'bg-gray-300 text-gray-700',
  },
};

const AccessControlMatrix = ({ acm, policyScore, onSelectCell }) => {
  const [search, setSearch] = useState('');
  const [selectedCell, setSelectedCell] = useState(null);

  if (!acm || !acm.matrix) {
    return (
      <div className="p-8 text-center bg-white rounded-xl border border-gray-200 shadow-sm">
        <Shield className="w-10 h-10 text-gray-400 mx-auto mb-3" />
        <h3 className="text-sm font-semibold text-gray-700">Access Control Matrix Not Yet Generated</h3>
        <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
          The matrix is constructed automatically once check modules and differential response analysis complete.
        </p>
      </div>
    );
  }

  const { roles = [], endpoints = [], matrix = {}, anomalies = [], summary = {} } = acm;

  const filteredEndpoints = endpoints.filter((ep) =>
    ep.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Top Section: Policy Score & High-Level Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="md:col-span-2">
          <PolicyScore score={policyScore !== undefined ? policyScore : acm.policy_score} />
        </div>
        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-sm flex flex-col justify-center">
          <span className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Boundary State Summary</span>
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="p-2 bg-red-50 rounded-lg border border-red-100">
              <span className="text-lg font-bold text-red-600">{summary.cross_access_cells || 0}</span>
              <p className="text-[10px] text-red-600 font-semibold uppercase mt-0.5">Cross-Tenant</p>
            </div>
            <div className="p-2 bg-emerald-50 rounded-lg border border-emerald-100">
              <span className="text-lg font-bold text-emerald-600">{summary.own_only_cells || 0}</span>
              <p className="text-[10px] text-emerald-600 font-semibold uppercase mt-0.5">Isolated</p>
            </div>
            <div className="p-2 bg-slate-50 rounded-lg border border-slate-100">
              <span className="text-lg font-bold text-slate-700">{summary.denied_cells || 0}</span>
              <p className="text-[10px] text-slate-600 font-semibold uppercase mt-0.5">Gated</p>
            </div>
          </div>
        </div>
      </div>

      {/* Policy Anomalies Banner */}
      {anomalies && anomalies.length > 0 && (
        <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-4 shadow-sm">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-5 h-5 text-amber-600" />
            <h4 className="text-sm font-bold text-amber-900">
              Policy Anomalies Detected ({anomalies.length})
            </h4>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {anomalies.map((anom, idx) => (
              <div key={idx} className="bg-white p-3 rounded-lg border border-amber-200 text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold text-gray-900">{anom.title}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 uppercase">
                    {anom.severity}
                  </span>
                </div>
                <p className="text-gray-600 mb-2 leading-relaxed">{anom.description}</p>
                {anom.endpoints && (
                  <div className="flex flex-wrap gap-1">
                    {anom.endpoints.map((ep, eIdx) => (
                      <span key={eIdx} className="bg-gray-100 text-gray-700 font-mono text-[10px] px-1.5 py-0.5 rounded">
                        {ep}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Matrix Controls & Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="p-4 border-b border-gray-200 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 bg-gray-50">
          <div>
            <h3 className="text-sm font-bold text-gray-800">Role × Endpoint Authorization Heatmap</h3>
            <p className="text-xs text-gray-500 mt-0.5">
              Live status mapping reconstructed from differential scan results across active user roles.
            </p>
          </div>
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Filter endpoints..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50/70 text-[11px] font-bold text-gray-500 uppercase tracking-wider">
                <th className="py-3 px-4 w-72 sticky left-0 bg-gray-50 shadow-[1px_0_0_0_#e5e7eb]">Endpoint</th>
                {roles.map((role) => (
                  <th key={role} className="py-3 px-4 text-center min-w-[140px]">
                    <span className="font-semibold text-gray-800">{role}</span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 text-xs">
              {filteredEndpoints.map((ep) => {
                const parts = ep.split(' ');
                const method = parts[0];
                const path = parts.slice(1).join(' ');

                return (
                  <tr key={ep} className="hover:bg-gray-50/50 transition-colors">
                    <td className="py-2.5 px-4 font-mono font-medium text-gray-900 sticky left-0 bg-white shadow-[1px_0_0_0_#e5e7eb]">
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold mr-2 uppercase ${
                        method === 'GET' ? 'bg-blue-100 text-blue-700' :
                        method === 'POST' ? 'bg-green-100 text-green-700' :
                        method === 'PUT' ? 'bg-amber-100 text-amber-700' :
                        method === 'DELETE' ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-700'
                      }`}>
                        {method}
                      </span>
                      <span className="text-gray-700">{path}</span>
                    </td>
                    {roles.map((role) => {
                      const cell = matrix[role]?.[ep] || { level: 'NOT_TESTED' };
                      const style = LEVEL_STYLES[cell.level] || LEVEL_STYLES.NOT_TESTED;
                      const Icon = style.icon;

                      return (
                        <td
                          key={role}
                          onClick={() => setSelectedCell({ role, endpoint: ep, cell })}
                          className="py-2 px-3 text-center cursor-pointer"
                        >
                          <div
                            className={`inline-flex items-center justify-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-semibold transition-all hover:scale-105 shadow-xs ${style.bg}`}
                          >
                            <Icon className="w-3 h-3 shrink-0" />
                            <span>{style.label}</span>
                          </div>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Cell Modal / Details */}
      {selectedCell && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-xs flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl max-w-md w-full p-5 shadow-xl border border-gray-200">
            <div className="flex items-center justify-between pb-3 border-b border-gray-200">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-indigo-600" />
                <h4 className="text-sm font-bold text-gray-900">Authorization Cell Inspector</h4>
              </div>
              <button
                onClick={() => setSelectedCell(null)}
                className="text-gray-400 hover:text-gray-600 text-sm font-bold"
              >
                ✕
              </button>
            </div>
            <div className="py-4 space-y-3 text-xs">
              <div>
                <span className="text-gray-500 font-medium">Role:</span>
                <span className="font-bold text-gray-900 ml-2">{selectedCell.role}</span>
              </div>
              <div>
                <span className="text-gray-500 font-medium">Endpoint:</span>
                <span className="font-mono text-gray-900 ml-2">{selectedCell.endpoint}</span>
              </div>
              <div>
                <span className="text-gray-500 font-medium">Evaluated Access Level:</span>
                <span className={`ml-2 px-2 py-0.5 rounded text-[11px] font-bold ${
                  LEVEL_STYLES[selectedCell.cell.level]?.badge || 'bg-gray-200 text-gray-700'
                }`}>
                  {selectedCell.cell.level}
                </span>
              </div>
              {selectedCell.cell.findings && selectedCell.cell.findings.length > 0 ? (
                <div>
                  <span className="text-gray-500 font-medium block mb-1">Findings & Evidence:</span>
                  <div className="bg-red-50 text-red-900 p-2.5 rounded-lg border border-red-200 space-y-1">
                    {selectedCell.cell.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className="text-red-500">•</span>
                        <span>{f}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="bg-emerald-50 text-emerald-800 p-2.5 rounded-lg border border-emerald-200">
                  Access permissions strictly adhere to policy boundaries with no cross-user leakage detected.
                </div>
              )}
            </div>
            <div className="pt-2 text-right">
              <button
                onClick={() => setSelectedCell(null)}
                className="px-4 py-1.5 bg-gray-100 hover:bg-gray-200 text-gray-700 font-semibold rounded-lg text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AccessControlMatrix;
