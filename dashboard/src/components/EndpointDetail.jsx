import React, { useState } from 'react';
import StatusBadge from './StatusBadge';
import { X, Lightbulb, Copy, Check, Terminal, Code2, FileText, AlertCircle, Percent } from 'lucide-react';

const EndpointDetail = ({ result, onClose }) => {
  const [copiedTab, setCopiedTab] = useState(null);
  const [poeTab, setPoeTab] = useState('curl'); // 'curl', 'python', 'raw'

  if (!result) return null;

  const moduleName = result.module_name || result.module || 'Authorization Check';
  const responseSnippet = result.response_snippet || result.response_body;
  const baselineSnippet = result.baseline_snippet;
  const evidenceDiff = result.evidence_diff || result.evidence;
  const simScore = result.similarity_score !== null && result.similarity_score !== undefined
    ? Math.round(result.similarity_score * 100)
    : null;

  const sensitiveFields = Array.isArray(result.sensitive_fields)
    ? result.sensitive_fields
    : (typeof result.sensitive_fields === 'string' && result.sensitive_fields ? JSON.parse(result.sensitive_fields) : []);

  const remediationText = result.remediation || (
    result.module === 'HorizontalBOLA' ? 
      "Ensure that object-level permissions are checked on the server-side before performing actions on the resource. The authenticated user must be the rightful owner or have explicit permissions for the requested resource ID." 
      : result.module === 'VerticalPrivilege' ?
      "Ensure that the user's role has the necessary authorization to access this administrative or privileged endpoint. Do not rely solely on hiding UI elements."
      : "Implement proper server-side authorization checks."
  );

  let parsedPayload = null;
  if (result.payload) {
    parsedPayload = result.payload;
  } else if (result.payload_json) {
    try {
      parsedPayload = typeof result.payload_json === 'string' ? JSON.parse(result.payload_json) : result.payload_json;
    } catch (e) {
      parsedPayload = result.payload_json;
    }
  }

  const handleCopy = (text, tabKey) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(tabKey);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
      {/* Backdrop */}
      <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div className="fixed inset-0 bg-gray-900/75 backdrop-blur-xs transition-opacity" aria-hidden="true" onClick={onClose}></div>

        <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

        <div className="inline-block align-bottom bg-white rounded-2xl text-left overflow-hidden shadow-2xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl w-full border border-gray-200">
          {/* Header */}
          <div className="bg-white px-6 py-5 border-b border-gray-200 flex justify-between items-start">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <StatusBadge type="method" value={result.method} />
                <h3 className="text-lg leading-6 font-bold text-gray-900 font-mono" id="modal-title">
                  {result.endpoint}
                </h3>
              </div>
              <div className="flex flex-wrap items-center gap-2.5 text-xs">
                <span className="text-gray-700 font-bold bg-gray-100 px-2.5 py-0.5 rounded-md border border-gray-200">
                  {moduleName}
                </span>
                <span className="text-gray-300">|</span>
                <StatusBadge type="severity" value={result.severity} />
                <StatusBadge type="verdict" value={result.verdict} />
                {result.mutation_verified === 1 && (
                  <span className="px-2 py-0.5 rounded-md font-bold text-[10px] uppercase bg-red-100 text-red-800 border border-red-200">
                    💥 State Mutation Verified
                  </span>
                )}
              </div>
            </div>
            <button
              onClick={onClose}
              className="bg-white rounded-lg p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors cursor-pointer"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <div className="p-6 overflow-y-auto max-h-[75vh] space-y-6">
            {/* Pillar 1: Differential Similarity Gauge Banner */}
            {simScore !== null && (
              <div className="bg-gradient-to-r from-indigo-50 to-purple-50 border border-indigo-200/80 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-indigo-600 text-white flex items-center justify-center font-bold text-sm shadow-sm shrink-0">
                    <Percent className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-900">
                        Pillar 1 • Differential Response Similarity
                      </h4>
                      <span className="text-[10px] font-bold px-2 py-0.2 rounded-full bg-indigo-200 text-indigo-900">
                        Jaccard Tree Analysis
                      </span>
                    </div>
                    <p className="text-xs text-gray-600 mt-0.5">
                      Normalized tree comparison between authorized baseline vs unauthorized probe response.
                    </p>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <span className="text-2xl font-black text-indigo-600">{simScore}%</span>
                  <div className="w-28 bg-gray-200 h-2 rounded-full mt-1 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${simScore >= 70 ? 'bg-red-500' : simScore >= 30 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                      style={{ width: `${simScore}%` }}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Sensitive Data Leakage Alert */}
            {sensitiveFields.length > 0 && (
              <div className="bg-red-50 border border-red-200 rounded-xl p-4 flex gap-3 items-start">
                <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                <div className="text-xs space-y-1">
                  <h4 className="font-bold text-red-900">Confidential Owner Attributes Leaked in Response:</h4>
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {sensitiveFields.map((field, idx) => (
                      <span key={idx} className="bg-red-100 text-red-800 border border-red-200 px-2 py-0.5 rounded font-mono text-[11px]">
                        {field}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Remediation Guidance */}
            {result.verdict === 'NEEDS_FIX' && (
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3 items-start">
                <Lightbulb className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                <div className="text-xs">
                  <h4 className="font-bold text-amber-900 mb-1">Remediation Guidance</h4>
                  <p className="text-amber-800 leading-relaxed">{remediationText}</p>
                </div>
              </div>
            )}

            {/* Pillar 4: Proof-of-Exploit & Reproduction Suite */}
            {(result.poe_curl || result.poe_python) && (
              <div className="border border-gray-200 rounded-xl overflow-hidden bg-slate-950 text-slate-100">
                <div className="bg-slate-900 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase bg-red-600 text-white px-2 py-0.5 rounded">
                      Pillar 4 PoE
                    </span>
                    <span className="text-xs font-bold text-slate-200">Exploit & Verification Test Scripts</span>
                  </div>
                  <div className="flex items-center gap-1">
                    {[
                      { id: 'curl', label: 'cURL Command', icon: Terminal, code: result.poe_curl },
                      { id: 'python', label: 'Python Test', icon: Code2, code: result.poe_python },
                    ].map((tab) => {
                      const Icon = tab.icon;
                      if (!tab.code) return null;
                      return (
                        <button
                          key={tab.id}
                          onClick={() => setPoeTab(tab.id)}
                          className={`flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-lg transition-colors cursor-pointer ${
                            poeTab === tab.id
                              ? 'bg-indigo-600 text-white shadow-xs'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                          }`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          <span>{tab.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="relative p-4 font-mono text-xs overflow-x-auto">
                  <button
                    onClick={() => handleCopy(poeTab === 'curl' ? result.poe_curl : result.poe_python, poeTab)}
                    className="absolute right-4 top-4 flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded text-xs transition-colors cursor-pointer border border-slate-700"
                  >
                    {copiedTab === poeTab ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400 font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Script</span>
                      </>
                    )}
                  </button>
                  <pre className="text-slate-200 whitespace-pre">
                    {poeTab === 'curl' ? result.poe_curl : result.poe_python}
                  </pre>
                </div>
              </div>
            )}

            {/* Differential Comparison: Baseline vs Probe */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Baseline (Authorized Owner) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-gray-700 uppercase tracking-wider">
                    Authorized Baseline (Owner Role)
                  </h4>
                  <span className="text-[10px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                    Expected Normal State
                  </span>
                </div>
                <div className="bg-slate-900 text-slate-200 rounded-xl p-3.5 font-mono text-xs overflow-x-auto whitespace-pre max-h-56 overflow-y-auto border border-slate-800">
                  {baselineSnippet ? baselineSnippet : <span className="text-slate-500 italic">No baseline recorded</span>}
                </div>
              </div>

              {/* Probe (Unauthorized Caller) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-gray-700 uppercase tracking-wider">
                    Probe Response (Unauthorized Role)
                  </h4>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                    result.actual_status >= 200 && result.actual_status < 300 && result.verdict === 'NEEDS_FIX'
                      ? 'bg-red-50 text-red-700 border-red-200 font-bold'
                      : 'bg-gray-100 text-gray-600 border-gray-200'
                  }`}>
                    HTTP {result.actual_status || 'N/A'}
                  </span>
                </div>
                <div className="bg-slate-900 text-slate-200 rounded-xl p-3.5 font-mono text-xs overflow-x-auto whitespace-pre max-h-56 overflow-y-auto border border-slate-800">
                  {responseSnippet ? (
                    typeof responseSnippet === 'object' ? JSON.stringify(responseSnippet, null, 2) : responseSnippet
                  ) : (
                    <span className="text-slate-500 italic">No body returned</span>
                  )}
                </div>
              </div>
            </div>

            {/* Differential Evidence Diff */}
            {evidenceDiff && (
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-gray-700 uppercase tracking-wider">
                  Algorithmic Evidence & Delta
                </h4>
                <div className="bg-slate-900 text-slate-100 rounded-xl p-4 font-mono text-xs overflow-x-auto whitespace-pre leading-relaxed border border-slate-800">
                  {evidenceDiff.split('\n').map((line, i) => {
                    if (line.startsWith('-')) {
                      return <div key={i} className="text-red-400 bg-red-950/40 px-1 py-0.5 rounded">{line}</div>;
                    } else if (line.startsWith('+')) {
                      return <div key={i} className="text-emerald-400 bg-emerald-950/40 px-1 py-0.5 rounded">{line}</div>;
                    }
                    return <div key={i} className="text-slate-300">{line}</div>;
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EndpointDetail;
