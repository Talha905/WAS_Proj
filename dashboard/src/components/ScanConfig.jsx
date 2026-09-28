import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startScan } from '../api';
import { Plus, Trash2, Play, UploadCloud, Info } from 'lucide-react';

const TEST_CATEGORIES = [
  {
    id: 'bola',
    name: 'Broken Object Level Authorization (BOLA/IDOR)',
    description: 'Direct object reference flaws allowing users to view, tamper with, or delete other users’ private resources.',
    modules: [
      {
        id: 'HorizontalBOLA',
        name: 'Horizontal BOLA / IDOR',
        badge: 'Core OWASP API1',
        badgeColor: 'bg-red-100 text-red-800 border-red-200',
        purpose: 'Tests if User A can read, update, or delete User B\'s objects (e.g. /api/orders/1, /api/users/2).',
        speed: 'Moderate',
      },
      {
        id: 'QueryParamSubstitution',
        name: 'Query Parameter IDOR',
        badge: 'Fast',
        badgeColor: 'bg-green-100 text-green-800 border-green-200',
        purpose: 'Checks if ?user_id=X or ?admin=true query parameters override server-side identity or filter results illegally.',
        speed: 'Fast',
      },
      {
        id: 'CrossEndpointGraph',
        name: 'Cross-Endpoint ID Reuse',
        badge: 'Chained Access',
        badgeColor: 'bg-purple-100 text-purple-800 border-purple-200',
        purpose: 'Takes object IDs discovered on one endpoint (e.g. orders) and probes related endpoints (products, users).',
        speed: 'Moderate',
      },
    ],
  },
  {
    id: 'privilege',
    name: 'Privilege Escalation & Authorization Boundaries (BFLA)',
    description: 'Broken function-level authorization and privilege attribute manipulation.',
    modules: [
      {
        id: 'VerticalPrivilege',
        name: 'Vertical Privilege Escalation (BFLA)',
        badge: 'Core OWASP API5',
        badgeColor: 'bg-red-100 text-red-800 border-red-200',
        purpose: 'Checks if regular non-admin roles can invoke restricted admin routes (/api/admin/*).',
        speed: 'Fast',
      },
      {
        id: 'MassAssignment',
        name: 'Mass Assignment / Body Tampering',
        badge: 'OWASP API6',
        badgeColor: 'bg-orange-100 text-orange-800 border-orange-200',
        purpose: 'Injects privileged fields (role: "admin", is_admin: true, user_id: 2) into write request bodies (POST/PUT).',
        speed: 'Moderate',
      },
    ],
  },
  {
    id: 'auth',
    name: 'Authentication & Token Security',
    description: 'Verification that endpoints properly gate requests and validate cryptographic authentication tokens.',
    modules: [
      {
        id: 'MissingAuth',
        name: 'Missing Authentication Gate',
        badge: 'OWASP API2',
        badgeColor: 'bg-blue-100 text-blue-800 border-blue-200',
        purpose: 'Verifies endpoints strictly reject unauthenticated requests (missing Authorization header) with HTTP 401.',
        speed: 'Very Fast',
      },
      {
        id: 'MalformedAuth',
        name: 'Malformed & Bad Token Validation',
        badge: 'Token Security',
        badgeColor: 'bg-yellow-100 text-yellow-800 border-yellow-200',
        purpose: 'Sends malformed signatures, empty tokens, and wrong auth schemes to ensure tokens are validated.',
        speed: 'Fast',
      },
    ],
  },
  {
    id: 'fuzzing_and_protocol',
    name: 'Input Boundary Fuzzing & Protocol Tampering',
    description: 'Probing parameter handling and HTTP method enforcement.',
    modules: [
      {
        id: 'IDManipulation',
        name: 'Boundary & Malformed ID Fuzzing',
        badge: 'Fuzzing',
        badgeColor: 'bg-gray-100 text-gray-800 border-gray-200',
        purpose: 'Tests boundary integers (0, -1, 99999) and strings (null, admin) to detect 500 errors or leaks.',
        speed: 'Moderate',
      },
      {
        id: 'MethodSubstitution',
        name: 'HTTP Verb Tampering',
        badge: 'Method Gating',
        badgeColor: 'bg-indigo-100 text-indigo-800 border-indigo-200',
        purpose: 'Tests alternate HTTP verbs (PUT/DELETE/POST on GET routes) to verify method gating.',
        speed: 'Fast',
      },
      {
        id: 'ResponseLeakage',
        name: 'Error Response Data Leakage',
        badge: 'Info Disclosure',
        badgeColor: 'bg-pink-100 text-pink-800 border-pink-200',
        purpose: 'Analyzes error and denial responses for stack traces, internal paths, or leaked other-user data.',
        speed: 'Fast',
      },
    ],
  },
];

const ALL_MODULE_IDS = TEST_CATEGORIES.flatMap(c => c.modules.map(m => m.id));

const PRESETS = [
  {
    id: 'core_bola',
    label: '⚡ Core BOLA Only (Fastest ~15-30s)',
    description: 'Tests only Horizontal Object Access, Query Param BOLA, and Admin Privilege Escalation.',
    modules: ['HorizontalBOLA', 'QueryParamSubstitution', 'VerticalPrivilege'],
  },
  {
    id: 'recommended',
    label: '🎯 Recommended OWASP Suite (~45s)',
    description: 'Core BOLA + Mass Assignment + Missing Auth. Best balance of speed and coverage.',
    modules: ['HorizontalBOLA', 'QueryParamSubstitution', 'VerticalPrivilege', 'MassAssignment', 'MissingAuth'],
  },
  {
    id: 'all',
    label: '🔍 Full Comprehensive Scan (All 10 Tests)',
    description: 'Runs all 10 authorization, fuzzing, and protocol check modules.',
    modules: ALL_MODULE_IDS,
  },
];

const ScanConfig = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [targetUrl, setTargetUrl] = useState('http://localhost:5001');
  const [discoveryMode, setDiscoveryMode] = useState('openapi');
  const [specContent, setSpecContent] = useState('');
  
  // Default to recommended OWASP suite
  const [selectedModules, setSelectedModules] = useState([
    'HorizontalBOLA',
    'QueryParamSubstitution',
    'VerticalPrivilege',
    'MassAssignment',
    'MissingAuth',
  ]);

  // Pillar 0: Scan Depth Controller (quick = ~15-25 requests, standard = ~40-60, deep = ~80-120)
  const [scanDepth, setScanDepth] = useState('quick');

  const [endpoints, setEndpoints] = useState([
    { path: '/api/users/:id', method: 'GET', requires_auth: true }
  ]);
  
  const [roles, setRoles] = useState([
    { name: 'Admin', auth_type: 'bearer', auth_value: '', resources: { user_ids: '3', order_ids: '', product_ids: '' } },
    { name: 'UserA', auth_type: 'bearer', auth_value: '', resources: { user_ids: '1', order_ids: '1, 2', product_ids: '1, 2' } },
    { name: 'UserB', auth_type: 'bearer', auth_value: '', resources: { user_ids: '2', order_ids: '3, 4', product_ids: '3, 4' } }
  ]);

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      setSpecContent(evt.target.result);
    };
    reader.readAsText(file);
  };

  const addRole = () => {
    setRoles([...roles, { name: '', auth_type: 'bearer', auth_value: '', resources: { user_ids: '', order_ids: '', product_ids: '' } }]);
  };

  const removeRole = (idx) => {
    if (roles.length <= 2) {
      alert("At least 2 roles are required to test cross-user access.");
      return;
    }
    const newRoles = [...roles];
    newRoles.splice(idx, 1);
    setRoles(newRoles);
  };

  const updateRole = (idx, field, val) => {
    const newRoles = [...roles];
    newRoles[idx][field] = val;
    setRoles(newRoles);
  };

  const updateRoleResources = (idx, field, val) => {
    const newRoles = [...roles];
    newRoles[idx].resources[field] = val;
    setRoles(newRoles);
  };

  const addEndpoint = () => {
    setEndpoints([...endpoints, { path: '', method: 'GET', requires_auth: true }]);
  };

  const removeEndpoint = (idx) => {
    const newEp = [...endpoints];
    newEp.splice(idx, 1);
    setEndpoints(newEp);
  };

  const updateEndpoint = (idx, field, val) => {
    const newEp = [...endpoints];
    newEp[idx][field] = val;
    setEndpoints(newEp);
  };

  // Module selection helpers
  const toggleModule = (modId) => {
    if (selectedModules.includes(modId)) {
      setSelectedModules(selectedModules.filter(m => m !== modId));
    } else {
      setSelectedModules([...selectedModules, modId]);
    }
  };

  const toggleCategory = (cat) => {
    const catModuleIds = cat.modules.map(m => m.id);
    const allSelected = catModuleIds.every(id => selectedModules.includes(id));
    if (allSelected) {
      setSelectedModules(selectedModules.filter(id => !catModuleIds.includes(id)));
    } else {
      const merged = new Set([...selectedModules, ...catModuleIds]);
      setSelectedModules(Array.from(merged));
    }
  };

  const applyPreset = (presetModuleIds) => {
    setSelectedModules(presetModuleIds);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      if (selectedModules.length === 0) {
        throw new Error("Please select at least one test category to run.");
      }

      const config = {
        target_url: targetUrl,
        selected_modules: selectedModules,
        scan_depth: scanDepth,
        discovery: {
          mode: discoveryMode,
          selected_modules: selectedModules,
          scan_depth: scanDepth,
        },
        roles: roles.map(r => ({
          name: r.name,
          auth_type: r.auth_type,
          auth_value: r.auth_value,
          resources: {
            user_ids: r.resources.user_ids.split(',').map(s => s.trim()).filter(Boolean),
            order_ids: r.resources.order_ids.split(',').map(s => s.trim()).filter(Boolean),
            product_ids: r.resources.product_ids.split(',').map(s => s.trim()).filter(Boolean)
          }
        }))
      };

      if (discoveryMode === 'manual') {
        config.discovery.endpoints = endpoints;
      } else {
        if (!specContent.trim()) {
          throw new Error("Please upload or paste an OpenAPI JSON specification file.");
        }
        try {
          config.discovery.spec = JSON.parse(specContent);
        } catch(err) {
          throw new Error("Invalid JSON in spec content. Please ensure it is valid JSON.");
        }
      }

      const res = await startScan(config);
      navigate(`/scans/${res.data.scan_id}`);
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 pb-12">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">New BOLA/IDOR Security Scan</h1>
          <p className="text-sm text-gray-500 mt-1">Configure target endpoint discovery, select specific test categories, and set role credentials.</p>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 text-red-700 p-4 rounded-lg border border-red-200 flex items-start gap-2">
          <Info className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-8">
        {/* Section 1: Target */}
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold mb-4 text-gray-900 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 text-xs font-bold flex items-center justify-center">1</span>
            Target Configuration
          </h2>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target Base URL</label>
            <input 
              type="url" 
              required
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
              value={targetUrl} 
              onChange={e => setTargetUrl(e.target.value)} 
              placeholder="http://localhost:5001" 
            />
            <p className="text-xs text-gray-500 mt-1.5">For local demo apps: http://localhost:5001 (before-fix) or http://localhost:5002 (after-fix)</p>
          </div>
        </section>

        {/* Section 2: Scan Depth & Speed Controller */}
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 text-xs font-bold flex items-center justify-center">2</span>
              Scan Depth & Request Volume
            </h2>
            <span className="text-xs bg-indigo-100 text-indigo-800 font-semibold px-2 py-0.5 rounded-full">
              Pillar 0 Controller
            </span>
          </div>
          <p className="text-xs text-gray-500 mb-4">
            Controls role permutation width, object discovery, and state mutation verification to throttle execution duration.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              {
                id: 'quick',
                label: '⚡ Quick (~15-25 req)',
                time: '~20-30 seconds',
                badge: 'Recommended for Demos',
                badgeColor: 'bg-emerald-100 text-emerald-800 border-emerald-200',
                desc: 'Single role pair cross-check, first ID per resource, rapid BOLA detection with Differential Analysis.',
              },
              {
                id: 'standard',
                label: '🎯 Standard (~40-60 req)',
                time: '~1-2 minutes',
                badge: 'Autonomous Canaries',
                badgeColor: 'bg-blue-100 text-blue-800 border-blue-200',
                desc: 'Cross-role pairs, autonomous canary provisioning, full differential tree similarity scoring.',
              },
              {
                id: 'deep',
                label: '🔬 Deep (~80-120 req)',
                time: '~3-4 minutes',
                badge: 'Mutation Verified',
                badgeColor: 'bg-purple-100 text-purple-800 border-purple-200',
                desc: 'Exhaustive role permutations, live state mutation verification, boundary fuzzing, full ACM graph.',
              },
            ].map((d) => (
              <div
                key={d.id}
                onClick={() => setScanDepth(d.id)}
                className={`p-4 rounded-xl border-2 cursor-pointer transition-all ${
                  scanDepth === d.id
                    ? 'border-indigo-600 bg-indigo-50/40 shadow-xs ring-1 ring-indigo-500'
                    : 'border-gray-200 hover:border-gray-300 bg-white'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-sm text-gray-900">{d.label}</span>
                  <input
                    type="radio"
                    name="scanDepthRadio"
                    checked={scanDepth === d.id}
                    onChange={() => setScanDepth(d.id)}
                    className="text-indigo-600 focus:ring-indigo-500"
                  />
                </div>
                <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded-full border mb-2 ${d.badgeColor}`}>
                  {d.badge} • {d.time}
                </span>
                <p className="text-xs text-gray-600 leading-relaxed">{d.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Section 3: Discovery */}
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <h2 className="text-lg font-semibold mb-4 text-gray-900 flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 text-xs font-bold flex items-center justify-center">3</span>
            Endpoint Discovery
          </h2>
          <div className="flex gap-4 mb-6">
            {['openapi', 'manual', 'postman'].map(mode => (
              <label key={mode} className="flex items-center gap-2 cursor-pointer">
                <input 
                  type="radio" 
                  name="discoveryMode" 
                  value={mode}
                  checked={discoveryMode === mode}
                  onChange={() => setDiscoveryMode(mode)}
                  className="text-indigo-600 focus:ring-indigo-500 h-4 w-4"
                />
                <span className="capitalize font-medium text-sm text-gray-700">{mode === 'openapi' ? 'OpenAPI JSON (Recommended)' : mode}</span>
              </label>
            ))}
          </div>

          {discoveryMode === 'manual' ? (
            <div className="space-y-4">
              {endpoints.map((ep, idx) => (
                <div key={idx} className="flex gap-3 items-start bg-gray-50 p-3 rounded-lg border border-gray-200">
                  <div className="flex-1">
                    <input 
                      type="text" 
                      placeholder="/api/orders/{id}" 
                      required
                      value={ep.path} 
                      onChange={e => updateEndpoint(idx, 'path', e.target.value)}
                      className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                    />
                  </div>
                  <div className="w-28">
                    <select 
                      value={ep.method} 
                      onChange={e => updateEndpoint(idx, 'method', e.target.value)}
                      className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                    >
                      {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
                        <option key={m} value={m}>{m}</option>
                      ))}
                    </select>
                  </div>
                  <div className="flex items-center pt-2">
                    <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
                      <input 
                        type="checkbox" 
                        checked={ep.requires_auth}
                        onChange={e => updateEndpoint(idx, 'requires_auth', e.target.checked)}
                        className="rounded text-indigo-600 focus:ring-indigo-500 h-4 w-4"
                      />
                      Auth Req
                    </label>
                  </div>
                  <button type="button" onClick={() => removeEndpoint(idx)} className="p-2 text-red-500 hover:bg-red-50 rounded">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}
              <button 
                type="button" 
                onClick={addEndpoint}
                className="flex items-center gap-2 text-sm text-indigo-600 font-medium hover:text-indigo-800"
              >
                <Plus className="w-4 h-4" /> Add Endpoint
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center justify-center w-full">
                <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-indigo-200 border-dashed rounded-lg cursor-pointer bg-indigo-50/40 hover:bg-indigo-50 transition-colors">
                  <div className="flex flex-col items-center justify-center pt-5 pb-6">
                    <UploadCloud className="w-8 h-8 mb-2 text-indigo-600" />
                    <p className="mb-1 text-sm text-gray-700"><span className="font-semibold">Click to upload openapi.json</span></p>
                    <p className="text-xs text-gray-500">Located in demo-apps/before-fix/openapi.json or after-fix</p>
                  </div>
                  <input type="file" className="hidden" accept=".json" onChange={handleFileUpload} />
                </label>
              </div>
              <textarea
                value={specContent}
                onChange={e => setSpecContent(e.target.value)}
                placeholder="Or paste JSON specification here directly..."
                className="w-full h-36 p-3 font-mono text-xs border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none"
              />
            </div>
          )}
        </section>

        {/* Section 3: Test Selection / Categorization */}
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                <span className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 text-xs font-bold flex items-center justify-center">3</span>
                Test Selection (Separate Test Types)
              </h2>
              <p className="text-xs text-gray-500 mt-0.5">
                Choose which kinds of tests to execute. Running only relevant tests saves significant time.
              </p>
            </div>
            <div className="text-xs font-semibold px-2.5 py-1 bg-indigo-50 text-indigo-700 rounded-full shrink-0 border border-indigo-200 self-start sm:self-auto">
              {selectedModules.length} of {ALL_MODULE_IDS.length} tests active
            </div>
          </div>

          {/* Quick Presets */}
          <div className="mb-6 bg-gray-50 p-4 rounded-xl border border-gray-200">
            <span className="text-xs font-bold uppercase tracking-wider text-gray-500 block mb-2.5">Quick Presets</span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {PRESETS.map((p) => {
                const isActive = p.modules.length === selectedModules.length && p.modules.every(id => selectedModules.includes(id));
                return (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => applyPreset(p.modules)}
                    className={`text-left p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                      isActive
                        ? 'border-indigo-600 bg-indigo-50/80 ring-2 ring-indigo-500/20'
                        : 'border-gray-200 bg-white hover:border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    <div className="font-semibold text-gray-900 mb-1">{p.label}</div>
                    <div className="text-gray-500 text-[11px] leading-relaxed">{p.description}</div>
                  </button>
                );
              })}
            </div>
            <div className="mt-3 flex justify-end gap-3 text-xs">
              <button 
                type="button" 
                onClick={() => setSelectedModules(ALL_MODULE_IDS)}
                className="text-indigo-600 hover:text-indigo-800 font-medium cursor-pointer"
              >
                Select All
              </button>
              <span className="text-gray-300">|</span>
              <button 
                type="button" 
                onClick={() => setSelectedModules([])}
                className="text-gray-500 hover:text-gray-800 font-medium cursor-pointer"
              >
                Deselect All
              </button>
            </div>
          </div>

          {/* Categories & Individual Checkboxes */}
          <div className="space-y-5">
            {TEST_CATEGORIES.map((cat) => {
              const catModuleIds = cat.modules.map(m => m.id);
              const allCatSelected = catModuleIds.every(id => selectedModules.includes(id));

              return (
                <div key={cat.id} className="border border-gray-200 rounded-xl overflow-hidden bg-white">
                  <div className="bg-gray-50 px-4 py-3 border-b border-gray-200 flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold text-gray-900">{cat.name}</h3>
                      <p className="text-xs text-gray-500">{cat.description}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => toggleCategory(cat)}
                      className="text-xs font-medium text-indigo-600 hover:text-indigo-800 bg-white px-2.5 py-1 border border-gray-200 rounded shadow-2xs shrink-0 ml-3 cursor-pointer"
                    >
                      {allCatSelected ? 'Deselect Category' : 'Select Category'}
                    </button>
                  </div>

                  <div className="divide-y divide-gray-100">
                    {cat.modules.map((mod) => {
                      const isChecked = selectedModules.includes(mod.id);
                      return (
                        <label
                          key={mod.id}
                          className={`flex items-start gap-3 p-4 cursor-pointer transition-colors ${
                            isChecked ? 'bg-indigo-50/20 hover:bg-indigo-50/40' : 'bg-white hover:bg-gray-50'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => toggleModule(mod.id)}
                            className="mt-1 h-4 w-4 rounded text-indigo-600 focus:ring-indigo-500 border-gray-300"
                          />
                          <div className="flex-1">
                            <div className="flex flex-wrap items-center gap-2 mb-1">
                              <span className="font-semibold text-sm text-gray-900">{mod.name}</span>
                              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${mod.badgeColor}`}>
                                {mod.badge}
                              </span>
                              <span className="text-[10px] text-gray-400 font-mono">
                                • {mod.speed}
                              </span>
                            </div>
                            <p className="text-xs text-gray-600 leading-relaxed">{mod.purpose}</p>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Section 4: Roles & Resources */}
        <section className="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
          <div className="flex justify-between items-center mb-2">
            <h2 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
              <span className="w-6 h-6 rounded-full bg-indigo-50 text-indigo-600 text-xs font-bold flex items-center justify-center">4</span>
              Roles & Known Resources
            </h2>
            <button 
              type="button" 
              onClick={addRole}
              className="flex items-center gap-1 text-sm bg-indigo-50 text-indigo-700 px-3 py-1.5 rounded hover:bg-indigo-100 transition-colors"
            >
              <Plus className="w-4 h-4" /> Add Role
            </button>
          </div>
          <p className="text-sm text-gray-500 mb-6">Provide at least 2 roles and their known resource IDs to test cross-user access (BOLA).</p>

          <div className="space-y-6">
            {roles.map((role, idx) => (
              <div key={idx} className="bg-gray-50 p-5 rounded-lg border border-gray-200 relative">
                {roles.length > 2 && (
                  <button type="button" onClick={() => removeRole(idx)} className="absolute top-4 right-4 p-1.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Role Name</label>
                    <input 
                      type="text" 
                      required
                      value={role.name} 
                      onChange={e => updateRole(idx, 'name', e.target.value)}
                      placeholder="e.g. Admin, UserA, UserB"
                      className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">Auth Type</label>
                    <select 
                      value={role.auth_type} 
                      onChange={e => updateRole(idx, 'auth_type', e.target.value)}
                      className="w-full px-3 py-2 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                    >
                      <option value="bearer">Bearer Token</option>
                      <option value="cookie">Cookie</option>
                      <option value="apikey">API Key</option>
                    </select>
                  </div>
                </div>
                
                <div className="mb-4">
                  <label className="block text-xs font-medium text-gray-700 mb-1">Auth Value (Token / JWT)</label>
                  <textarea 
                    required
                    value={role.auth_value} 
                    onChange={e => updateRole(idx, 'auth_value', e.target.value)}
                    rows={2}
                    placeholder="eyJhbGciOiJIUzI1NiIsIn..."
                    className="w-full px-3 py-2 text-sm font-mono border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                  />
                </div>

                <div className="pt-4 border-t border-gray-200">
                  <h4 className="text-sm font-medium text-gray-800 mb-3">Known Resource IDs Owned By This Role (comma separated)</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <label className="block text-xs text-gray-600 mb-1">User IDs</label>
                      <input 
                        type="text" 
                        value={role.resources.user_ids} 
                        onChange={e => updateRoleResources(idx, 'user_ids', e.target.value)}
                        placeholder="1"
                        className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-600 mb-1">Order IDs</label>
                      <input 
                        type="text" 
                        value={role.resources.order_ids} 
                        onChange={e => updateRoleResources(idx, 'order_ids', e.target.value)}
                        placeholder="1, 2"
                        className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-600 mb-1">Product IDs</label>
                      <input 
                        type="text" 
                        value={role.resources.product_ids} 
                        onChange={e => updateRoleResources(idx, 'product_ids', e.target.value)}
                        placeholder="1, 2"
                        className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded focus:ring-2 focus:ring-indigo-500 outline-none"
                      />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <div className="flex justify-between items-center pt-2">
          <div className="text-sm text-gray-500">
            {selectedModules.length === 0 ? (
              <span className="text-red-500 font-medium">⚠️ No test categories selected</span>
            ) : (
              <span>Ready to run <strong>{selectedModules.length}</strong> test categories</span>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || selectedModules.length === 0}
            className={`flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white font-medium rounded-lg shadow-sm hover:bg-indigo-700 transition-colors focus:ring-4 focus:ring-indigo-200 cursor-pointer ${
              loading || selectedModules.length === 0 ? 'opacity-70 cursor-not-allowed' : ''
            }`}
          >
            {loading ? <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" /> : <Play className="w-5 h-5" />}
            Start Scan
          </button>
        </div>
      </form>
    </div>
  );
};

export default ScanConfig;

