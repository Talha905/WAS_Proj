import React, { useState, useMemo } from 'react';
import StatusBadge from './StatusBadge';
import EndpointDetail from './EndpointDetail';
import { Search, Filter, X } from 'lucide-react';

const ResultsTable = ({ scan }) => {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterVerdict, setFilterVerdict] = useState('ALL');
  const [searchPath, setSearchPath] = useState('');
  const [page, setPage] = useState(1);
  const [selectedResult, setSelectedResult] = useState(null);

  const ITEMS_PER_PAGE = 20;
  const results = scan.results || [];

  const filteredData = useMemo(() => {
    return results.filter(r => {
      const matchSev = filterSeverity === 'ALL' || r.severity === filterSeverity;
      const matchVer = filterVerdict === 'ALL' || r.verdict === filterVerdict;
      const matchPath = r.endpoint.toLowerCase().includes(searchPath.toLowerCase());
      return matchSev && matchVer && matchPath;
    });
  }, [results, filterSeverity, filterVerdict, searchPath]);

  const totalPages = Math.ceil(filteredData.length / ITEMS_PER_PAGE);
  const currentData = filteredData.slice((page - 1) * ITEMS_PER_PAGE, page * ITEMS_PER_PAGE);

  const clearFilters = () => {
    setFilterSeverity('ALL');
    setFilterVerdict('ALL');
    setSearchPath('');
    setPage(1);
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 flex flex-col">
      <div className="p-4 border-b border-gray-200 flex flex-col sm:flex-row sm:items-center gap-4 bg-gray-50 rounded-t-xl">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-gray-400" />
          <input 
            type="text" 
            placeholder="Search endpoint path..." 
            value={searchPath}
            onChange={(e) => { setSearchPath(e.target.value); setPage(1); }}
            className="w-full pl-9 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 outline-none"
          />
        </div>
        <div className="flex items-center gap-3">
          <Filter className="w-4 h-4 text-gray-400" />
          <select 
            value={filterVerdict}
            onChange={(e) => { setFilterVerdict(e.target.value); setPage(1); }}
            className="border border-gray-300 rounded-lg py-2 px-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"
          >
            <option value="ALL">All Verdicts</option>
            <option value="NEEDS_FIX">Needs Fix</option>
            <option value="PASSES">Passes</option>
            <option value="INCONCLUSIVE">Inconclusive</option>
          </select>
          <select 
            value={filterSeverity}
            onChange={(e) => { setFilterSeverity(e.target.value); setPage(1); }}
            className="border border-gray-300 rounded-lg py-2 px-3 text-sm focus:ring-2 focus:ring-indigo-500 outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
          {(filterSeverity !== 'ALL' || filterVerdict !== 'ALL' || searchPath !== '') && (
            <button onClick={clearFilters} className="text-gray-500 hover:text-gray-700 p-2" title="Clear filters">
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Endpoint</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Module</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Verdict</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Code (Exp / Act)</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Action</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {currentData.length === 0 ? (
              <tr><td colSpan="6" className="px-6 py-8 text-center text-gray-500">No results match your filters.</td></tr>
            ) : (
              currentData.map((r, idx) => (
                <tr key={idx} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap"><StatusBadge type="severity" value={r.severity} /></td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
                    <div className="flex items-center gap-2">
                      <StatusBadge type="method" value={r.method} />
                      <span className="truncate max-w-[200px] lg:max-w-xs block" title={r.endpoint}>{r.endpoint}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div>{r.module}</div>
                    {r.similarity_score !== null && r.similarity_score !== undefined && (
                      <span className="inline-block mt-0.5 px-1.5 py-0.2 rounded text-[10px] font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {Math.round(r.similarity_score * 100)}% Sim
                      </span>
                    )}
                    {r.mutation_verified === 1 && (
                      <span className="inline-block ml-1 mt-0.5 px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-100 text-red-800">
                        💥 Tampered
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <StatusBadge type="verdict" value={r.verdict} />
                    {r.poe_curl && (
                      <span className="ml-1.5 inline-block text-[10px] font-bold text-slate-700 bg-slate-100 border border-slate-300 px-1 py-0.2 rounded">
                        PoE Ready
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                    {r.expected_status || '-'} / <span className={r.actual_status >= 400 ? 'text-red-500' : 'text-green-500'}>{r.actual_status || '-'}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button 
                      onClick={() => setSelectedResult(r)}
                      className="text-indigo-600 hover:text-indigo-900 text-sm font-medium px-3 py-1 rounded hover:bg-indigo-50 transition-colors cursor-pointer"
                    >
                      Inspect & PoE
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between bg-gray-50 rounded-b-xl">
          <span className="text-sm text-gray-700">Showing {((page - 1) * ITEMS_PER_PAGE) + 1} to {Math.min(page * ITEMS_PER_PAGE, filteredData.length)} of {filteredData.length}</span>
          <div className="flex gap-2">
            <button 
              disabled={page === 1}
              onClick={() => setPage(p => p - 1)}
              className="px-3 py-1 border border-gray-300 rounded bg-white text-sm disabled:opacity-50"
            >
              Prev
            </button>
            <button 
              disabled={page === totalPages}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1 border border-gray-300 rounded bg-white text-sm disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {selectedResult && (
        <EndpointDetail result={selectedResult} onClose={() => setSelectedResult(null)} />
      )}
    </div>
  );
};

export default ResultsTable;
