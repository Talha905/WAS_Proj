import React from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';

const COLORS = {
  NEEDS_FIX: '#ef4444',
  PASSES: '#22c55e',
  INCONCLUSIVE: '#f59e0b',
  HIGH: '#ef4444',
  MEDIUM: '#f97316',
  LOW: '#eab308',
  INFO: '#3b82f6'
};

const SummaryCharts = ({ results = [] }) => {
  if (!results.length) return null;

  // Pie chart data
  const verdictCounts = results.reduce((acc, r) => {
    acc[r.verdict] = (acc[r.verdict] || 0) + 1;
    return acc;
  }, {});
  
  const pieData = Object.keys(verdictCounts).map(key => ({
    name: key,
    value: verdictCounts[key]
  }));

  // Bar chart data (Severities)
  const sevCounts = results.reduce((acc, r) => {
    if (r.verdict === 'NEEDS_FIX') {
      acc[r.severity] = (acc[r.severity] || 0) + 1;
    }
    return acc;
  }, { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });

  const sevData = [
    { name: 'HIGH', count: sevCounts.HIGH },
    { name: 'MEDIUM', count: sevCounts.MEDIUM },
    { name: 'LOW', count: sevCounts.LOW },
    { name: 'INFO', count: sevCounts.INFO },
  ].filter(d => d.count > 0);

  // Top endpoints by NEEDS_FIX
  const epCounts = results.reduce((acc, r) => {
    if (r.verdict === 'NEEDS_FIX') {
      acc[r.endpoint] = (acc[r.endpoint] || 0) + 1;
    }
    return acc;
  }, {});
  
  const epData = Object.entries(epCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ep, count]) => ({ endpoint: ep, count }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
      <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
        <h3 className="text-sm font-semibold text-gray-700 mb-4 text-center">Verdict Distribution</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip formatter={(value, name) => [value, name]} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
        <h3 className="text-sm font-semibold text-gray-700 mb-4 text-center">Vulnerabilities by Severity</h3>
        <div className="h-64">
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} />
                <XAxis type="number" />
                <YAxis type="category" dataKey="name" tick={{fontSize: 12}} />
                <Tooltip />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {sevData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-400 text-sm">No vulnerabilities found</div>
          )}
        </div>
      </div>

      <div className="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
        <h3 className="text-sm font-semibold text-gray-700 mb-4 text-center">Top Endpoints (Vulnerable)</h3>
        <div className="h-64">
          {epData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={epData} layout="vertical" margin={{ top: 5, right: 30, left: 10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} />
                <XAxis type="number" />
                <YAxis type="category" dataKey="endpoint" width={80} tick={{fontSize: 10}} tickFormatter={(val) => val.length > 15 ? val.substring(0,15)+'...' : val} />
                <Tooltip />
                <Bar dataKey="count" fill={COLORS.NEEDS_FIX} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-gray-400 text-sm">No vulnerabilities found</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SummaryCharts;
