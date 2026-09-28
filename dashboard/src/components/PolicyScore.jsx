import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';

const PolicyScore = ({ score = 100, size = 'md' }) => {
  const numScore = typeof score === 'number' ? Math.max(0, Math.min(100, score)) : 100;

  let grade = 'A';
  let label = 'Rigid Access Control';
  let color = 'text-emerald-600';
  let bgColor = 'bg-emerald-50 border-emerald-200';
  let badgeColor = 'bg-emerald-600';
  let Icon = ShieldCheck;

  if (numScore >= 90) {
    grade = 'A';
    label = 'Strong Authorization Policy';
    color = 'text-emerald-600';
    bgColor = 'bg-emerald-50 border-emerald-200';
    badgeColor = 'bg-emerald-600';
    Icon = ShieldCheck;
  } else if (numScore >= 75) {
    grade = 'B';
    label = 'Minor Authorization Gaps';
    color = 'text-blue-600';
    bgColor = 'bg-blue-50 border-blue-200';
    badgeColor = 'bg-blue-600';
    Icon = ShieldCheck;
  } else if (numScore >= 55) {
    grade = 'C';
    label = 'Object-Level Gaps Present';
    color = 'text-amber-600';
    bgColor = 'bg-amber-50 border-amber-200';
    badgeColor = 'bg-amber-500';
    Icon = ShieldAlert;
  } else {
    grade = 'F';
    label = 'Critical Policy Breaches';
    color = 'text-red-600';
    bgColor = 'bg-red-50 border-red-200';
    badgeColor = 'bg-red-600';
    Icon = ShieldX;
  }

  if (size === 'sm') {
    return (
      <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${bgColor}`}>
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs font-semibold text-gray-700">Policy Score:</span>
        <span className={`text-xs font-bold ${color}`}>{numScore}/100</span>
        <span className={`text-[10px] font-bold text-white px-1.5 py-0.5 rounded ${badgeColor}`}>{grade}</span>
      </div>
    );
  }

  return (
    <div className={`p-4 rounded-xl border ${bgColor} flex items-center justify-between shadow-sm`}>
      <div className="flex items-center gap-4">
        <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${badgeColor} text-white shadow-md`}>
          <Icon className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-bold text-gray-900">Authorization Health Index</h4>
            <span className={`text-xs font-extrabold text-white px-2 py-0.5 rounded-full ${badgeColor}`}>
              Grade {grade}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">{label}</p>
        </div>
      </div>
      <div className="text-right">
        <div className={`text-3xl font-black ${color}`}>{numScore}<span className="text-lg font-medium text-gray-400">/100</span></div>
        <div className="w-24 bg-gray-200 h-1.5 rounded-full mt-1.5 overflow-hidden">
          <div
            className={`h-full rounded-full ${badgeColor}`}
            style={{ width: `${numScore}%` }}
          />
        </div>
      </div>
    </div>
  );
};

export default PolicyScore;
