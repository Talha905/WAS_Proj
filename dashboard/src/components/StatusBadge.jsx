import React from 'react';

const StatusBadge = ({ type, value }) => {
  let bg = 'bg-gray-100';
  let text = 'text-gray-800';
  let pulse = false;

  const v = (value || '').toUpperCase();

  if (type === 'verdict') {
    if (v === 'NEEDS_FIX') { bg = 'bg-red-100'; text = 'text-red-800'; }
    else if (v === 'PASSES') { bg = 'bg-green-100'; text = 'text-green-800'; }
    else if (v === 'INCONCLUSIVE') { bg = 'bg-yellow-100'; text = 'text-yellow-800'; }
  } else if (type === 'severity') {
    if (v === 'HIGH') { bg = 'bg-red-100'; text = 'text-red-800'; }
    else if (v === 'MEDIUM') { bg = 'bg-orange-100'; text = 'text-orange-800'; }
    else if (v === 'LOW') { bg = 'bg-yellow-100'; text = 'text-yellow-800'; }
    else if (v === 'INFO') { bg = 'bg-blue-100'; text = 'text-blue-800'; }
  } else if (type === 'status') {
    if (v === 'RUNNING') { bg = 'bg-blue-100'; text = 'text-blue-800'; pulse = true; }
    else if (v === 'COMPLETE') { bg = 'bg-green-100'; text = 'text-green-800'; }
    else if (v === 'ERROR') { bg = 'bg-red-100'; text = 'text-red-800'; }
    else if (v === 'CANCELLED' || v === 'STOPPED') { bg = 'bg-amber-100'; text = 'text-amber-800'; }
    else if (v === 'PENDING') { bg = 'bg-gray-200'; text = 'text-gray-700'; }
  } else if (type === 'method') {
    if (v === 'GET') { bg = 'bg-blue-100'; text = 'text-blue-800'; }
    else if (v === 'POST') { bg = 'bg-green-100'; text = 'text-green-800'; }
    else if (v === 'PUT') { bg = 'bg-yellow-100'; text = 'text-yellow-800'; }
    else if (v === 'DELETE') { bg = 'bg-red-100'; text = 'text-red-800'; }
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${bg} ${text} ${pulse ? 'animate-pulse' : ''}`}>
      {pulse && <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mr-1.5 animate-ping"></span>}
      {value}
    </span>
  );
};

export default StatusBadge;
