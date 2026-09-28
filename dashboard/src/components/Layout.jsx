import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, List, Plus } from 'lucide-react';

const Layout = ({ children }) => {
  return (
    <div className="flex h-screen bg-gray-50 font-sans text-gray-900 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-6 flex items-center gap-3 border-b border-gray-800">
          <Shield className="w-8 h-8 text-indigo-400" />
          <span className="text-xl font-bold tracking-wide">BOLA Checker</span>
        </div>
        <nav className="flex-1 px-4 py-6 space-y-2">
          <NavLink
            to="/"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <List className="w-5 h-5" />
            Dashboard
          </NavLink>
          <NavLink
            to="/new"
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                isActive ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <Plus className="w-5 h-5" />
            New Scan
          </NavLink>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto p-8 relative">
        <div className="max-w-6xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
