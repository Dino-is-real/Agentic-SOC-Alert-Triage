import React from 'react';
import { Shield, Activity, ListOrdered, CheckSquare, BarChart3, LineChart } from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  pendingCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({ currentTab, setCurrentTab, pendingCount }) => {
  const navItems = [
    { id: 'overview', label: 'SOC Overview', icon: Activity },
    { id: 'alerts', label: 'Alert Queue', icon: ListOrdered },
    { id: 'investigation', label: 'Investigation Dossier', icon: Shield },
    { id: 'approvals', label: 'Human Approval Gate', icon: CheckSquare, badge: pendingCount },
    { id: 'analytics', label: 'SOC Analytics', icon: LineChart },
    { id: 'benchmarks', label: 'Research Evaluation', icon: BarChart3 },
  ];

  return (
    <header className="border-b border-gray-800 bg-[#0B0F19]/90 sticky top-0 z-50 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <span className="font-bold text-lg text-white tracking-tight flex items-center gap-2">
                Adaptive SOC
                <span className="text-xs px-2 py-0.5 rounded-full bg-blue-900/50 text-blue-400 border border-blue-700/50 font-mono">
                  Trust Gate 03
                </span>
              </span>
              <p className="text-xs text-gray-400">Autonomous Multi-Agent Alert Triage Framework</p>
            </div>
          </div>

          <nav className="flex space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setCurrentTab(item.id)}
                  className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-xs font-bold bg-amber-500 text-black">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          <div className="flex items-center space-x-3">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-semibold text-gray-200">Tier-2 Analyst Console</p>
              <p className="text-[10px] font-mono text-emerald-400">● Engine Active (Gate 03: 0.65)</p>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
