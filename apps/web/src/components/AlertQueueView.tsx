import React, { useState } from 'react';
import { Search, Filter, Play } from 'lucide-react';

interface AlertQueueViewProps {
  alerts: any[];
  onTriageAlert: (alertPayload: any) => void;
  isLoading: boolean;
}

export const AlertQueueView: React.FC<AlertQueueViewProps> = ({ alerts, onTriageAlert, isLoading }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filtered = alerts.filter((a) => {
    const matchesSearch = a.signature.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (a.source_format && a.source_format.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesSeverity = filterSeverity === 'ALL' || a.severity.toUpperCase() === filterSeverity;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900/80 border border-gray-800">
        <div className="flex items-center gap-2 flex-1 max-w-md bg-gray-950 px-3 py-2 rounded-lg border border-gray-800 focus-within:border-blue-600 transition-colors">
          <Search className="h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts by signature, source format..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none text-sm text-white placeholder-gray-500 focus:outline-none w-full"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-400" />
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-gray-950 border border-gray-800 text-sm text-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:border-blue-600"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      <div className="rounded-xl border border-gray-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-gray-300">
            <thead className="bg-gray-950/80 text-xs uppercase font-mono text-gray-400 border-b border-gray-800">
              <tr>
                <th className="px-5 py-3.5">Severity</th>
                <th className="px-5 py-3.5">Alert Signature</th>
                <th className="px-5 py-3.5">Source SIEM</th>
                <th className="px-5 py-3.5">Triage Verdict</th>
                <th className="px-5 py-3.5">Trust Score</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {filtered.map((alert, idx) => {
                const isCritical = alert.severity.toLowerCase() === 'critical';
                const isHigh = alert.severity.toLowerCase() === 'high';
                return (
                  <tr key={idx} className="hover:bg-gray-800/40 transition-colors">
                    <td className="px-5 py-4 whitespace-nowrap">
                      <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase ${
                        isCritical
                          ? 'bg-red-900/50 text-red-300 border border-red-700/50'
                          : isHigh
                          ? 'bg-orange-900/50 text-orange-300 border border-orange-700/50'
                          : 'bg-blue-900/50 text-blue-300 border border-blue-700/50'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="font-semibold text-white">{alert.signature}</div>
                      <div className="text-xs text-gray-400 font-mono mt-0.5">{alert.incident_id || alert.id || 'Pending Triage'}</div>
                    </td>
                    <td className="px-5 py-4 whitespace-nowrap">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300">
                        {alert.source_format || 'Splunk / Wazuh'}
                      </span>
                    </td>
                    <td className="px-5 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 text-xs font-semibold ${
                        alert.overall_verdict === 'malicious' ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        <span className={`h-2 w-2 rounded-full ${
                          alert.overall_verdict === 'malicious' ? 'bg-red-500' : 'bg-emerald-500'
                        }`} />
                        {alert.overall_verdict ? alert.overall_verdict.toUpperCase() : 'QUEUED'}
                      </span>
                    </td>
                    <td className="px-5 py-4 whitespace-nowrap font-mono">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold ${
                          alert.trust_score !== undefined && alert.trust_score >= 0.50
                            ? 'text-emerald-400'
                            : 'text-cyan-400'
                        }`}>
                          {alert.trust_score !== undefined ? alert.trust_score.toFixed(3) : '—'}
                        </span>
                        {alert.trust_score !== undefined && alert.trust_score >= 0.50 && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-sans font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 uppercase">
                            AUTO-PASSED
                          </span>
                        )}
                        {alert.trust_score !== undefined && alert.trust_score < 0.50 && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-sans font-bold bg-amber-950/80 text-amber-300 border border-amber-700/60 uppercase">
                            ESCALATED
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => onTriageAlert(alert.raw_payload || alert)}
                        disabled={isLoading}
                        className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-all hover:scale-105 disabled:opacity-50"
                      >
                        <Play className="h-3.5 w-3.5" />
                        <span>{alert.trust_score !== undefined ? 'Re-Triage' : 'Run Triage'}</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
