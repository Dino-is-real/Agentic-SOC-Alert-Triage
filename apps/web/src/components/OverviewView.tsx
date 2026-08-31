import React from 'react';
import { ShieldCheck, AlertTriangle, Clock, Cpu, ArrowRight, ShieldAlert, Sparkles } from 'lucide-react';
import { InvestigationDossier } from '../types';

interface OverviewViewProps {
  metrics: any;
  latestIncident: InvestigationDossier | null;
  onViewIncident: () => void;
  onSimulateNewAlert: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  metrics,
  latestIncident,
  onViewIncident,
  onSimulateNewAlert,
}) => {
  const cards = [
    {
      title: 'Total Triaged Incidents',
      value: metrics?.total_incidents_triaged ?? 142,
      change: '+18% today',
      icon: ShieldCheck,
      color: 'text-blue-400',
      bg: 'bg-blue-900/20 border-blue-800/40',
    },
    {
      title: 'Auto-Suggested (T ≥ 0.65)',
      value: metrics?.auto_suggest_count ?? 89,
      change: '62.7% auto-suggest rate',
      icon: Sparkles,
      color: 'text-emerald-400',
      bg: 'bg-emerald-900/20 border-emerald-800/40',
    },
    {
      title: 'Human Escalations (T < 0.65)',
      value: metrics?.escalated_count ?? 53,
      change: '37.3% analyst escalation',
      icon: AlertTriangle,
      color: 'text-amber-400',
      bg: 'bg-amber-900/20 border-amber-800/40',
    },
    {
      title: 'Mean Triage Latency',
      value: `${metrics?.mean_latency_ms ?? 2.1}s`,
      change: '-94% vs human baseline (45m)',
      icon: Clock,
      color: 'text-cyan-400',
      bg: 'bg-cyan-900/20 border-cyan-800/40',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Ingest Action */}
      <div className="flex flex-col md:flex-row md:items-center justify-between p-6 rounded-xl bg-gradient-to-r from-blue-900/30 via-slate-900 to-indigo-900/30 border border-blue-800/50 shadow-xl">
        <div className="space-y-1">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span>Adaptive SOC Operations Command</span>
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">
              Live Monitoring
            </span>
          </h2>
          <p className="text-sm text-gray-300 max-w-2xl">
            Autonomous multi-agent alert triage powered by calibrated multi-label routing, pgvector historical memory, and deterministic Trust Score Gate 03.
          </p>
        </div>
        <div className="mt-4 md:mt-0 flex space-x-3">
          <button
            onClick={onSimulateNewAlert}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-lg font-medium text-sm bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg shadow-blue-600/30 transition-all hover:scale-[1.02]"
          >
            <ShieldAlert className="h-4 w-4" />
            <span>Ingest Test Attack Alert</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div key={idx} className={`p-5 rounded-xl border ${card.bg} transition-all hover:border-opacity-60`}>
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">{card.title}</span>
                <Icon className={`h-5 w-5 ${card.color}`} />
              </div>
              <div className="mt-3">
                <span className="text-2xl font-bold text-white tracking-tight">{card.value}</span>
                <p className="text-xs text-gray-400 mt-1">{card.change}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Latest Triaged Incident Spotlight */}
      {latestIncident && (
        <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-semibold text-white flex items-center gap-2">
              <Cpu className="h-5 w-5 text-blue-400" />
              <span>Latest Investigation Dossier Spotlight</span>
            </h3>
            <button
              onClick={onViewIncident}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-medium transition-colors"
            >
              <span>View Full Dossier</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-1">
              <span className="text-xs text-gray-400">Signature</span>
              <p className="font-semibold text-sm text-gray-100 truncate">{latestIncident.normalized_alert.signature}</p>
              <div className="flex items-center gap-2 pt-1">
                <span className="text-xs px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800/40 uppercase font-mono">
                  {latestIncident.normalized_alert.raw_severity}
                </span>
                <span className="text-xs text-gray-400 font-mono">{latestIncident.normalized_alert.source_format}</span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-1">
              <span className="text-xs text-gray-400">Specialist Consensus</span>
              <p className="font-semibold text-sm text-gray-100 flex items-center gap-2">
                <span className={`h-2.5 w-2.5 rounded-full ${latestIncident.consensus_assessment.overall_verdict === 'malicious' ? 'bg-red-500' : 'bg-amber-500'}`} />
                <span className="capitalize">{latestIncident.consensus_assessment.overall_verdict}</span>
                <span className="text-xs text-gray-400 font-mono">({Math.round(latestIncident.consensus_assessment.consensus_score * 100)}% agreement)</span>
              </p>
              <p className="text-xs text-gray-400 pt-1">
                Active Agents: {latestIncident.routing_decision.selected_domains.join(', ')}
              </p>
            </div>

            <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-1">
              <span className="text-xs text-gray-400">Trust Score (Gate 03)</span>
              <div className="flex items-center gap-3 pt-0.5">
                <span className="text-xl font-bold font-mono text-cyan-400">
                  {latestIncident.trust_assessment.trust_score.toFixed(3)}
                </span>
                <span className={`text-xs px-2.5 py-0.5 rounded-full font-semibold ${
                  latestIncident.trust_assessment.decision === 'AUTO_SUGGEST'
                    ? 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/50'
                    : 'bg-amber-900/50 text-amber-300 border border-amber-700/50'
                }`}>
                  {latestIncident.trust_assessment.decision}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 truncate">
                {latestIncident.trust_assessment.reason_codes.join(', ')}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
