import React from 'react';
import { Calculator, ShieldAlert, CheckCircle2 } from 'lucide-react';
import { TrustAssessment } from '../types';

interface TrustExplainabilityPanelProps {
  assessment: TrustAssessment;
}

export const TrustExplainabilityPanel: React.FC<TrustExplainabilityPanelProps> = ({ assessment }) => {
  const { components, trust_score, threshold, decision, reason_codes, calculation_version } = assessment;

  const isAutoSuggest = decision === 'AUTO_SUGGEST';

  return (
    <div className="p-6 rounded-xl bg-slate-900/90 border border-blue-900/40 shadow-2xl space-y-6">
      {/* Header with Result */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-gray-800 gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Calculator className="h-5 w-5 text-cyan-400" />
            <h3 className="text-lg font-bold text-white tracking-tight">
              Deterministic Trust Score Engine (Gate 03)
            </h3>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400">
              {calculation_version}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Formula: <code className="text-cyan-300 font-mono">T = clamp[ (0.50 × C_consensus) + (0.30 × H) − (0.20 × S_penalty) ]</code>
          </p>
        </div>

        <div className="flex items-center space-x-4">
          <div className="text-right">
            <span className="text-xs font-semibold text-gray-400 block uppercase">Calculated Score T</span>
            <span className="text-3xl font-extrabold font-mono text-cyan-400 tracking-tight">
              {trust_score.toFixed(3)}
            </span>
          </div>

          <div className={`px-4 py-2 rounded-lg border font-bold text-sm flex items-center space-x-2 ${
            isAutoSuggest
              ? 'bg-emerald-950/80 text-emerald-300 border-emerald-700/60'
              : 'bg-amber-950/80 text-amber-300 border-amber-700/60'
          }`}>
            {isAutoSuggest ? (
              <>
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>AUTO-SUGGEST PLAYBOOK (T ≥ {threshold})</span>
              </>
            ) : (
              <>
                <ShieldAlert className="h-4 w-4 text-amber-400" />
                <span>ESCALATE TO HUMAN (T &lt; {threshold})</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 3 Component Breakdown Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Consensus Score Component */}
        <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span className="font-semibold uppercase tracking-wider">1. Agent Consensus (wC = 0.50)</span>
            <span className="font-mono text-blue-400">C = {components.consensus_score.toFixed(3)}</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-blue-600 to-cyan-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${components.consensus_score * 100}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-400 pt-1">
            <span>Weighted Contribution:</span>
            <span className="font-mono font-bold text-white">+{components.weighted_consensus.toFixed(3)}</span>
          </div>
        </div>

        {/* Historical Precedent Component */}
        <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span className="font-semibold uppercase tracking-wider">2. Vector Precedent (wH = 0.30)</span>
            <span className="font-mono text-indigo-400">H = {components.historical_similarity.toFixed(3)}</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-indigo-600 to-purple-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${components.historical_similarity * 100}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-400 pt-1">
            <span>Weighted Contribution:</span>
            <span className="font-mono font-bold text-white">+{components.weighted_historical.toFixed(3)}</span>
          </div>
        </div>

        {/* Severity Penalty Component */}
        <div className="p-4 rounded-lg bg-gray-950/60 border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span className="font-semibold uppercase tracking-wider">3. Asset Penalty (wS = 0.20)</span>
            <span className="font-mono text-rose-400">S = {components.severity_penalty.toFixed(3)}</span>
          </div>
          <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
            <div
              className="bg-gradient-to-r from-orange-500 to-rose-600 h-full rounded-full transition-all duration-500"
              style={{ width: `${components.severity_penalty * 100}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-gray-400 pt-1">
            <span>Subtracted Penalty:</span>
            <span className="font-mono font-bold text-rose-400">−{components.weighted_penalty.toFixed(3)}</span>
          </div>
        </div>
      </div>

      {/* Reason Codes Breakdown */}
      <div className="p-4 rounded-lg bg-gray-950/40 border border-gray-800/80 space-y-2">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
          Triggered Diagnostic Reason Codes
        </span>
        <div className="flex flex-wrap gap-2">
          {reason_codes.map((code, idx) => (
            <span
              key={idx}
              className="text-xs font-mono px-3 py-1 rounded bg-blue-950/60 text-blue-300 border border-blue-800/50"
            >
              {code}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
};
