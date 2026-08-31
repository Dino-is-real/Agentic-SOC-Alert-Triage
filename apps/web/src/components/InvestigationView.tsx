import React, { useState } from 'react';
import { Shield, Network, Terminal, UserCheck, Cloud, Bug, Radio, Zap, History, ChevronDown, ChevronUp, CheckCircle2, Lock, ShieldAlert, Cpu } from 'lucide-react';
import { InvestigationDossier, AgentDomain } from '../types';
import { TrustExplainabilityPanel } from './TrustExplainabilityPanel';
import { RouterInspectionModal } from './RouterInspectionModal';
import { PlaybookSimulationModal } from './PlaybookSimulationModal';

interface InvestigationViewProps {
  dossier: InvestigationDossier | null;
  onApprovePlaybook: (requestId: string) => Promise<any>;
  onRejectPlaybook: (requestId: string) => void;
  isExecuting: boolean;
}

export const InvestigationView: React.FC<InvestigationViewProps> = ({
  dossier,
  onApprovePlaybook,
  onRejectPlaybook,
  isExecuting,
}) => {
  const [inspectingDomain, setInspectingDomain] = useState<AgentDomain | null>(null);
  const [showSimulationModal, setShowSimulationModal] = useState<boolean>(false);
  const [expandedAgents, setExpandedAgents] = useState<Record<string, boolean>>({});

  if (!dossier) {
    return (
      <div className="p-12 rounded-xl bg-slate-900/60 border border-gray-800 text-center space-y-3">
        <Shield className="h-12 w-12 text-gray-500 mx-auto" />
        <h3 className="text-lg font-semibold text-white">No Active Investigation Loaded</h3>
        <p className="text-sm text-gray-400 max-w-md mx-auto">
          Select an alert from the Alert Queue or click "Ingest Test Attack Alert" on the overview to run autonomous multi-agent triage.
        </p>
      </div>
    );
  }

  const { normalized_alert, routing_decision, agent_findings, consensus_assessment, historical_cases, trust_assessment, playbook, approval_request } = dossier;

  const domainIcons: Record<string, any> = {
    network: Network,
    endpoint: Terminal,
    identity: UserCheck,
    cloud: Cloud,
    malware: Bug,
    threat_intel: Radio,
  };

  const toggleAgentExpand = (domain: string) => {
    setExpandedAgents((prev) => ({
      ...prev,
      [domain]: !prev[domain],
    }));
  };

  const isApproved = approval_request.status === 'APPROVED';

  return (
    <div className="space-y-6">
      {/* Active Modal for Inspecting Router Model Decision */}
      {inspectingDomain && (
        <RouterInspectionModal
          domain={inspectingDomain}
          probability={routing_decision.probabilities[inspectingDomain] ?? 0.05}
          threshold={0.50}
          isSelected={routing_decision.selected_domains.includes(inspectingDomain)}
          alert={normalized_alert}
          onClose={() => setInspectingDomain(null)}
        />
      )}

      {/* Active Modal for Running Playbook Simulation */}
      {showSimulationModal && (
        <PlaybookSimulationModal
          playbook={playbook}
          request={approval_request}
          onConfirmApprove={() => onApprovePlaybook(approval_request.request_id)}
          onClose={() => setShowSimulationModal(false)}
        />
      )}

      {/* Investigation Dossier Header */}
      <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
                Incident ID: {dossier.incident_id}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded bg-red-900/60 text-red-300 border border-red-700/50 font-bold uppercase font-mono">
                {normalized_alert.raw_severity}
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">{normalized_alert.signature}</h2>
            <p className="text-xs text-gray-400 font-mono">Source SIEM: {normalized_alert.source_format} | Category: {normalized_alert.category}</p>
          </div>

          <div className="text-right">
            <span className="text-xs text-gray-400 block font-semibold">Triage Decision</span>
            <span className={`text-sm font-bold uppercase px-3 py-1 rounded-md inline-block mt-1 ${
              consensus_assessment.overall_verdict === 'malicious' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
            }`}>
              {consensus_assessment.overall_verdict}
            </span>
          </div>
        </div>
      </div>

      {/* Stage 1: ML Multi-Label Routing Decisions */}
      <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-gray-800 gap-2">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-gray-300 flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              <span>ML Multi-Label Router Posterior Probabilities</span>
            </h3>
            <p className="text-xs text-gray-400">Click on any domain tile to inspect model feature attributions & logit weights.</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-cyan-400 bg-cyan-950/60 px-2.5 py-1 rounded border border-cyan-800/40 font-mono">
              Inference Latency: {routing_decision.routing_latency_ms}ms
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
          {Object.entries(routing_decision.probabilities).map(([domain, prob]) => {
            const isSelected = routing_decision.selected_domains.includes(domain as any);
            const Icon = domainIcons[domain] || Shield;
            return (
              <button
                key={domain}
                onClick={() => setInspectingDomain(domain as AgentDomain)}
                className={`p-3 rounded-lg border text-left transition-all duration-200 hover:scale-[1.03] group ${
                  isSelected
                    ? 'bg-blue-950/60 border-blue-500/80 shadow-md shadow-blue-900/40 hover:border-cyan-400'
                    : 'bg-gray-950/40 border-gray-800/80 opacity-60 hover:opacity-100 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between">
                  <Icon className={`h-4 w-4 transition-colors ${isSelected ? 'text-blue-400 group-hover:text-cyan-300' : 'text-gray-500'}`} />
                  <span className={`text-xs font-mono font-bold ${isSelected ? 'text-blue-300' : 'text-gray-500'}`}>
                    {(prob * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="mt-2">
                  <span className="text-xs font-semibold uppercase tracking-wider block text-gray-200 group-hover:text-white truncate">
                    {domain.replace('_', ' ')}
                  </span>
                  <div className="flex items-center justify-between mt-0.5">
                    <span className={`text-[10px] font-mono ${isSelected ? 'text-emerald-400 font-bold' : 'text-gray-500'}`}>
                      {isSelected ? '● Dispatched' : '○ Bypassed'}
                    </span>
                    <span className="text-[10px] text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity">
                      Inspect ➔
                    </span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Stage 2: Specialist Agent Findings & Concrete Evidence */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Terminal className="h-5 w-5 text-cyan-400" />
            <span>Specialist Domain Agent Deep Findings ({Object.keys(agent_findings).length} Dispatched)</span>
          </h3>
          <span className="text-xs text-gray-400 font-mono">
            Async LangGraph Execution: {routing_decision.selected_domains.length} parallel nodes
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(agent_findings).map(([domain, finding]) => {
            const Icon = domainIcons[domain] || Shield;
            const isExpanded = !!expandedAgents[domain];

            return (
              <div key={domain} className="p-5 rounded-xl bg-slate-900/80 border border-gray-800 space-y-3 shadow-lg transition-all hover:border-gray-700">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Icon className="h-4 w-4 text-blue-400" />
                    <span className="font-bold text-sm text-white uppercase tracking-wider">{domain.replace('_', ' ')} SPECIALIST</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold uppercase ${
                      finding.verdict === 'malicious'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {finding.verdict}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-cyan-300 font-bold">
                      {(finding.confidence * 100).toFixed(0)}% Conf
                    </span>
                  </div>
                </div>

                <p className="text-xs text-gray-300 leading-relaxed bg-gray-950/60 p-3 rounded border border-gray-800/80">
                  {finding.reasoning_summary}
                </p>

                {finding.evidence_items.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider block">Grounded Evidence:</span>
                    {finding.evidence_items.map((ev, i) => (
                      <div key={i} className="text-xs font-mono bg-blue-950/30 border border-blue-900/40 p-2 rounded flex justify-between items-center">
                        <span className="text-gray-300 truncate max-w-[70%]">{ev.value}</span>
                        <span className="text-[10px] text-blue-400">{ev.source}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="pt-2 border-t border-gray-800/80">
                  <button
                    onClick={() => toggleAgentExpand(domain)}
                    className="w-full flex items-center justify-between text-xs text-blue-400 hover:text-blue-300 py-1 transition-colors font-medium"
                  >
                    <span>{isExpanded ? 'Hide Technical Details' : 'View Threat Hunting Queries & Telemetry'}</span>
                    {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                  </button>

                  {isExpanded && (
                    <div className="mt-3 space-y-3 p-3 rounded-lg bg-gray-950/80 border border-gray-800 text-xs font-mono animate-in fade-in">
                      {finding.mitre_techniques.length > 0 && (
                        <div>
                          <span className="text-[10px] text-gray-400 uppercase font-sans font-semibold block">Mapped ATT&CK Techniques:</span>
                          <div className="flex flex-wrap gap-1.5 mt-1">
                            {finding.mitre_techniques.map((t, idx) => (
                              <span key={idx} className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {finding.recommended_queries.length > 0 && (
                        <div>
                          <span className="text-[10px] text-gray-400 uppercase font-sans font-semibold block">Recommended SIEM Hunting Query:</span>
                          <div className="mt-1 p-2 rounded bg-slate-900 border border-gray-800 text-cyan-300 overflow-x-auto text-[11px]">
                            {finding.recommended_queries[0]}
                          </div>
                        </div>
                      )}

                      {finding.uncertainty_factors.length > 0 && (
                        <div>
                          <span className="text-[10px] text-gray-400 uppercase font-sans font-semibold block">Diagnostic Caveats:</span>
                          <ul className="list-disc list-inside text-gray-400 text-[11px] mt-0.5">
                            {finding.uncertainty_factors.map((uf, idx) => (
                              <li key={idx}>{uf}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Stage 3: MITRE ATT&CK Mapping */}
      {consensus_assessment.aggregated_mitre.length > 0 && (
        <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-gray-300 flex items-center gap-2">
            <Shield className="h-4 w-4 text-purple-400" />
            <span>MITRE Enterprise ATT&CK Kill-Chain Mapping</span>
          </h3>
          <div className="flex flex-wrap gap-2 pt-1">
            {consensus_assessment.aggregated_mitre.map((tech) => (
              <div key={tech.technique_id} className="p-2.5 rounded-lg bg-purple-950/40 border border-purple-800/50 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold font-mono text-purple-300">{tech.technique_id}</span>
                  <span className="text-xs text-gray-200 font-semibold">{tech.technique_name}</span>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-gray-400 font-mono">
                  <span>Tactic: {tech.tactic}</span>
                  <span>•</span>
                  <span>Agents: {tech.mapped_by_agents.join(', ')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stage 4: Historical Memory & Vector Retrieval (pgvector) */}
      {historical_cases.length > 0 && (
        <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-gray-300 flex items-center gap-2">
            <History className="h-4 w-4 text-indigo-400" />
            <span>Top-K pgvector Historical Incident Precedent</span>
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
            {historical_cases.map((hc, idx) => (
              <div key={idx} className="p-3.5 rounded-lg bg-gray-950/60 border border-gray-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-200 truncate">{hc.incident_title}</span>
                  <span className="text-xs font-mono text-indigo-400 font-bold">
                    Sim: {(hc.similarity_score * 100).toFixed(1)}%
                  </span>
                </div>
                <p className="text-xs text-gray-400">{hc.outcome_summary}</p>
                <div className="text-[10px] font-mono text-emerald-400 pt-0.5">
                  Executed: {hc.executed_playbook}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Stage 5: Deterministic Trust Score Engine (Gate 03) */}
      <TrustExplainabilityPanel assessment={trust_assessment} />

      {/* Stage 6: Playbook & Mandatory Human Approval Gate */}
      <div className={`p-6 rounded-xl shadow-2xl space-y-5 border transition-all ${
        isApproved
          ? 'bg-emerald-950/20 border-emerald-700/60'
          : 'bg-slate-900/90 border-amber-900/50'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-800 gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className={`text-xs font-mono font-bold uppercase tracking-wider ${
                isApproved ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {isApproved ? '● Remediated in Sandbox (HMAC Signed)' : '🚨 Mandatory Human Approval Boundary (Gate 03)'}
              </span>
            </div>
            <h3 className="text-lg font-bold text-white mt-0.5">{playbook.title}</h3>
          </div>

          <div className="flex items-center gap-2">
            {!isApproved ? (
              <>
                <button
                  onClick={() => onRejectPlaybook(approval_request.request_id)}
                  disabled={isExecuting}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-200 transition-colors disabled:opacity-50"
                >
                  Reject Remediation
                </button>
                <button
                  onClick={() => setShowSimulationModal(true)}
                  disabled={isExecuting}
                  className="flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-bold bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-600/30 transition-all hover:scale-105 disabled:opacity-50"
                >
                  <Lock className="h-4 w-4" />
                  <span>Authorize & Run Sandboxed Simulation</span>
                </button>
              </>
            ) : (
              <button
                onClick={() => setShowSimulationModal(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-emerald-700/50 transition-colors"
              >
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>View Live State Diff & Simulation Details</span>
              </button>
            )}
          </div>
        </div>

        {/* Visual Security State Diff Post-Remediation */}
        {isApproved && (
          <div className="p-4 rounded-xl bg-gray-950/80 border border-emerald-800/40 space-y-3 animate-in fade-in">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider block">
              Active Quarantined Posture (Simulation Result)
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                <span className="text-gray-400 text-[10px] uppercase font-semibold">Endpoint Security</span>
                <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                  <Lock className="h-3.5 w-3.5" />
                  <span>ISOLATED (VLAN 999)</span>
                </div>
                <p className="text-[10px] text-gray-400 font-mono">FINANCE-PC-01 production link down.</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                <span className="text-gray-400 text-[10px] uppercase font-semibold">Firewall Ingress</span>
                <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  <span>BLOCK RULE ACTIVE</span>
                </div>
                <p className="text-[10px] text-gray-400 font-mono">185.220.101.5 dropped at perimeter.</p>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                <span className="text-gray-400 text-[10px] uppercase font-semibold">Forensic Capture</span>
                <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                  <Cpu className="h-3.5 w-3.5" />
                  <span>MEM DUMP STAGED</span>
                </div>
                <p className="text-[10px] text-gray-400 font-mono">Volatility memory dump artifact captured.</p>
              </div>
            </div>
          </div>
        )}

        {/* Declarative Actions List */}
        <div className="space-y-2">
          {playbook.actions.map((act, idx) => (
            <div key={idx} className="p-3.5 rounded-lg bg-gray-950/80 border border-gray-800 flex items-start justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-blue-400 uppercase">{act.action_type.replace(/_/g, ' ')}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">Target: {act.target_entity}</span>
                </div>
                <p className="text-xs text-gray-400">{act.rationale}</p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 whitespace-nowrap">
                Reversible Safe Action
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
