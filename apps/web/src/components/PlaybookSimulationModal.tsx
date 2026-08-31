import React, { useState } from 'react';
import { X, ShieldCheck, CheckCircle2, Terminal, Key, Undo2, Lock, ShieldAlert, Cpu } from 'lucide-react';
import { Playbook, ApprovalRequest } from '../types';

interface PlaybookSimulationModalProps {
  playbook: Playbook;
  request: ApprovalRequest;
  onConfirmApprove: () => Promise<any>;
  onClose: () => void;
}

export const PlaybookSimulationModal: React.FC<PlaybookSimulationModalProps> = ({
  playbook,
  request,
  onConfirmApprove,
  onClose,
}) => {
  const [step, setStep] = useState<'review' | 'signing' | 'simulating' | 'complete'>('review');
  const [activeActionIdx, setActiveActionIdx] = useState<number>(0);
  const [isRolledBack, setIsRolledBack] = useState<boolean>(false);

  const startSimulation = async () => {
    setStep('signing');
    await new Promise((r) => setTimeout(r, 700));
    setStep('simulating');

    await onConfirmApprove();

    for (let i = 0; i < playbook.actions.length; i++) {
      setActiveActionIdx(i);
      await new Promise((r) => setTimeout(r, 500));
    }

    setStep('complete');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in">
      <div className="relative w-full max-w-3xl rounded-2xl bg-slate-900 border border-blue-900/80 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-800 bg-gray-950/80">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <ShieldCheck className="h-6 w-6 text-white" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                <span>Playbook Remediation Sandbox</span>
                <span className="text-xs px-2 py-0.5 rounded bg-blue-900/50 text-blue-300 font-mono border border-blue-700/40">
                  Gate 03 Authorized
                </span>
              </h3>
              <p className="text-xs text-gray-400 font-mono">
                Incident: {request.incident_id} • Trust Score: {request.trust_score.toFixed(3)}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Phase 1: Review State */}
          {step === 'review' && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl bg-slate-950 border border-blue-900/40 space-y-2">
                <span className="text-xs font-bold text-amber-400 uppercase tracking-wider block">
                  Mandatory Security Verification
                </span>
                <p className="text-xs text-gray-300 leading-relaxed">
                  Executing this remediation will compute an <strong className="text-emerald-400">HMAC-SHA256 authorization token</strong>, verify that your analyst credentials have non-repudiation authorization, and execute the following <strong className="text-white">{playbook.actions.length} sandboxed remediation actions</strong> in sequence:
                </p>
              </div>

              <div className="space-y-2.5">
                <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                  Staged Remediation Sequence:
                </span>
                {playbook.actions.map((act, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-gray-950/70 border border-gray-800 flex items-center justify-between gap-4"
                  >
                    <div className="flex items-center space-x-3">
                      <span className="h-6 w-6 rounded-full bg-blue-900/50 text-blue-300 font-mono text-xs flex items-center justify-center font-bold">
                        {idx + 1}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold font-mono text-cyan-300 uppercase">
                            {act.action_type.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[11px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
                            ➔ {act.target_entity}
                          </span>
                        </div>
                        <p className="text-[11px] text-gray-400 mt-0.5">{act.rationale}</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/40 shrink-0">
                      Reversible
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Phase 2: Cryptographic Signing Animation */}
          {step === 'signing' && (
            <div className="py-12 flex flex-col items-center justify-center space-y-4 text-center animate-in fade-in">
              <div className="relative">
                <div className="h-16 w-16 rounded-2xl bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center animate-pulse shadow-lg shadow-cyan-500/30">
                  <Key className="h-8 w-8 text-white animate-spin" />
                </div>
              </div>
              <div className="space-y-1">
                <h4 className="text-base font-bold text-white">Generating Cryptographic HMAC-SHA256 Token...</h4>
                <p className="text-xs font-mono text-cyan-400">
                  Binding: (Request: {request.request_id.slice(0, 8)}... || Analyst: lead_soc_analyst || Status: APPROVED)
                </p>
              </div>
            </div>
          )}

          {/* Phase 3 & 4: Step-by-Step Live Execution Stream */}
          {(step === 'simulating' || step === 'complete') && (
            <div className="space-y-6 animate-in fade-in">
              {/* Visual Sequence Runner */}
              <div className="space-y-3">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-bold text-gray-300 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-emerald-400" />
                    <span>Real-Time Remediation Execution Pipeline</span>
                  </span>
                  <span className="font-mono text-emerald-400 font-bold">
                    {step === 'complete' ? '● ALL ACTIONS EXECUTED' : '● SIMULATING IN PROGRESS...'}
                  </span>
                </div>

                <div className="space-y-2.5">
                  {playbook.actions.map((act, idx) => {
                    const isDone = step === 'complete' || idx < activeActionIdx;
                    const isCurrent = step === 'simulating' && idx === activeActionIdx;

                    return (
                      <div
                        key={idx}
                        className={`p-4 rounded-xl border transition-all duration-300 ${
                          isDone
                            ? 'bg-emerald-950/20 border-emerald-700/60 shadow-md shadow-emerald-950/20'
                            : isCurrent
                            ? 'bg-blue-950/40 border-blue-500 shadow-lg shadow-blue-900/30 scale-[1.01]'
                            : 'bg-gray-950/40 border-gray-800/80 opacity-50'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className={`h-7 w-7 rounded-lg flex items-center justify-center font-bold text-xs ${
                              isDone
                                ? 'bg-emerald-600 text-white'
                                : isCurrent
                                ? 'bg-blue-600 text-white animate-spin'
                                : 'bg-gray-800 text-gray-400'
                            }`}>
                              {isDone ? <CheckCircle2 className="h-4 w-4" /> : idx + 1}
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-white font-mono uppercase">
                                  {act.action_type.replace(/_/g, ' ')}
                                </span>
                                <span className="text-xs font-mono px-2 py-0.5 rounded bg-gray-800 text-cyan-300">
                                  Target: {act.target_entity}
                                </span>
                              </div>
                              <p className="text-[11px] text-gray-300 mt-1 font-mono">
                                {isDone ? (
                                  <span className="text-emerald-300">
                                    ✓ State Transition: {act.target_entity} quarantined. Firewall rule staged.
                                  </span>
                                ) : isCurrent ? (
                                  <span className="text-cyan-300 animate-pulse">
                                    ⚙ Applying state diff & computing blast radius...
                                  </span>
                                ) : (
                                  <span className="text-gray-500">Queued in sequence</span>
                                )}
                              </p>
                            </div>
                          </div>

                          <span className={`text-xs font-mono font-bold px-2.5 py-1 rounded ${
                            isDone
                              ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                              : isCurrent
                              ? 'bg-blue-950 text-blue-300 border border-blue-700 animate-pulse'
                              : 'bg-gray-800 text-gray-500'
                          }`}>
                            {isDone ? 'SIMULATED SUCCESS' : isCurrent ? 'RUNNING' : 'PENDING'}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Visual State Topology Diff */}
              {step === 'complete' && (
                <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-3">
                  <span className="text-xs font-bold text-gray-300 uppercase tracking-wider block">
                    Visual Security Posture State Diff
                  </span>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                    <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                      <span className="text-gray-400 text-[10px] uppercase font-semibold">Target Endpoint</span>
                      <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                        <Lock className="h-3.5 w-3.5" />
                        <span>ISOLATED (VLAN 999)</span>
                      </div>
                      <p className="text-[10px] text-gray-500">Production traffic severed.</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                      <span className="text-gray-400 text-[10px] uppercase font-semibold">Perimeter Firewall</span>
                      <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                        <ShieldAlert className="h-3.5 w-3.5" />
                        <span>INGRESS DROP RULE</span>
                      </div>
                      <p className="text-[10px] text-gray-500">External C2 IP blocked.</p>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-900 border border-gray-800 space-y-1">
                      <span className="text-gray-400 text-[10px] uppercase font-semibold">Forensic Capture</span>
                      <div className="flex items-center gap-1.5 font-mono font-bold text-emerald-400">
                        <Cpu className="h-3.5 w-3.5" />
                        <span>ARTIFACT STAGED</span>
                      </div>
                      <p className="text-[10px] text-gray-500">Memory & Prefetch ready for triage.</p>
                    </div>
                  </div>

                  {/* Rollback Demo Button */}
                  <div className="pt-2 flex items-center justify-between border-t border-gray-800/80">
                    <span className="text-[11px] text-gray-400">
                      Blast Radius: Zero production impact • Fully reversible
                    </span>
                    <button
                      onClick={() => setIsRolledBack(!isRolledBack)}
                      className="flex items-center gap-1.5 px-3 py-1 rounded bg-gray-800 hover:bg-gray-700 text-xs font-semibold text-gray-200 transition-colors"
                    >
                      <Undo2 className="h-3.5 w-3.5 text-amber-400" />
                      <span>{isRolledBack ? 'Re-Apply Remediation' : 'Simulate Rollback / Undo'}</span>
                    </button>
                  </div>
                  {isRolledBack && (
                    <div className="p-2.5 rounded bg-amber-950/40 border border-amber-800/50 text-amber-300 text-xs font-mono">
                      ✓ Rollback simulation executed: Host re-assigned to production VLAN; firewall drop rule withdrawn.
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-gray-800 bg-gray-950/80 flex items-center justify-between">
          <div className="text-xs text-gray-400 font-mono">
            Authorization: HMAC-SHA256 Token Verification
          </div>

          <div className="flex items-center space-x-3">
            {step === 'review' ? (
              <>
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={startSimulation}
                  className="flex items-center space-x-2 px-5 py-2 rounded-lg text-xs font-bold bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-600/30 transition-all hover:scale-105"
                >
                  <Lock className="h-4 w-4" />
                  <span>Authorize & Run Sandboxed Simulation</span>
                </button>
              </>
            ) : (
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white transition-colors"
              >
                Done & Return to Dossier
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
