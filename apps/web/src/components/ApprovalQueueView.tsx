import React from 'react';
import { CheckSquare, CheckCircle2, XCircle, Terminal } from 'lucide-react';
import { ApprovalRequest } from '../types';

interface ApprovalQueueViewProps {
  pendingRequests: ApprovalRequest[];
  onApprove: (requestId: string) => void;
  onReject: (requestId: string) => void;
  isExecuting: boolean;
  executionLogs: any[];
}

export const ApprovalQueueView: React.FC<ApprovalQueueViewProps> = ({
  pendingRequests,
  onApprove,
  onReject,
  isExecuting,
  executionLogs,
}) => {
  return (
    <div className="space-y-6">
      <div className="p-6 rounded-xl bg-slate-900/80 border border-amber-900/50 shadow-xl space-y-2">
        <div className="flex items-center gap-2">
          <CheckSquare className="h-5 w-5 text-amber-400" />
          <h2 className="text-lg font-bold text-white">Tier-2 Security Analyst Approval Queue</h2>
        </div>
        <p className="text-xs text-gray-300">
          Security Boundary Gate 03: Playbooks require explicit cryptographic HMAC-SHA256 authorization from a verified human analyst prior to sandboxed or live execution.
        </p>
      </div>

      <div className="space-y-4">
        <h3 className="text-sm font-bold uppercase tracking-wider text-gray-400">
          Pending Authorization Requests ({pendingRequests.length})
        </h3>

        {pendingRequests.length === 0 ? (
          <div className="p-8 rounded-xl bg-slate-900/40 border border-gray-800 text-center text-sm text-gray-500">
            No approval requests currently pending. All triaged incidents are up to date.
          </div>
        ) : (
          <div className="space-y-3">
            {pendingRequests.map((req) => (
              <div
                key={req.request_id}
                className="p-5 rounded-xl bg-slate-900/80 border border-gray-800 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-lg"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-900/50 text-blue-300">
                      Request: {req.request_id.slice(0, 8)}...
                    </span>
                    <span className="text-xs font-mono font-bold text-cyan-400">
                      Trust Score: {req.trust_score.toFixed(3)}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 font-mono">
                      PENDING SIGN-OFF
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 font-mono">
                    Incident ID: {req.incident_id} | Expires: {new Date(req.expires_at).toLocaleTimeString()}
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => onReject(req.request_id)}
                    disabled={isExecuting}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors disabled:opacity-50"
                  >
                    <XCircle className="h-4 w-4 text-rose-400" />
                    <span>Reject</span>
                  </button>
                  <button
                    onClick={() => onApprove(req.request_id)}
                    disabled={isExecuting}
                    className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg text-xs font-bold bg-emerald-600 hover:bg-emerald-500 text-white shadow transition-all hover:scale-105 disabled:opacity-50"
                  >
                    <CheckCircle2 className="h-4 w-4" />
                    <span>Sign HMAC & Approve</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {executionLogs.length > 0 && (
        <div className="p-6 rounded-xl bg-gray-950 border border-gray-800 shadow-2xl space-y-3 font-mono">
          <div className="flex items-center justify-between pb-2 border-b border-gray-800 text-xs text-gray-400">
            <span className="flex items-center gap-2 text-emerald-400 font-bold">
              <Terminal className="h-4 w-4" />
              <span>Simulation Sandbox Execution Diff Stream</span>
            </span>
            <span className="text-[10px] text-gray-500">Append-Only Immutable Ledger</span>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto text-xs">
            {executionLogs.map((log, idx) => (
              <div key={idx} className="p-3 rounded bg-slate-900/60 border border-gray-800/80 space-y-1">
                <div className="flex items-center justify-between text-[11px] text-blue-300">
                  <span>[EXEC] {log.action_type} ➔ {log.target}</span>
                  <span className="text-emerald-400 font-bold">{log.status}</span>
                </div>
                <p className="text-gray-300">{log.simulated_effect}</p>
                <div className="text-[10px] text-amber-400">Reversion: {log.reversion_step}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
