import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewView } from './components/OverviewView';
import { AlertQueueView } from './components/AlertQueueView';
import { InvestigationView } from './components/InvestigationView';
import { ApprovalQueueView } from './components/ApprovalQueueView';
import { EvaluationBenchmarksView } from './components/EvaluationBenchmarksView';
import { InvestigationDossier, ApprovalRequest } from './types';

export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<string>('overview');
  const [alerts, setAlerts] = useState<any[]>([]);
  const [latestDossier, setLatestDossier] = useState<InvestigationDossier | null>(null);
  const [pendingApprovals, setPendingApprovals] = useState<ApprovalRequest[]>([]);
  const [executionLogs, setExecutionLogs] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Initial seed alerts
  useEffect(() => {
    const initialAlerts = [
      {
        incident_id: 'INC-8891',
        signature: 'Cobalt Strike C2 Beaconing via Encoded PowerShell',
        severity: 'critical',
        source_format: 'splunk',
        overall_verdict: 'malicious',
        trust_score: 0.782,
        raw_payload: {
          sourcetype: 'WinEventLog:Security',
          host: 'FINANCE-PC-01',
          CommandLine: 'powershell.exe -enc JABhID0A... -WindowStyle Hidden',
          process_name: 'powershell.exe',
          user: 'alice_finance',
          severity: 'critical',
          src_ip: '185.220.101.5',
          dest_port: 443,
        },
      },
      {
        incident_id: 'INC-8892',
        signature: 'Automated SSH Brute Force Against Jump Host',
        severity: 'high',
        source_format: 'wazuh',
        overall_verdict: 'malicious',
        trust_score: 0.695,
        raw_payload: {
          rule: { level: 10, description: 'Multiple SSH authentication failures from external IP', groups: ['sshd'] },
          agent: { id: '001', name: 'bastion-host', ip: '10.0.0.1' },
          data: {
            srcip: '194.26.29.112',
            srcport: '48921',
            dstport: '22',
            protocol: 'TCP',
            user: 'root',
            auth_status: 'FAILED',
          },
        },
      },
      {
        incident_id: 'INC-8893',
        signature: 'Unauthorized AWS S3 Bucket Public ACL Policy Mutation',
        severity: 'critical',
        source_format: 'synthetic',
        overall_verdict: 'malicious',
        trust_score: 0.741,
        raw_payload: {
          source_format: 'synthetic',
          signature: 'AWS S3 Public Bucket Exposure',
          raw_severity: 'critical',
          cloud: {
            cloud_provider: 'AWS',
            account_id: '123456789012',
            region: 'us-east-1',
            resource_arn: 'arn:aws:s3:::customer-pii-records',
            event_name: 'PutBucketPolicy',
          },
          identity: {
            username: 'unverified_contractor',
            auth_status: 'SUCCESS',
            is_privileged: true,
          },
        },
      },
      {
        incident_id: 'INC-8894',
        signature: 'Automated Cloud Deployment Pipeline',
        severity: 'low',
        source_format: 'synthetic',
        overall_verdict: 'benign',
        trust_score: 0.892,
        raw_payload: {
          source_format: 'synthetic',
          signature: 'Automated Cloud Deployment Pipeline',
          raw_severity: 'low',
          cloud: {
            cloud_provider: 'AWS',
            account_id: '123456789012',
            event_name: 'AssumeRole',
          },
          identity: {
            username: 'terraform-service-account',
            auth_status: 'SUCCESS',
          },
        },
      },
    ];

    setAlerts(initialAlerts);
    // Triage the first alert by default to populate state
    handleTriageAlert(initialAlerts[0].raw_payload);
  }, []);

  const handleTriageAlert = async (payload: any) => {
    setIsLoading(true);
    try {
      const resp = await fetch('/api/v1/investigations/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (resp.ok) {
        const data: InvestigationDossier = await resp.json();
        setLatestDossier(data);
        if (data.approval_request && data.approval_request.status === 'PENDING') {
          setPendingApprovals((prev) => {
            const filtered = prev.filter((p) => p.request_id !== data.approval_request.request_id);
            return [data.approval_request, ...filtered];
          });
        }
        fetchMetrics();
      }
    } catch (e) {
      console.error('Failed to run triage:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const fetchMetrics = async () => {
    try {
      const resp = await fetch('/api/v1/metrics/summary');
      if (resp.ok) {
        const data = await resp.json();
        setMetrics(data);
      }
    } catch (e) {
      console.error('Failed to fetch metrics:', e);
    }
  };

  const handleApprovePlaybook = async (requestId: string) => {
    setIsLoading(true);
    try {
      // 1. Submit approval decision
      const decResp = await fetch(`/api/v1/approvals/${requestId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analyst_id: 'lead_soc_analyst',
          decision: 'APPROVED',
          analyst_notes: 'Verified malicious indicator corroboration. Approved for sandbox simulation.',
        }),
      });

      if (decResp.ok) {
        const decision = await decResp.json();
        // 2. Execute simulated remediation
        const execResp = await fetch(`/api/v1/approvals/${decision.decision_id}/execute`, {
          method: 'POST',
        });
        if (execResp.ok) {
          const execData = await execResp.json();
          setExecutionLogs((prev) => [...execData.action_logs, ...prev]);
          setPendingApprovals((prev) => prev.filter((p) => p.request_id !== requestId));
          if (latestDossier && latestDossier.approval_request.request_id === requestId) {
            setLatestDossier({
              ...latestDossier,
              approval_request: { ...latestDossier.approval_request, status: 'APPROVED' },
            });
          }
        }
      }
    } catch (e) {
      console.error('Failed to approve playbook:', e);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRejectPlaybook = async (requestId: string) => {
    try {
      await fetch(`/api/v1/approvals/${requestId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analyst_id: 'lead_soc_analyst',
          decision: 'REJECTED',
          analyst_notes: 'False positive or authorized drill.',
        }),
      });
      setPendingApprovals((prev) => prev.filter((p) => p.request_id !== requestId));
    } catch (e) {
      console.error('Failed to reject playbook:', e);
    }
  };

  const simulateDiverseAttack = () => {
    const testAttacks = [
      {
        source_format: 'synthetic',
        signature: 'LockBit 3.0 Ransomware Dropper Detonation',
        raw_severity: 'critical',
        endpoint: {
          hostname: 'PROD-PAYMENT-SRV-01',
          process_name: 'svchost_updater.exe',
          sha256: '44d88612fea8a8f36de82e1278abb02f',
          file_path: 'C:\\Windows\\Temp\\updater.exe',
        },
      },
      {
        source_format: 'synthetic',
        signature: 'High-Volume SYN Flood Port Scan',
        raw_severity: 'high',
        network: {
          src_ip: '185.220.101.5',
          dst_ip: '10.0.1.50',
          dst_port: 80,
          protocol: 'TCP',
          dns_query: 'c2-beacon.darknet.top',
        },
      },
    ];

    const pick = testAttacks[Math.floor(Math.random() * testAttacks.length)];
    handleTriageAlert(pick);
    setCurrentTab('investigation');
  };

  return (
    <div className="min-h-screen bg-[#080C14] text-slate-100 flex flex-col">
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        pendingCount={pendingApprovals.length}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {currentTab === 'overview' && (
          <OverviewView
            metrics={metrics}
            latestIncident={latestDossier}
            onViewIncident={() => setCurrentTab('investigation')}
            onSimulateNewAlert={simulateDiverseAttack}
          />
        )}

        {currentTab === 'alerts' && (
          <AlertQueueView
            alerts={alerts}
            onTriageAlert={(payload) => {
              handleTriageAlert(payload);
              setCurrentTab('investigation');
            }}
            isLoading={isLoading}
          />
        )}

        {currentTab === 'investigation' && (
          <InvestigationView
            dossier={latestDossier}
            onApprovePlaybook={handleApprovePlaybook}
            onRejectPlaybook={handleRejectPlaybook}
            isExecuting={isLoading}
          />
        )}

        {currentTab === 'approvals' && (
          <ApprovalQueueView
            pendingRequests={pendingApprovals}
            onApprove={handleApprovePlaybook}
            onReject={handleRejectPlaybook}
            isExecuting={isLoading}
            executionLogs={executionLogs}
          />
        )}

        {currentTab === 'benchmarks' && (
          <EvaluationBenchmarksView benchmarkData={metrics?.baseline_comparison} />
        )}
      </main>

      <footer className="border-t border-gray-800 bg-[#0B0F19] py-4 text-center text-xs text-gray-500 font-mono">
        Adaptive Trust-Aware SOC Multi-Agent Framework • Semester 7 Research & Patent Prototype • Gate 03 Safety Invariant
      </footer>
    </div>
  );
};
