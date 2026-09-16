import React, { useState } from 'react';
import {
  Activity,
  Layers,
  Cpu,
  Clock,
  ShieldCheck,
  Flame,
  Zap,
  TrendingDown,
  TrendingUp,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  PlayCircle,
  ExternalLink,
  Target,
  BarChart3,
  PieChart,
} from 'lucide-react';
import { AnalyticsData } from '../types';

interface AnalyticsViewProps {
  analytics: AnalyticsData | null;
  onRefresh: () => void;
  onBatchSeed: () => Promise<void>;
  onSelectIncident: (incidentId: string) => void;
  isSeeding: boolean;
}

export const AnalyticsView: React.FC<AnalyticsViewProps> = ({
  analytics,
  onRefresh,
  onBatchSeed,
  onSelectIncident,
  isSeeding,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<string>('all');
  const [hoveredCell, setHoveredCell] = useState<{ d1: string; d2: string; count: number } | null>(null);
  const [hoveredTrustPoint, setHoveredTrustPoint] = useState<{
    index: number;
    score: number;
    incidentId: string;
    verdict: string;
    severity: string;
    signature: string;
    decision: string;
    x: number;
    y: number;
  } | null>(null);

  if (!analytics) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-4">
        <RefreshCw className="h-10 w-10 text-cyan-400 animate-spin" />
        <p className="text-sm font-mono text-gray-400">Loading Real-Time Analytics Telemetry...</p>
        <button
          onClick={onRefresh}
          className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-mono text-white transition shadow-md"
        >
          Click to Load Telemetry
        </button>
      </div>
    );
  }

  const {
    total_runs,
    executive_kpis,
    trust_distribution,
    domain_routing_analytics,
    mitre_attack_analytics,
    latency_telemetry,
    containment_action_analytics,
    incident_runs,
  } = analytics;

  const domainLabels: Record<string, string> = {
    network: 'Network',
    endpoint: 'Endpoint',
    identity: 'Identity',
    cloud: 'Cloud',
    malware: 'Malware',
    threat_intel: 'Threat Intel',
  };

  const getHeatmapColor = (count: number, maxCount: number) => {
    if (count === 0) return 'bg-slate-900/60 text-gray-600 border-gray-800/40';
    const ratio = maxCount > 0 ? count / maxCount : 0;
    if (ratio < 0.25) return 'bg-blue-950/80 text-cyan-300 border-blue-800/60';
    if (ratio < 0.5) return 'bg-blue-900/90 text-cyan-200 border-cyan-700/70 font-semibold';
    if (ratio < 0.75) return 'bg-indigo-700 text-white border-indigo-500 shadow-md shadow-indigo-600/30 font-bold';
    return 'bg-gradient-to-tr from-cyan-600 to-blue-500 text-white border-cyan-300 shadow-lg shadow-cyan-500/40 font-extrabold';
  };

  const maxMatrixVal = Math.max(
    1,
    ...domain_routing_analytics.co_activation_matrix.flatMap((row) => row)
  );

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious':
        return 'bg-red-950/70 text-red-400 border-red-800/60';
      case 'suspicious':
        return 'bg-amber-950/70 text-amber-400 border-amber-800/60';
      case 'benign':
        return 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-800/70';
      case 'high':
        return 'bg-orange-950/80 text-orange-300 border-orange-800/70';
      case 'medium':
        return 'bg-amber-950/80 text-amber-300 border-amber-800/70';
      case 'low':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/70';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  // --- Visual Graph Geometry & Computations ---
  // 1. Triage Verdict Donut Geometry
  const totalVerdictCount = Math.max(
    1,
    (executive_kpis.malicious_count || 0) +
      (executive_kpis.suspicious_count || 0) +
      (executive_kpis.benign_count || 0)
  );
  const malPct = Math.round(((executive_kpis.malicious_count || 0) / totalVerdictCount) * 100);
  const suspPct = Math.round(((executive_kpis.suspicious_count || 0) / totalVerdictCount) * 100);
  const benPct = Math.max(0, 100 - malPct - suspPct);

  const donutR = 36;
  const donutCircumference = 2 * Math.PI * donutR; // ~226.19
  const malStroke = ((executive_kpis.malicious_count || 0) / totalVerdictCount) * donutCircumference;
  const suspStroke = ((executive_kpis.suspicious_count || 0) / totalVerdictCount) * donutCircumference;
  const benStroke = ((executive_kpis.benign_count || 0) / totalVerdictCount) * donutCircumference;

  // 2. Sequential Trust Score Trajectory Points
  const rawTimeline = latency_telemetry?.run_timeline;
  const timelinePoints =
    rawTimeline && rawTimeline.length > 0
      ? rawTimeline
      : [
          {
            run_index: 1,
            incident_id: 'INC-SIM-01',
            signature: 'Suspicious SSH Brute-Force Wave',
            trust_score: 0.38,
            verdict: 'MALICIOUS',
            severity: 'HIGH',
            decision: 'ESCALATE_TIER2_3',
          },
          {
            run_index: 2,
            incident_id: 'INC-SIM-02',
            signature: 'DNS C2 Beaconing via Port 53',
            trust_score: 0.74,
            verdict: 'MALICIOUS',
            severity: 'CRITICAL',
            decision: 'AUTO_SUGGEST',
          },
          {
            run_index: 3,
            incident_id: 'INC-SIM-03',
            signature: 'Authorized DevOps Terraform Mutation',
            trust_score: 0.92,
            verdict: 'BENIGN',
            severity: 'LOW',
            decision: 'AUTO_SUGGEST',
          },
          {
            run_index: 4,
            incident_id: 'INC-SIM-04',
            signature: 'TCP SYN Flood Volumetric Anomaly',
            trust_score: 0.55,
            verdict: 'SUSPICIOUS',
            severity: 'MEDIUM',
            decision: 'AUTO_SUGGEST',
          },
          {
            run_index: 5,
            incident_id: 'INC-SIM-05',
            signature: 'Kerberoasting Ticket Harvesting',
            trust_score: 0.34,
            verdict: 'MALICIOUS',
            severity: 'CRITICAL',
            decision: 'ESCALATE_TIER2_3',
          },
          {
            run_index: 6,
            incident_id: 'INC-SIM-06',
            signature: 'Ransomware Canary File Decoy Trigger',
            trust_score: 0.88,
            verdict: 'MALICIOUS',
            severity: 'CRITICAL',
            decision: 'AUTO_SUGGEST',
          },
        ];

  const svgW = 760;
  const svgH = 175;
  const pL = 46;
  const pR = 24;
  const pT = 24;
  const pB = 30;
  const cW = svgW - pL - pR;
  const cH = svgH - pT - pB;
  const thresholdVal = trust_distribution.threshold || 0.50;
  const tauY = pT + cH * (1 - Math.min(1, Math.max(0, thresholdVal)));

  const computedPoints = timelinePoints.map((pt, idx) => {
    const x = pL + (idx / Math.max(1, timelinePoints.length - 1)) * cW;
    const clampedScore = Math.min(1, Math.max(0, pt.trust_score));
    const y = pT + cH * (1 - clampedScore);
    return { ...pt, x, y, clampedScore };
  });

  const pathD = computedPoints
    .map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(' ');

  const areaD =
    computedPoints.length > 0
      ? `${pathD} L ${computedPoints[computedPoints.length - 1].x.toFixed(1)} ${pT + cH} L ${computedPoints[0].x.toFixed(1)} ${pT + cH} Z`
      : '';

  const maxTrustRun = computedPoints.reduce(
    (prev, curr) => (curr.trust_score > prev.trust_score ? curr : prev),
    computedPoints[0]
  );
  const minTrustRun = computedPoints.reduce(
    (prev, curr) => (curr.trust_score < prev.trust_score ? curr : prev),
    computedPoints[0]
  );

  // 3. Stage-Wise Latency Stacked Breakdown
  const stageBreakdownEntries = Object.entries(latency_telemetry.stage_breakdown_ms || {});
  const totalStageLatencyMs = Math.max(
    0.001,
    stageBreakdownEntries.reduce((acc, [, dur]) => acc + dur, 0)
  );


  return (
    <div className="space-y-8 animate-fadeIn">
      {/* 1. Header Banner & Controls */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-950 via-slate-900 to-indigo-950 border border-indigo-900/40 shadow-2xl flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-500/25">
              <Activity className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Real-Time Telemetry & SOC Analytics
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-700/60 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Live Stream ({total_runs} Incidents Triaged)
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">
                Dynamic mathematical distributions, 6×6 domain co-activation heatmaps, MITRE kill-chain telemetry, and stage-wise performance.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onRefresh}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-xs font-mono text-gray-300 border border-gray-700 transition"
            title="Refresh Live Telemetry"
          >
            <RefreshCw className="h-3.5 w-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>

          <button
            onClick={onBatchSeed}
            disabled={isSeeding}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold shadow-lg shadow-blue-600/30 transition disabled:opacity-50"
          >
            <PlayCircle className={`h-4 w-4 ${isSeeding ? 'animate-spin' : ''}`} />
            <span>{isSeeding ? 'Ingesting Scenarios...' : 'Ingest Batch Benchmark Corpus'}</span>
          </button>
        </div>
      </div>

      {/* Sub-Tab Navigation */}
      <div className="flex items-center space-x-1.5 border-b border-gray-800 pb-2 overflow-x-auto text-xs font-medium font-mono">
        {[
          { id: 'all', label: 'All Telemetry Overview', icon: Layers },
          { id: 'trust', label: 'Trust Dynamics & Graphs', icon: ShieldCheck },
          { id: 'routing', label: '6×6 Specialist Heatmap', icon: Flame },
          { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: Target },
          { id: 'latency', label: 'Pipeline Performance', icon: Clock },
          { id: 'runs', label: 'Incident Telemetry Feed', icon: Cpu },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg transition-all ${
                isActive
                  ? 'bg-blue-600/90 text-white shadow-md shadow-blue-600/20 font-semibold'
                  : 'text-gray-400 hover:bg-slate-800/60 hover:text-gray-200'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* 2. Executive KPI Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-gray-800/80 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Total Triaged</span>
          <div className="text-2xl font-black text-white font-mono">{executive_kpis.total_runs}</div>
          <div className="text-[10px] text-gray-400 font-mono flex items-center gap-1">
            <span className="text-red-400">{executive_kpis.malicious_count} Mal</span> •{' '}
            <span className="text-amber-400">{executive_kpis.suspicious_count} Susp</span> •{' '}
            <span className="text-emerald-400">{executive_kpis.benign_count} Ben</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-indigo-900/40 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Mean Trust Score</span>
          <div className="text-2xl font-black text-indigo-300 font-mono">
            {executive_kpis.mean_trust_score.toFixed(3)}
          </div>
          <div className="text-[10px] text-indigo-400 font-mono">
            Med: {executive_kpis.median_trust_score.toFixed(3)} (σ = {executive_kpis.std_dev_trust.toFixed(3)})
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-emerald-900/40 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Auto-Suggest Rate</span>
          <div className="text-2xl font-black text-emerald-400 font-mono">
            {executive_kpis.auto_suggest_rate_pct}%
          </div>
          <div className="text-[10px] text-gray-400 font-mono">
            {executive_kpis.auto_suggest_count} / {executive_kpis.total_runs} (T ≥ 0.65)
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-amber-900/40 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Human Escalation</span>
          <div className="text-2xl font-black text-amber-400 font-mono">
            {executive_kpis.escalated_rate_pct}%
          </div>
          <div className="text-[10px] text-gray-400 font-mono">
            {executive_kpis.escalated_count} / {executive_kpis.total_runs} (T &lt; 0.65)
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-900/40 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Avg Agents / Run</span>
          <div className="text-2xl font-black text-cyan-300 font-mono">
            {executive_kpis.avg_agents_per_run}
          </div>
          <div className="text-[10px] text-cyan-400 font-mono flex items-center gap-0.5">
            <TrendingDown className="h-3 w-3" />
            <span>59.5% savings vs 6.0</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-purple-900/40 shadow-lg space-y-1">
          <span className="text-[11px] font-mono text-gray-400 uppercase tracking-wider">Mean Routing Latency</span>
          <div className="text-2xl font-black text-purple-300 font-mono">
            {executive_kpis.mean_routing_latency_ms} <span className="text-xs font-normal">ms</span>
          </div>
          <div className="text-[10px] text-purple-400 font-mono">
            Pipeline: ~{executive_kpis.mean_pipeline_latency_ms}s
          </div>
        </div>
      </div>

      {/* 3. Sub-Section: Trust Distribution & Dynamic Graphs */}
      {(activeSubTab === 'all' || activeSubTab === 'trust') && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Trust Score 5-Bin Histogram */}
            <div className="lg:col-span-2 p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-5">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="h-5 w-5 text-indigo-400" />
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                      Deterministic Trust Score Distribution & Gate 03 Boundary
                    </h3>
                  </div>
                  <p className="text-xs text-gray-400">
                    Formula: <span className="font-mono text-cyan-400">T = clamp[(0.50 × C) + (0.30 × H) - (0.20 × S)]</span>
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded bg-indigo-950 text-indigo-300 border border-indigo-700/50 text-xs font-mono">
                  Threshold τ = {trust_distribution.threshold}
                </span>
              </div>

              {/* Histogram Bars */}
              <div className="space-y-3 pt-2">
                {trust_distribution.bins.map((b, idx) => {
                  const isOverThreshold = idx >= 3;
                  return (
                    <div key={b.range} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-gray-300 flex items-center gap-1.5">
                          <span className={`h-2 w-2 rounded-full ${isOverThreshold ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                          Bin [{b.range}] {isOverThreshold ? '(Auto-Suggest Capable)' : '(Mandatory Human Escalation)'}
                        </span>
                        <span className="text-gray-400">
                          <strong className="text-white">{b.count}</strong> runs ({b.pct}%)
                        </span>
                      </div>
                      <div className="h-4 w-full rounded-full bg-gray-950 overflow-hidden border border-gray-800/80 relative">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${
                            isOverThreshold
                              ? 'bg-gradient-to-r from-blue-500 to-emerald-400'
                              : 'bg-gradient-to-r from-amber-600 to-orange-500'
                          }`}
                          style={{ width: `${Math.max(b.pct, 3)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Visual Triage Decision & Verdict Breakdown Graphs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-gray-800">
                {/* Graph A: Triage Verdict Donut Chart */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-gray-800/80 flex items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-1.5 text-xs font-mono font-semibold text-gray-300">
                      <PieChart className="h-3.5 w-3.5 text-rose-400" />
                      <span>Verdict Proportions</span>
                    </div>
                    <div className="space-y-1 text-[11px] font-mono pt-1">
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-rose-500" />
                        <span className="text-gray-300">Malicious:</span>
                        <strong className="text-white">{executive_kpis.malicious_count}</strong>
                        <span className="text-gray-500 text-[10px]">({malPct}%)</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-amber-400" />
                        <span className="text-gray-300">Suspicious:</span>
                        <strong className="text-white">{executive_kpis.suspicious_count}</strong>
                        <span className="text-gray-500 text-[10px]">({suspPct}%)</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-emerald-400" />
                        <span className="text-gray-300">Benign:</span>
                        <strong className="text-white">{executive_kpis.benign_count}</strong>
                        <span className="text-gray-500 text-[10px]">({benPct}%)</span>
                      </div>
                    </div>
                  </div>

                  {/* Donut SVG */}
                  <div className="relative flex items-center justify-center flex-shrink-0">
                    <svg className="w-24 h-24 transform -rotate-90" viewBox="0 0 96 96">
                      {/* Background Ring */}
                      <circle
                        cx="48"
                        cy="48"
                        r={donutR}
                        fill="transparent"
                        stroke="#1e293b"
                        strokeWidth="9"
                      />
                      {/* Malicious Arc */}
                      <circle
                        cx="48"
                        cy="48"
                        r={donutR}
                        fill="transparent"
                        stroke="#f43f5e"
                        strokeWidth="9"
                        strokeDasharray={`${malStroke} ${donutCircumference - malStroke}`}
                        strokeDashoffset="0"
                        strokeLinecap="round"
                      />
                      {/* Suspicious Arc */}
                      <circle
                        cx="48"
                        cy="48"
                        r={donutR}
                        fill="transparent"
                        stroke="#f59e0b"
                        strokeWidth="9"
                        strokeDasharray={`${suspStroke} ${donutCircumference - suspStroke}`}
                        strokeDashoffset={-malStroke}
                        strokeLinecap="round"
                      />
                      {/* Benign Arc */}
                      <circle
                        cx="48"
                        cy="48"
                        r={donutR}
                        fill="transparent"
                        stroke="#10b981"
                        strokeWidth="9"
                        strokeDasharray={`${benStroke} ${donutCircumference - benStroke}`}
                        strokeDashoffset={-(malStroke + suspStroke)}
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute flex flex-col items-center justify-center text-center">
                      <span className="text-sm font-black text-white font-mono leading-none">
                        {executive_kpis.total_runs}
                      </span>
                      <span className="text-[8px] font-mono text-gray-400 tracking-tighter">RUNS</span>
                    </div>
                  </div>
                </div>

                {/* Graph B: Gate 03 Triage Decision Breakdown */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-gray-800/80 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-1.5 text-xs font-mono font-semibold text-gray-300">
                      <BarChart3 className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Decision Split</span>
                    </div>
                    <span className="text-[10px] font-mono text-indigo-400">τ = {trust_distribution.threshold}</span>
                  </div>

                  <div className="space-y-2 font-mono text-xs">
                    {/* Auto-Suggest Capable */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" /> Auto-Suggest Capable
                        </span>
                        <span className="text-white font-bold">{executive_kpis.auto_suggest_rate_pct}%</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-gray-900 overflow-hidden border border-gray-800">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-emerald-600 to-teal-400"
                          style={{ width: `${Math.max(executive_kpis.auto_suggest_rate_pct, 2)}%` }}
                        />
                      </div>
                    </div>

                    {/* Mandatory Human Escalation */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px]">
                        <span className="text-amber-400 flex items-center gap-1">
                          <XCircle className="h-3 w-3" /> Human Escalation
                        </span>
                        <span className="text-white font-bold">{executive_kpis.escalated_rate_pct}%</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-gray-900 overflow-hidden border border-gray-800">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-amber-600 to-orange-400"
                          style={{ width: `${Math.max(executive_kpis.escalated_rate_pct, 2)}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[10px] font-mono text-gray-400 pt-1 border-t border-gray-800/60">
                    <span>Mean: <strong className="text-indigo-300">{executive_kpis.mean_trust_score.toFixed(3)}</strong></span>
                    <span>Median: <strong className="text-indigo-300">{executive_kpis.median_trust_score.toFixed(3)}</strong></span>
                    <span>Std Dev: <strong className="text-gray-300">±{executive_kpis.std_dev_trust.toFixed(3)}</strong></span>
                  </div>
                </div>
              </div>
            </div>

            {/* Triggered Reason Codes Distribution */}
            <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  Gate 03 Reason Codes
                </h3>
                <p className="text-xs text-gray-400">Diagnostic escalation triggers</p>
              </div>

              <div className="space-y-2.5 pt-2">
                {Object.keys(trust_distribution.reason_codes).length === 0 ? (
                  <div className="py-8 text-center text-xs text-gray-500 font-mono">
                    No diagnostic penalty reason codes triggered in current runs.
                  </div>
                ) : (
                  Object.entries(trust_distribution.reason_codes).map(([rc, count]) => (
                    <div key={rc} className="p-2.5 rounded-lg bg-slate-950 border border-gray-800 space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-amber-300 font-semibold text-[11px] truncate max-w-[200px]" title={rc}>
                          {rc}
                        </span>
                        <span className="text-gray-300 font-bold">{count}x</span>
                      </div>
                      <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
                        <div
                          className="h-full rounded-full bg-amber-400"
                          style={{
                            width: `${Math.min(100, (count / Math.max(1, total_runs)) * 100)}%`,
                          }}
                        />
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Premier Chart: Sequential Trust Score Trajectory & Safety Horizon Graph */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center space-x-2">
                  <TrendingUp className="h-5 w-5 text-cyan-400" />
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                    Sequential Trust Score Trajectory & Decision Horizon
                  </h3>
                </div>
                <p className="text-xs text-gray-400">
                  Continuous incident trust evaluation vs deterministic Gate 03 threshold boundary (τ = {trust_distribution.threshold})
                </p>
              </div>

              <div className="flex items-center flex-wrap gap-2 text-xs font-mono">
                <span className="px-2.5 py-1 rounded bg-slate-950 border border-gray-800 text-gray-300">
                  Peak: <strong className="text-emerald-400">{maxTrustRun.trust_score.toFixed(2)}</strong>
                </span>
                <span className="px-2.5 py-1 rounded bg-slate-950 border border-gray-800 text-gray-300">
                  Min: <strong className="text-amber-400">{minTrustRun.trust_score.toFixed(2)}</strong>
                </span>
                <span className="px-2.5 py-1 rounded bg-emerald-950/70 border border-emerald-800/60 text-emerald-300 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  T ≥ {trust_distribution.threshold} Auto-Suggest
                </span>
                <span className="px-2.5 py-1 rounded bg-amber-950/70 border border-amber-800/60 text-amber-300 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                  T &lt; {trust_distribution.threshold} Escalated
                </span>
              </div>
            </div>

            {/* Interactive SVG Trend Chart */}
            <div className="relative bg-slate-950/90 rounded-xl border border-gray-800/80 p-3 overflow-hidden">
              <svg
                viewBox={`0 0 ${svgW} ${svgH}`}
                className="w-full h-44 sm:h-52"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id="trustAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.35" />
                    <stop offset="65%" stopColor="#3b82f6" stopOpacity="0.10" />
                    <stop offset="100%" stopColor="#0284c7" stopOpacity="0.0" />
                  </linearGradient>
                  <filter id="trustGlow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Shaded Background Zones */}
                <rect
                  x={pL}
                  y={pT}
                  width={cW}
                  height={Math.max(0, tauY - pT)}
                  fill="rgba(16, 185, 129, 0.035)"
                />
                <rect
                  x={pL}
                  y={tauY}
                  width={cW}
                  height={Math.max(0, pT + cH - tauY)}
                  fill="rgba(245, 158, 11, 0.035)"
                />

                {/* Horizontal Gridlines & Y-Axis Ticks */}
                {[1.0, 0.75, 0.5, 0.25, 0.0].map((level) => {
                  const y = pT + cH * (1 - level);
                  return (
                    <g key={level}>
                      <line
                        x1={pL}
                        y1={y}
                        x2={svgW - pR}
                        y2={y}
                        stroke="#1e293b"
                        strokeWidth="1"
                        strokeDasharray={level === 0.0 || level === 1.0 ? '0' : '3 3'}
                      />
                      <text
                        x={pL - 8}
                        y={y + 3.5}
                        textAnchor="end"
                        className="text-[9px] fill-gray-500 font-mono"
                      >
                        {level.toFixed(2)}
                      </text>
                    </g>
                  );
                })}

                {/* Gate 03 Threshold Boundary Line */}
                <line
                  x1={pL}
                  y1={tauY}
                  x2={svgW - pR}
                  y2={tauY}
                  stroke="#06b6d4"
                  strokeWidth="1.5"
                  strokeDasharray="5 4"
                />
                <text
                  x={svgW - pR - 4}
                  y={tauY - 6}
                  textAnchor="end"
                  className="text-[10px] fill-cyan-400 font-mono font-semibold"
                >
                  τ = {thresholdVal.toFixed(2)} Gate Boundary
                </text>

                {/* Gradient Fill Under Curve */}
                {areaD && <path d={areaD} fill="url(#trustAreaGrad)" />}

                {/* Main Curve Line */}
                {pathD && (
                  <path
                    d={pathD}
                    fill="none"
                    stroke="#38bdf8"
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    filter="url(#trustGlow)"
                  />
                )}

                {/* Interactive Points */}
                {computedPoints.map((pt, i) => {
                  const isHovered = hoveredTrustPoint?.index === i;
                  const isAuto = pt.trust_score >= thresholdVal;
                  return (
                    <g key={i}>
                      {isHovered && (
                        <line
                          x1={pt.x}
                          y1={pT}
                          x2={pt.x}
                          y2={pT + cH}
                          stroke="#64748b"
                          strokeWidth="1"
                          strokeDasharray="2 2"
                        />
                      )}
                      <circle
                        cx={pt.x}
                        cy={pt.y}
                        r={isHovered ? 6.5 : 4}
                        fill={isAuto ? '#10b981' : '#f59e0b'}
                        stroke="#0f172a"
                        strokeWidth="2"
                        className="cursor-pointer transition-all duration-150"
                        onMouseEnter={() =>
                          setHoveredTrustPoint({
                            index: i,
                            score: pt.trust_score,
                            incidentId: pt.incident_id,
                            verdict: pt.verdict,
                            severity: pt.severity,
                            signature: pt.signature,
                            decision: pt.decision,
                            x: pt.x,
                            y: pt.y,
                          })
                        }
                        onMouseLeave={() => setHoveredTrustPoint(null)}
                        onClick={() => onSelectIncident(pt.incident_id)}
                      />
                    </g>
                  );
                })}
              </svg>

              {/* Floating Tooltip when hovering point */}
              {hoveredTrustPoint && (
                <div
                  className="absolute z-20 pointer-events-none p-3 rounded-lg bg-slate-900/95 border border-cyan-500/50 shadow-2xl backdrop-blur-md text-xs font-mono space-y-1 transform -translate-x-1/2 -translate-y-full"
                  style={{
                    left: `${(hoveredTrustPoint.x / svgW) * 100}%`,
                    top: `${Math.max(15, (hoveredTrustPoint.y / svgH) * 100 - 10)}%`,
                  }}
                >
                  <div className="flex items-center justify-between gap-3 border-b border-gray-800 pb-1">
                    <span className="font-bold text-white truncate max-w-[150px]">
                      {hoveredTrustPoint.incidentId}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        hoveredTrustPoint.score >= thresholdVal
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                          : 'bg-amber-950 text-amber-300 border border-amber-700'
                      }`}
                    >
                      T = {hoveredTrustPoint.score.toFixed(3)}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-300 truncate max-w-[200px]">
                    {hoveredTrustPoint.signature}
                  </p>
                  <div className="flex items-center gap-2 pt-1 text-[10px]">
                    <span className={getVerdictBadge(hoveredTrustPoint.verdict)}>
                      {hoveredTrustPoint.verdict}
                    </span>
                    <span className={getSeverityBadge(hoveredTrustPoint.severity)}>
                      {hoveredTrustPoint.severity}
                    </span>
                    <span className="text-gray-400">
                      {hoveredTrustPoint.score >= thresholdVal ? 'Auto-Suggest' : 'Escalate'}
                    </span>
                  </div>
                </div>
              )}
            </div>
            <div className="flex items-center justify-between text-[11px] font-mono text-gray-500 px-1">
              <span>Timeline of Triaged Incidents</span>
              <span className="text-cyan-400/80">Click point to inspect incident details in dossier</span>
            </div>
          </div>
        </div>
      )}

      {/* 4. Sub-Section: 6x6 Domain Specialist Co-Activation Heatmap */}
      {(activeSubTab === 'all' || activeSubTab === 'routing') && (
        <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <Flame className="h-5 w-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  6×6 Domain Specialist Co-Activation Heatmap Matrix
                </h3>
              </div>
              <p className="text-xs text-gray-400">
                Shows co-occurrence frequency of domain specialists simultaneously activated by the ML Multi-Label Router (P ≥ 0.50).
              </p>
            </div>

            {hoveredCell && (
              <div className="px-3 py-1.5 rounded-lg bg-cyan-950/80 border border-cyan-700/60 text-xs font-mono text-cyan-300">
                Pair: <strong className="text-white">{domainLabels[hoveredCell.d1]}</strong> +{' '}
                <strong className="text-white">{domainLabels[hoveredCell.d2]}</strong> →{' '}
                <strong className="text-cyan-400">{hoveredCell.count} co-activations</strong>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
            {/* Heatmap Grid */}
            <div className="lg:col-span-2 overflow-x-auto">
              <div className="min-w-[500px]">
                {/* Header Row */}
                <div className="grid grid-cols-7 gap-1.5 mb-1.5 text-center text-[11px] font-mono text-gray-400 font-semibold">
                  <div className="text-left pl-2 text-gray-500">Domain \ Domain</div>
                  {domain_routing_analytics.domain_names.map((d) => (
                    <div key={d} className="truncate px-1 py-1" title={domainLabels[d]}>
                      {domainLabels[d].slice(0, 7)}
                    </div>
                  ))}
                </div>

                {/* Heatmap Rows */}
                {domain_routing_analytics.domain_names.map((d1, i) => (
                  <div key={d1} className="grid grid-cols-7 gap-1.5 mb-1.5 text-center text-xs font-mono">
                    <div className="text-left text-[11px] text-gray-300 font-semibold flex items-center pl-2 truncate" title={domainLabels[d1]}>
                      {domainLabels[d1]}
                    </div>
                    {domain_routing_analytics.domain_names.map((d2, j) => {
                      const count = domain_routing_analytics.co_activation_matrix[i][j];
                      const colorClass = getHeatmapColor(count, maxMatrixVal);
                      const isDiagonal = i === j;
                      return (
                        <div
                          key={d2}
                          onMouseEnter={() => setHoveredCell({ d1, d2, count })}
                          onMouseLeave={() => setHoveredCell(null)}
                          className={`h-11 rounded-lg border flex flex-col items-center justify-center cursor-pointer transition-all duration-200 transform hover:scale-105 ${colorClass}`}
                          title={`${domainLabels[d1]} & ${domainLabels[d2]}: ${count} incidents`}
                        >
                          <span className="text-xs">{count}</span>
                          {isDiagonal && <span className="text-[9px] opacity-70">self</span>}
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>

            {/* Individual Domain Activation Frequencies */}
            <div className="p-5 rounded-xl bg-slate-950 border border-gray-800 space-y-4">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono">
                Individual Activation Rates & Router Confidence
              </h4>
              <div className="space-y-3.5">
                {domain_routing_analytics.domain_names.map((d) => {
                  const count = domain_routing_analytics.domain_activation_counts[d] || 0;
                  const pct = domain_routing_analytics.domain_activation_pct[d] || 0;
                  const conf = domain_routing_analytics.avg_domain_confidences[d] || 0;
                  return (
                    <div key={d} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-gray-200 font-medium">{domainLabels[d]}</span>
                        <span className="text-gray-400">
                          <strong className="text-white">{count}</strong> ({pct}%) • Avg P: {(conf * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
                        <div
                          className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400"
                          style={{ width: `${Math.max(pct, 2)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5. Sub-Section: MITRE ATT&CK Threat Matrix & Tactic Breakdown */}
      {(activeSubTab === 'all' || activeSubTab === 'mitre') && (
        <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-6">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Target className="h-5 w-5 text-rose-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                MITRE ATT&CK Threat Kill-Chain & Technique Frequency
              </h3>
            </div>
            <p className="text-xs text-gray-400">
              Aggregated technique detection across multi-agent consensus and correlation engine.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Technique Frequency List */}
            <div className="lg:col-span-2 space-y-3">
              {mitre_attack_analytics.technique_frequencies.length === 0 ? (
                <div className="py-8 text-center text-xs text-gray-500 font-mono">
                  No MITRE ATT&CK techniques mapped in current incident store.
                </div>
              ) : (
                mitre_attack_analytics.technique_frequencies.map((tech) => (
                  <div
                    key={tech.technique_id}
                    className="p-3.5 rounded-xl bg-slate-950 border border-gray-800 hover:border-gray-700 transition flex items-center justify-between gap-4"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center space-x-2.5">
                        <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/60 text-xs font-mono font-bold">
                          {tech.technique_id}
                        </span>
                        <span className="text-sm font-semibold text-white truncate">{tech.name}</span>
                      </div>
                      <p className="text-xs text-gray-400 font-mono">Tactic: {tech.tactic}</p>
                    </div>

                    <div className="text-right font-mono flex-shrink-0">
                      <div className="text-lg font-black text-rose-400">{tech.count}</div>
                      <div className="text-[10px] text-gray-500">detections</div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Tactic Distribution Summary */}
            <div className="p-5 rounded-xl bg-slate-950 border border-gray-800 space-y-4">
              <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider font-mono">
                Kill-Chain Tactic Breakdown
              </h4>
              <div className="space-y-3">
                {Object.entries(mitre_attack_analytics.tactic_distribution).map(([tactic, count]) => (
                  <div key={tactic} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-gray-300">{tactic}</span>
                      <span className="text-white font-bold">{count}</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-rose-500"
                        style={{ width: `${Math.min(100, (count / Math.max(1, total_runs)) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 6. Sub-Section: Pipeline Performance & Latency Telemetry */}
      {(activeSubTab === 'all' || activeSubTab === 'latency') && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Stage-wise Latency Breakdown & Proportional Waterfall Graph */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
            <div className="space-y-0.5">
              <div className="flex items-center space-x-2">
                <Clock className="h-5 w-5 text-purple-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Stage-Wise Pipeline Latency Breakdown
                </h3>
              </div>
              <p className="text-xs text-gray-400">Mean processing duration & proportional time consumption</p>
            </div>

            {/* Proportional Stacked Waterfall Bar */}
            <div className="space-y-1.5 pt-1">
              <div className="flex justify-between text-[11px] font-mono text-gray-400">
                <span>Orchestrator Stage Share</span>
                <span className="text-purple-300 font-bold">{totalStageLatencyMs.toFixed(1)} ms total</span>
              </div>
              <div className="h-3.5 w-full rounded-full bg-gray-950 border border-gray-800 flex overflow-hidden">
                {stageBreakdownEntries.map(([stage, dur], idx) => {
                  const pct = Math.max(1, (dur / totalStageLatencyMs) * 100);
                  const colors = [
                    'bg-blue-500',
                    'bg-cyan-400',
                    'bg-indigo-500',
                    'bg-purple-500',
                    'bg-emerald-400',
                  ];
                  return (
                    <div
                      key={stage}
                      className={`${colors[idx % colors.length]} h-full transition-all duration-500 hover:brightness-125 cursor-pointer`}
                      style={{ width: `${pct}%` }}
                      title={`${stage.replace('_', ' ')}: ${dur.toFixed(2)} ms (${pct.toFixed(1)}%)`}
                    />
                  );
                })}
              </div>
            </div>

            <div className="space-y-2.5 pt-2">
              {stageBreakdownEntries.map(([stage, dur], idx) => {
                const pct = ((dur / totalStageLatencyMs) * 100).toFixed(1);
                const dotColors = [
                  'bg-blue-500',
                  'bg-cyan-400',
                  'bg-indigo-500',
                  'bg-purple-500',
                  'bg-emerald-400',
                ];
                return (
                  <div key={stage} className="p-2.5 rounded-lg bg-slate-950 border border-gray-800/90 space-y-1">
                    <div className="flex justify-between items-center text-xs font-mono">
                      <span className="text-gray-300 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                        <span className={`h-2 w-2 rounded-full ${dotColors[idx % dotColors.length]}`} />
                        {stage.replace('_', ' ')}
                      </span>
                      <span className="text-purple-300 font-bold">
                        {dur.toFixed(2)} ms <span className="text-gray-500 font-normal text-[10px]">({pct}%)</span>
                      </span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-gray-900 overflow-hidden">
                      <div
                        className={`h-full rounded-full ${dotColors[idx % dotColors.length]}`}
                        style={{ width: `${Math.max(Number(pct), 2)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Containment Actions Distribution */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
            <div className="flex items-center space-x-2">
              <Zap className="h-5 w-5 text-amber-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Recommended Actions
              </h3>
            </div>
            <p className="text-xs text-gray-400">Remediation playbook action types</p>

            <div className="space-y-2.5 pt-2">
              {Object.keys(containment_action_analytics.action_types_distribution).length === 0 ? (
                <div className="py-8 text-center text-xs text-gray-500 font-mono">
                  No playbook actions generated yet.
                </div>
              ) : (
                Object.entries(containment_action_analytics.action_types_distribution).map(
                  ([act, count]) => (
                    <div key={act} className="flex justify-between items-center p-2.5 rounded bg-slate-950 border border-gray-800 text-xs font-mono">
                      <span className="text-gray-200">{act}</span>
                      <span className="px-2 py-0.5 rounded bg-blue-950 text-cyan-300 font-bold">
                        {count}x
                      </span>
                    </div>
                  )
                )
              )}
            </div>
          </div>

          {/* Approvals Velocity Summary */}
          <div className="p-6 rounded-xl bg-slate-900/80 border border-gray-800 shadow-xl space-y-4">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Approval Gate Velocity
              </h3>
            </div>
            <p className="text-xs text-gray-400">Analyst cryptographic sign-off status</p>

            <div className="space-y-3 pt-2">
              <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 flex items-center justify-between text-xs font-mono">
                <span className="text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" /> Approved & Executed
                </span>
                <span className="text-emerald-400 font-bold text-base">
                  {executive_kpis.approvals_summary.approved}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-800/60 flex items-center justify-between text-xs font-mono">
                <span className="text-amber-300 flex items-center gap-2">
                  <Clock className="h-4 w-4" /> Awaiting Analyst Review
                </span>
                <span className="text-amber-400 font-bold text-base">
                  {executive_kpis.approvals_summary.pending}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 flex items-center justify-between text-xs font-mono">
                <span className="text-rose-300 flex items-center gap-2">
                  <XCircle className="h-4 w-4" /> Rejected / False Positives
                </span>
                <span className="text-rose-400 font-bold text-base">
                  {executive_kpis.approvals_summary.rejected}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 7. Sub-Section: Real-Time Incident Telemetry Stream Table */}
      {(activeSubTab === 'all' || activeSubTab === 'runs') && (
        <div className="rounded-xl border border-gray-800 bg-slate-900/80 overflow-hidden shadow-2xl space-y-0">
          <div className="p-4 bg-gray-950 border-b border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-wider text-gray-300 font-mono">
                Chronological Incident Telemetry Stream ({incident_runs.length} Runs Recorded)
              </span>
            </div>
            <span className="text-xs text-gray-500 font-mono">Click row to open Investigation Dossier</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-gray-950/60 font-mono text-gray-400 border-b border-gray-800 uppercase">
                <tr>
                  <th className="px-5 py-3">#</th>
                  <th className="px-5 py-3">Signature / Title</th>
                  <th className="px-5 py-3">Format</th>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3">Verdict</th>
                  <th className="px-5 py-3">Trust Score</th>
                  <th className="px-5 py-3">Active Specialists</th>
                  <th className="px-5 py-3">Routing Latency</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {incident_runs.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-5 py-8 text-center text-gray-500 font-mono">
                      No incidents recorded yet. Click "Ingest Batch Benchmark Corpus" above to run test scenarios.
                    </td>
                  </tr>
                ) : (
                  incident_runs.map((inc) => (
                    <tr
                      key={inc.incident_id}
                      onClick={() => onSelectIncident(inc.incident_id)}
                      className="hover:bg-blue-950/30 cursor-pointer transition-colors"
                    >
                      <td className="px-5 py-3.5 font-mono text-gray-500">{inc.run_index}</td>
                      <td className="px-5 py-3.5 font-semibold text-white max-w-xs truncate" title={inc.signature}>
                        {inc.signature}
                      </td>
                      <td className="px-5 py-3.5 font-mono uppercase text-gray-400">
                        {inc.source_format}
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${getSeverityBadge(inc.severity)}`}>
                          {inc.severity}
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border ${getVerdictBadge(inc.verdict)}`}>
                          {inc.verdict}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 font-mono font-bold">
                        <span className={inc.trust_score >= 0.65 ? 'text-emerald-400' : 'text-amber-400'}>
                          {inc.trust_score.toFixed(3)}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 font-mono text-cyan-300">
                        {inc.domains_count} specialists
                      </td>
                      <td className="px-5 py-3.5 font-mono text-gray-400">
                        {inc.latency_ms.toFixed(2)} ms
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectIncident(inc.incident_id);
                          }}
                          className="px-2.5 py-1 rounded bg-blue-950/80 hover:bg-blue-800 text-cyan-300 border border-blue-700/60 text-[11px] font-mono flex items-center space-x-1 ml-auto"
                        >
                          <span>Dossier</span>
                          <ExternalLink className="h-3 w-3" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
