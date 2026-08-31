# Research Evaluation Plan & Experimental Protocol

**Document Version:** 1.0.0  
**Target:** Academic Conference / Journal Publication Benchmark Protocol  
**Reproducibility Standard:** Deterministic, Scripted, Seeded Dataset Benchmarks  

---

## 1. Experimental Objectives

This evaluation protocol validates the core hypothesis of the research project:
> **Hypothesis:** An adaptive multi-label ML router coupled with domain-specialist agents, historical vector memory, and a deterministic Trust Score engine achieves equal or superior triage precision compared to brute-force all-agent LLM systems, while reducing token expenditure and operational latency by >60% and enforcing strict human safety boundaries.

---

## 2. Baselines for Comparative Analysis

The framework natively implements and benchmarks four distinct architectural configurations:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            EVALUATION BASELINES                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ Baseline A: Static / Rule-Based SOAR                                        │
│   - Deterministic keyword and regex matching against alert signatures.      │
│   - No LLM reasoning, no vector memory. Brittle under novel variations.     │
├─────────────────────────────────────────────────────────────────────────────┤
│ Baseline B: Single General-Purpose LLM                                      │
│   - Monolithic prompt passed to a single general-purpose LLM instance.      │
│   - No domain decomposition, arbitrary self-reported confidence.            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Baseline C: All Specialists in Parallel (Brute Force Multi-Agent)            │
│   - Ingestion activates ALL 6 specialist agents for every incoming alert.   │
│   - High accuracy, but maximum token cost, API calls, and latency.          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Proposed System: Adaptive Trust-Aware Multi-Agent Framework                 │
│   - ML Multi-Label Router invokes only relevant specialists (P >= 0.50).    │
│   - pgvector Historical Precedent Retrieval (H).                            │
│   - Deterministic Trust Score Engine (Gate 03).                             │
│   - Hard Human Approval Gate.                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Evaluation Metrics

### 3.1 Triage & Classification Metrics
- **Precision, Recall, F1 (Macro & Micro):** Evaluated against ground-truth analyst verdicts (`MALICIOUS` vs `BENIGN` vs `SUSPICIOUS`).
- **Routing Accuracy & Hamming Loss:** Evaluates the multi-label router's ability to select the exact necessary domain specialists without omission or excess.
- **MITRE Technique Coverage:** Precision and Recall of detected ATT&CK technique IDs against ground truth attack scenario annotations.

### 3.2 Operational & Efficiency Metrics
- **Mean & P95 Triage Latency (seconds):** Total wall-clock time from raw alert ingestion to final playbook generation.
- **Agent Invocation Factor:** Average number of domain specialists spawned per alert (Theoretical min: 1.0, Max: 6.0).
- **External Tool / API Calls:** Number of external threat intel requests executed.
- **Token Consumption & Cost:** Total input/output LLM tokens per alert, translated to USD cost per 10,000 alerts.

### 3.3 Human Factors & Operational Safety
- **Escalation Rate (%):** Percentage of alerts escalated to Tier-2/3 human analysts ($T < 0.65$).
- **Analyst Workload Reduction (%):** Measured reduction in manual investigation steps for high-trust cases ($T \ge 0.65$).
- **False Auto-Suggestion Rate (FASR):** Proportion of benign or ambiguous alerts incorrectly auto-suggested as confident malicious playbooks (Target: $< 2.0\%$).
- **Safety Invariant Violations:** Count of unapproved response actions executed (Target: Absolute 0).

### 3.4 Trust & Calibration Metrics
- **Expected Calibration Error (ECE):**
  $$\text{ECE} = \sum_{m=1}^B \frac{|B_m|}{N} |\text{acc}(B_m) - \text{conf}(B_m)|$$
- **Brier Score:** Mean squared difference between predicted Trust Score $T$ and binary incident verification outcome.
- **Threshold Sensitivity Curve:** Trade-off analysis plotting FASR vs Analyst Escalation Rate across $\tau \in [0.40, 0.90]$.

---

## 4. Benchmark Datasets

| Dataset | Source / Type | Scale in Benchmark | Primary Evaluation Focus |
| :--- | :--- | :--- | :--- |
| **Splunk BOTS v2** | Real-world enterprise attack dataset (JSON events) | 250 curated scenarios | Endpoint, Lateral Movement, PowerShell, Ransomware |
| **CSE-CIC-IDS2018** | Realistic Network Flow + IDS dataset | 300 curated flow events | DDoS, Botnet, Infiltration, Web Attacks, Brute Force |
| **Synthetic Benchmark** | Deterministic, structured JSON test fixture | 150 diverse multi-domain incidents | Full CI/CD unit testing, edge cases, contradiction testing |

---

## 5. Experiment Execution & Reproducibility Pipeline

The evaluation is executed via an automated CLI test harness (`scripts/evaluate.py`):

```bash
python scripts/evaluate.py \
  --dataset data/processed/benchmark_suite.json \
  --baselines A,B,C,PROPOSED \
  --trials 5 \
  --seed 42 \
  --output docs/research/benchmark_results.json
```

### Reproducibility Tracking Schema
Every evaluation run outputs a structured JSON artifact containing:
- `timestamp_utc`: ISO-8601 timestamp
- `git_commit_sha`: Git commit hash
- `random_seed`: Deterministic seed
- `model_metadata`: ML router version, weights, hyperparameters
- `baseline_comparisons`: Full tabular breakdown across all metrics
- `statistical_significance`: Paired t-test and Wilcoxon signed-rank p-values
