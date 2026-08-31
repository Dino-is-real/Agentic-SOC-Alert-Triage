# ADR 0006: Multi-Label Gradient Boosting Classifier for Adaptive Specialist Routing

## Context and Problem Statement
Invoking all 6 specialist domain agents (Network, Endpoint, Identity, Cloud, Malware, Threat Intel) for every incoming alert creates massive LLM token overhead, high latency, and rate-limiting issues. A lightweight, high-speed, calibrated multi-label router is required to adaptively dispatch only the specialists relevant to the specific alert context.

## Considered Options
1. **LLM Supervisor Routing:** Passing the alert to an LLM router to output a JSON list of domains.
2. **Static Regex/Keyword Rule Router:** Hardcoded mapping rules based on signature strings.
3. **Calibrated Multi-Label Gradient Boosting Classifier:** Scikit-learn `OneVsRestClassifier(GradientBoostingClassifier)` or `HistGradientBoostingClassifier` with TF-IDF feature extraction and Platt scaling probability calibration.

## Decision Outcome
Chosen option: **Option 3: Calibrated Multi-Label Gradient Boosting Classifier**.
- **Ultra-Low Latency:** Inference completes in $< 5$ milliseconds (compared to 1.5–3.0 seconds for an LLM supervisor).
- **Zero Token Cost:** Routing incurs $0.00 in LLM API costs.
- **Calibrated Probabilities:** Outputs well-calibrated posterior probabilities $P(D_i \mid x) \in [0, 1]$, enabling threshold-based tuning and fallback safety policies.
- **Empirical Tracking:** Enables direct tracking of Multi-label F1, Hamming Loss, and Subset Accuracy.

## Consequences
- **Positive:** Reduces overall pipeline LLM token consumption by $> 60\%$; sub-millisecond dispatch time; reproducible offline training.
- **Negative:** Requires a labeled multi-domain alert dataset for model training and retraining pipelines.
