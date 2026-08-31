# ADR 0002: Deterministic Mathematical Trust Score Engine (Gate 03)

## Context and Problem Statement
LLMs are notoriously prone to uncalibrated overconfidence, hallucination, and prompt manipulation. If an LLM is permitted to self-report or decide whether a security remediation is trusted or should execute, adversaries can bypass security controls or benign system noise could trigger catastrophic outages.

## Considered Options
1. **LLM-Judged Confidence:** Prompting a supervisor LLM: *"Rate your confidence on a scale of 0 to 1 and decide if human approval is needed."*
2. **Simple Rule Threshold:** Fixed threshold based purely on raw alert severity.
3. **Deterministic Multi-Factor Mathematical Trust Score Engine:** Closed-form formula $T = \text{clamp}_{[0, 1]}(w_C C_{\text{consensus}} + w_H H - w_S S_{\text{penalty}})$ combining agent consensus, empirical vector memory similarity, and asset criticality.

## Decision Outcome
Chosen option: **Option 3: Deterministic Multi-Factor Mathematical Trust Score Engine**.
- **No LLM in the Loop for Scoring:** The Trust Score calculation is implemented in 100% deterministic Python arithmetic.
- **Explainability:** Components ($C_{\text{consensus}}, H, S_{\text{penalty}}$), reason codes, and weights are fully exposed and auditable.
- **Repeatability:** Given the same agent findings, historical vectors, and asset metadata, the score is identical across runs.

## Consequences
- **Positive:** Immune to LLM confidence hallucination; fully testable via unit test suites; provides a mathematically rigorous contribution for academic research publication.
- **Negative:** Requires calibration of weight parameters ($w_C, w_H, w_S$) and threshold $\tau$ across empirical dataset sweeps.
