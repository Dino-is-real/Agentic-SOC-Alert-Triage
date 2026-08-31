# Trust Score Engine Specification & Mathematical Formulation

**Document Version:** 1.0.0  
**Service ID:** `Gate-03-Trust-Engine`  
**Classification:** Research Core & Deterministic Safety Gate  

---

## 1. Mathematical Formulation

The Trust Score $T$ quantifies the objective, evidence-grounded confidence of the multi-agent assessment before determining whether a remediation playbook may be **auto-suggested** or must be **escalated to a human analyst**.

$$T = \text{clamp}_{[0, 1]}\Big( (w_C \cdot C_{\text{consensus}}) + (w_H \cdot H) - (w_S \cdot S_{\text{penalty}}) \Big)$$

where:
- $C_{\text{consensus}} \in [0, 1]$ is the **Agent Consensus Score**.
- $H \in [0, 1]$ is the **Historical Precedent Similarity Score**.
- $S_{\text{penalty}} \in [0, 1]$ is the **Asset Criticality & Severity Impact Penalty**.
- $w_C, w_H, w_S \ge 0$ are the **Component Weights**, subject to $w_C + w_H = 0.80$, with default values:
  $$w_C = 0.50, \quad w_H = 0.30, \quad w_S = 0.20$$
- $\text{clamp}_{[0, 1]}(x) = \max(0.0, \min(1.0, x))$.

---

## 2. Component Definitions

### 2.1 Agent Consensus Score ($C_{\text{consensus}}$)

Let $A = \{a_1, a_2, \dots, a_M\}$ be the set of active domain specialist agents invoked by the router ($M = |A| \ge 1$).  
Each agent $a_i$ outputs a verdict $v_i \in \{\text{MALICIOUS}, \text{SUSPICIOUS}, \text{BENIGN}, \text{INSUFFICIENT\_DATA}\}$ and a calibrated confidence $c_i \in [0, 1]$.

#### Numerical Verdict Mapping:
$$\mu(v_i) = \begin{cases} 
1.0 & \text{if } v_i = \text{MALICIOUS} \\
0.5 & \text{if } v_i = \text{SUSPICIOUS} \\
0.0 & \text{if } v_i = \text{BENIGN} \\
0.25 & \text{if } v_i = \text{INSUFFICIENT\_DATA}
\end{cases}$$

#### Weighted Mean Verdict & Agreement:
1. **Weighted Average Score:**
   $$\bar{\mu} = \frac{\sum_{i=1}^M c_i \cdot \mu(v_i)}{\sum_{i=1}^M c_i + \epsilon}$$
2. **Inter-Agent Variance & Contradiction Penalty:**
   $$\sigma^2 = \frac{\sum_{i=1}^M c_i \cdot (\mu(v_i) - \bar{\mu})^2}{\sum_{i=1}^M c_i + \epsilon}$$
   The contradiction penalty $\Delta_{\text{conflict}} = \min(1.0, 2.0 \cdot \sqrt{\sigma^2})$.
3. **Uncertainty Factor Penalty:**
   Let $u_i \in [0, 1]$ be the proportion of declared uncertainty factors for agent $i$:
   $$\bar{u} = \frac{1}{M} \sum_{i=1}^M u_i$$
4. **Final Consensus Computation:**
   $$C_{\text{consensus}} = \max\left(0.0, \left( \frac{1}{M} \sum_{i=1}^M c_i \right) \cdot (1.0 - \Delta_{\text{conflict}}) \cdot (1.0 - 0.5 \cdot \bar{u}) \right)$$

*Edge Case ($M = 1$):* When only a single specialist is invoked (e.g., pure Network scan), $\sigma^2 = 0$, so $C_{\text{consensus}} = c_1 \cdot (1.0 - 0.5 \cdot u_1) \cdot \lambda_{\text{single}}$ where $\lambda_{\text{single}} = 0.90$ (a 10% penalty reflecting lack of multi-domain corroboration).

---

### 2.2 Historical Precedent Similarity ($H$)

Let $K$ be the number of top nearest-neighbor historical incidents retrieved from pgvector via cosine distance:
$$\text{sim}(\mathbf{v}_{\text{query}}, \mathbf{v}_{\text{hist}}^{(k)}) = \frac{\mathbf{v}_{\text{query}} \cdot \mathbf{v}_{\text{hist}}^{(k)}}{\|\mathbf{v}_{\text{query}}\| \|\mathbf{v}_{\text{hist}}^{(k)}\|}$$

1. **Similarity Score:**
   $$H = \begin{cases}
   \frac{1}{K} \sum_{k=1}^K \text{sim}(\mathbf{v}_{\text{query}}, \mathbf{v}_{\text{hist}}^{(k)}) \cdot \rho_k & \text{if } K > 0 \\
   0.0 & \text{if } K = 0 \text{ (Cold Start)}
   \end{cases}$$
   where $\rho_k \in [0, 1]$ is the historical case outcome quality factor ($\rho_k = 1.0$ if the historical incident was verified by an analyst and successfully resolved; $\rho_k = 0.5$ if the historical case was inconclusive).
2. **Cold Start Policy:** If no historical precedents exist ($K=0$), $H=0.0$. In this case, the system flags reason code `RC_COLD_START_NO_HISTORY`, ensuring that novel attacks default to human review unless agent consensus is overwhelming.

---

### 2.3 Asset Criticality & Severity Penalty ($S_{\text{penalty}}$)

High-criticality assets (e.g., Domain Controllers, Payment Gateways) and high-severity signatures require higher confidence before auto-suggestion is safe.

$$S_{\text{penalty}} = \alpha \cdot \text{Criticality}_{\text{asset}} + (1 - \alpha) \cdot \text{Severity}_{\text{alert}}$$

where:
- $\alpha = 0.60$.
- $\text{Criticality}_{\text{asset}} \in \{ \text{CRITICAL}: 1.0, \text{HIGH}: 0.75, \text{MEDIUM}: 0.40, \text{LOW}: 0.10 \}$.
- $\text{Severity}_{\text{alert}} \in \{ \text{CRITICAL}: 1.0, \text{HIGH}: 0.75, \text{MEDIUM}: 0.50, \text{LOW}: 0.20 \}$.

---

## 3. Decision Gate 03 Logic

```python
THRESHOLD_DEFAULT = 0.65

if trust_score >= THRESHOLD_DEFAULT:
    decision = TrustDecision.AUTO_SUGGEST
    reason = "Trust Score exceeds safety threshold. Staging remediation playbook for human authorization."
else:
    decision = TrustDecision.ESCALATE_TO_HUMAN
    reason = "Trust Score below threshold. Escalating to Tier-2 analyst due to uncertainty/conflict."
```

### Safety Invariants:
1. **Never Autonomous:** Even if $T = 1.0$, the system *never* executes commands directly. It only transitions to `AUTO_SUGGEST` (pre-authorizing the playbook for a single-click human confirmation).
2. **Deterministic & Auditable:** $T$ is computed solely by mathematical functions. No LLM can override or modify $T$.

---

## 4. Reason Codes & Diagnostics

| Reason Code | Condition | Description |
| :--- | :--- | :--- |
| `RC_HIGH_CONSENSUS` | $C_{\text{consensus}} \ge 0.85$ | Multiple specialists agree with high confidence. |
| `RC_AGENT_CONFLICT` | $\Delta_{\text{conflict}} \ge 0.40$ | Direct contradiction between specialist verdicts. |
| `RC_HIGH_HISTORICAL_MATCH` | $H \ge 0.80$ | High semantic match to verified historical incident. |
| `RC_COLD_START_NO_HISTORY` | $K = 0$ | No relevant historical incidents found in pgvector. |
| `RC_CRITICAL_ASSET_PENALTY` | $S_{\text{penalty}} \ge 0.70$ | Target is a critical production asset; penalty applied. |
| `RC_SINGLE_AGENT_DISPATCH` | $M = 1$ | Only one specialist invoked; corroboration penalty applied. |

---

## 5. Test Vectors & Deterministic Edge Cases

| Scenario | $C_{\text{consensus}}$ | $H$ | $S_{\text{penalty}}$ | Raw $T$ | Clamped $T$ | Gate Decision |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Unanimous Critical Malicious** | $0.95$ | $0.85$ | $0.80$ | $0.50(0.95) + 0.30(0.85) - 0.20(0.80) = 0.57$ | $0.57$ | `ESCALATE` (Asset is too critical) |
| **2. High Consensus Standard Asset** | $0.92$ | $0.80$ | $0.20$ | $0.50(0.92) + 0.30(0.80) - 0.20(0.20) = 0.66$ | $0.66$ | `AUTO_SUGGEST` |
| **3. Severe Contradiction (Net vs End)**| $0.35$ | $0.70$ | $0.30$ | $0.50(0.35) + 0.30(0.70) - 0.20(0.30) = 0.325$| $0.325$ | `ESCALATE` (Contradiction drops C) |
| **4. Cold Start Novel Attack** | $0.90$ | $0.00$ | $0.25$ | $0.50(0.90) + 0.30(0.00) - 0.20(0.25) = 0.40$ | $0.40$ | `ESCALATE` (Lacks historical grounding)|
| **5. Low Severity Benign Match** | $0.95$ | $0.90$ | $0.15$ | $0.50(0.95) + 0.30(0.90) - 0.20(0.15) = 0.715$| $0.715$ | `AUTO_SUGGEST` |
