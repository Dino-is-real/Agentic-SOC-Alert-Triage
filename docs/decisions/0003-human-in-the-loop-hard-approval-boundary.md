# ADR 0003: Human-in-the-Loop Hard Architectural Approval Boundary

## Context and Problem Statement
Autonomous response actions in cybersecurity (e.g., isolating a host, revoking credentials, reconfiguring firewalls) carry extreme operational and business risk if executed improperly. In a research-grade, patent-oriented platform, safety guarantees must be backed by architectural constraints, not merely frontend UI conventions.

## Considered Options
1. **Fully Autonomous Remediation for High-Trust Alerts:** If $T \ge 0.65$, execute response actions directly without human intervention.
2. **Frontend-Only Button Disabling:** Prevent execution in the UI unless the user clicks a button, but allow the backend execution API to run unauthenticated.
3. **Mandatory Backend-Enforced Cryptographic Approval Gate:** All playbooks are staged in a `PENDING_APPROVAL` state. The execution engine strictly requires an HMAC-signed analyst approval token and checks persistent DB status before executing actions (defaulting to safe simulation mode).

## Decision Outcome
Chosen option: **Option 3: Mandatory Backend-Enforced Cryptographic Approval Gate**.
- **Definition of Auto-Suggest:** $T \ge 0.65$ enables *auto-suggestion* (pre-populating the playbook for one-click human verification), NEVER autonomous execution.
- **Backend Enforcement:** The execution engine checks authorization tokens and database state. It is physically impossible to trigger execution through prompt injection or UI manipulation.

## Consequences
- **Positive:** Zero risk of unintended automated production damage; complies with NIST SP 800-61r2 and enterprise SOC governance.
- **Negative:** Human analyst must take an explicit action to authorize execution, preserving human oversight.
