# Anti-Vibe Coding Rules & Engineering Rigor

These rules are non-negotiable for all code produced in this repository:

1. **No Monolithic Files:** Break code into small, focused modules obeying Single Responsibility Principle.
2. **No Duplicated Business Logic:** Centralize calculations (e.g. Trust formula, consensus logic, feature extraction) in dedicated domain services.
3. **No Fabricated Confidence or Metrics:**
   - Confidence scores must be calibrated.
   - Evaluation metrics must come directly from test executions, never hardcoded.
4. **No Silent Exception Swallowing:** Never use bare `except:` or log-and-pass patterns. Exceptions must be explicitly handled, structured, and surfaced in the investigation error trail.
5. **No Faking Production Execution:** Always clearly label simulated actions as `SIMULATED_SUCCESS` / `SIMULATED_FAILURE`. Never claim a real network isolation occurred if it was simulated.
6. **Explicit Type Hints:** Use strict Python 3.11+ type annotations (`mypy --strict` compliant).
7. **Comprehensive Unit Tests:** Every schema, router function, agent node, and trust equation must have companion tests in `tests/`.
