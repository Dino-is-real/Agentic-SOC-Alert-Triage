# ADR 0001: Modular Clean Architecture & Decoupled Domain Logic

## Context and Problem Statement
The SOC alert triage platform must support complex multi-agent workflows, machine learning models, external SIEM integrations, threat intelligence providers, and research evaluation baselines. A monolithic, tightly-coupled architecture would make testing, baseline comparison, and independent component evaluation brittle and non-reproducible.

## Considered Options
1. **Monolithic Fast-Prototype Architecture:** All business logic in FastAPI routes and single script files.
2. **Microservices Architecture:** Separate independent container services for router, agents, trust engine, and memory.
3. **Modular Clean Architecture (Hexagonal Ports and Adapters):** Single deployable repository with strictly decoupled domain core, independent subsystem packages, and abstract adapters for external dependencies.

## Decision Outcome
Chosen option: **Option 3: Modular Clean Architecture**.
- **Domain Independence:** Domain models (`src/domain`), trust engine (`src/trust`), and synthesis (`src/synthesis`) have zero external network/database dependencies.
- **Portability:** External integrations (VirusTotal, LLMs, Vector DB) implement abstract interfaces with mock implementations for deterministic testing.
- **Low Overhead:** Avoids network latency and operational complexity of microservices while maintaining clean modularity.

## Consequences
- **Positive:** Subsystems can be tested in total isolation; deterministic mock tests run in milliseconds without network access; cleanly supports 4 baseline comparative research evaluations.
- **Negative:** Requires strict discipline in maintaining interface boundaries and dependency directions.
