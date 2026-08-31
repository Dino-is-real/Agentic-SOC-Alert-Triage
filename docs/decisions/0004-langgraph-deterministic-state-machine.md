# ADR 0004: LangGraph for Deterministic Multi-Agent State Orchestration

## Context and Problem Statement
Multi-agent frameworks often rely on loose conversational patterns (e.g. autogen chat loops, unconstrained multi-turn debate). In a security operations platform, execution must follow a strict, auditable Directed Acyclic Graph (DAG) with explicit conditional transitions, timeouts, and state tracking.

## Considered Options
1. **Autonomous Conversational Chat Loops (AutoGen / CrewAI):** Free-form message passing between LLM agents until a stopping condition is reached.
2. **Custom Python Async State Engine:** Custom-built async task coordinator.
3. **LangGraph State Graph Engine:** Graph-based state machine with typed state channels, conditional branching, checkpointing, and deterministic node execution.

## Decision Outcome
Chosen option: **Option 3: LangGraph State Graph Engine**.
- **Explicit DAG State Transitions:** Alert ingestion $\to$ Router $\to$ Parallel Domain Specialists $\to$ Synthesis $\to$ Trust Gate $\to$ Approval Gate.
- **Typed State Management:** Uses a typed Pydantic/TypedDict state schema passed between nodes.
- **Conditional Branching:** Router probabilities directly control conditional edge activation, ensuring only relevant specialist nodes execute.

## Consequences
- **Positive:** Full auditability of every state change and node execution trace; reproducible execution; robust error and timeout handling.
- **Negative:** Requires strict state schema definition and node function purity.
