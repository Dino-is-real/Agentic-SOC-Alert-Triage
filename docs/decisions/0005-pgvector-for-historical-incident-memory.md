# ADR 0005: PostgreSQL + pgvector for Historical Incident Memory

## Context and Problem Statement
The framework requires grounding triage in historical institutional precedent. When a new alert arrives, the system must retrieve top-$K$ semantically similar historical incidents, their analyst-verified verdicts, and remediation outcomes to compute the historical similarity factor $H$.

## Considered Options
1. **Dedicated Vector DB (Pinecone / Qdrant / Milvus):** Standalone cloud/container vector database service.
2. **In-Memory Approximate Nearest Neighbor (FAISS):** Local flat/HNSW index file loaded into memory.
3. **PostgreSQL with `pgvector` Extension:** Unified relational database handling structured relational entities (alerts, incidents, findings, audit events) alongside dense vector embeddings.

## Decision Outcome
Chosen option: **Option 3: PostgreSQL with `pgvector` Extension**.
- **Unified Transactional & Vector Store:** Avoids distributed multi-database synchronization bugs between relational incident metadata and vector indexes.
- **ACID Compliance & Relational Joins:** Seamlessly join vector similarity search with relational filters (e.g. `WHERE tenant_id = ... AND verified_by_analyst = true`).
- **Low Operational Footprint:** Runs in a single lightweight PostgreSQL container in local and production environments.

## Consequences
- **Positive:** Simplified deployment; native SQL query interface; transactional guarantees for vector insertions upon incident resolution.
- **Negative:** Requires `pgvector` extension enabled on PostgreSQL 16 image.
