# Architecture Standards & Layering Rules

1. **Dependency Flow:**
   - `domain` depends on nothing.
   - `trust`, `synthesis`, `routing` depend only on `domain`.
   - `agents` depend on `domain`, `integrations`, and `orchestration`.
   - `api` depends on `domain`, `orchestration`, `memory`, `trust`, `response`.
   - Reverse dependencies (e.g. `domain` importing from `api` or `db`) are strictly forbidden.
2. **Adapter Isolation:**
   - All external services (VirusTotal, AbuseIPDB, Shodan, MITRE, OpenAI, Anthropic) must sit behind an abstract base class in `src/integrations/` or `src/agents/base.py`.
   - Every adapter must provide an accompanying `Mock*` implementation for zero-network testing.
3. **Database Layer:**
   - All DB operations use async SQLAlchemy 2.0 with explicit transaction scoping.
   - Migrations must be managed via Alembic; no raw `CREATE TABLE` execution in application code.
