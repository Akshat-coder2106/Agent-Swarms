# Project Sentinel Architecture

Project Sentinel is implemented as a production-oriented MVP that follows the v4 blueprint while staying runnable on a local developer machine.

## Components

- `backend/sentinel/models.py` defines the typed MCP envelopes, task state, evidence, patches, validation results, diagnosis reports, and rollback reports.
- `backend/sentinel/memory.py` ingests repositories, extracts code chunks and symbol graph edges, and runs deterministic security scans.
- `backend/sentinel/agents.py` implements the Architect, Scout, Engineer, and Critic roles as isolated services with explicit data contracts.
- `backend/sentinel/sandbox.py` validates patches in an ephemeral copied workspace with sanitized commands, resource limits, and static rescans.
- `backend/sentinel/orchestrator.py` owns session lifecycle, SSE events, convergence scoring, approval, escalation, and rollback.
- `backend/sentinel/api.py` exposes the FastAPI API, strict CORS, bearer authentication, and live session streams.
- `frontend/src/main.tsx` renders the live observatory for DAG state, validation axes, logical delta, budget, patch review, and activity feed.

## Local Demo Flow

1. Start the backend with `PYTHONPATH=backend python3 -m sentinel.api`.
2. Start the frontend with `cd frontend && npm install && npm run dev`.
3. Use the demo repo path `examples/python-vulnerable-api`.
4. Run an audit, inspect the generated parameterized SQL patch, approve it, and optionally roll it back.

The local sandbox is not a Firecracker replacement. It is the MVP adapter behind the same validation interface, designed so Firecracker or Wasmtime runners can replace it without changing agents or UI contracts.

## Full v4 Blueprint Status

Not every item in `Project_Sentinel_FINAL_v4.md` is implemented as infrastructure. The local build implements the end-to-end product path and keeps production integrations behind explicit interfaces.

- Implemented now: FastAPI API, typed MCP message envelopes, deterministic repository ingestion, local semantic retrieval, Python symbol graph extraction, scanner rules, four agent roles, sandbox validation, logical delta scoring, SSE telemetry, approval, rollback, signed bearer auth, strict CORS, and a professional operator UI.
- Adapter layer: local memory and sandbox runners are intentionally shaped to be replaced by Qdrant, Neo4j, Firecracker, and Wasmtime.
- Remaining infrastructure: Temporal durability, Kafka topics, Argo Workflows, Kubernetes namespace isolation, external scanner stack, OAuth provider integration, production secret mounting, OpenTelemetry exporters, and PagerDuty/JIRA integrations.
