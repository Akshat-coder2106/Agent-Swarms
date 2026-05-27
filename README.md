# Project Sentinel

Autonomous codebase auditing and remediation swarm with typed orchestration, deterministic repository memory, sandbox validation, live telemetry, approval, and rollback.

## Quick Start

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
PYTHONPATH=backend python3 -m sentinel.api
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173` and use this demo repository:

```text
./examples/python-vulnerable-api
```

For optional AI-backed remediation and Critic commentary, add `ANTHROPIC_API_KEY`
to `.env` or your shell. Without that key, Sentinel still runs deterministic
rules and clearly labels the fallback path.

## One-Command Docker Demo

```bash
cp .env.example .env
docker compose up --build
```

Then open `http://127.0.0.1:5173`.

## CLI Demo

```bash
PYTHONPATH=backend python3 -m sentinel.cli examples/python-vulnerable-api
```

Add `--approve` to apply the validated patch to the demo repository.

## Security Defaults

- JWT-style HMAC bearer tokens are required for API calls.
- Session-scoped tokens are issued after session creation.
- The UI exposes auth context, token rotation, and the session-scoped bearer state.
- CORS origins are explicit and environment-configurable.
- Repository paths are constrained to configured allowed roots.
- Sandbox commands run without shell expansion and with a sanitized environment.
- Patch approval verifies original file content before writing.
- Rollback verifies patched file content before restoring original content.

## Live Deployment (Hackathon Requirement 4)

To deploy this project to the cloud for the 30-day requirement:
1. **Push to GitHub**: Commit this codebase to a public or private GitHub repository.
2. **Backend (Render)**: Connect your repository to Render and deploy using the provided `render.yaml`. You will need to supply the `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` as environment variables in the Render dashboard.
3. **Frontend (Vercel)**: Connect your repository to Vercel. It will automatically detect Vite and use `vercel.json`. Set the environment variable `VITE_SENTINEL_API_URL` to your Render backend URL (e.g. `https://sentinel-api.onrender.com`).

**Test Credentials**: You do not need a password to access the UI. Just click "Rotate Token" in the sidebar to authenticate as `local-operator`.

## Spec Coverage

This repository is a polished local MVP for the v4 blueprint, not the full enterprise deployment.

- Implemented: typed MCP contracts, repository ingestion, local code memory, LangGraph-compatible state execution, agent roles, sandbox validation, convergence scoring, SSE telemetry, approval, rollback, auth, and audit reports.
- AI-enabled when configured: Engineer and Critic call Anthropic when `ANTHROPIC_API_KEY` is present, with deterministic fallback for offline demos.
- MVP adapters: local semantic/graph memory stands in for Qdrant and Neo4j; local sandbox runner stands in for Firecracker and Wasmtime.
- Planned production integrations: managed Kubernetes, Temporal persistence, Kafka queues, external scanner CLIs, cloud secret mounting, and PagerDuty/JIRA wiring.

The UI reads `/api/system/capabilities` so judges can see the coverage boundary directly.

## Test Commands

```bash
PYTHONPATH=backend python3 -m unittest discover -s tests
python3 -m compileall backend tests examples/python-vulnerable-api
```
