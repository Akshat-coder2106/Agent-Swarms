# Demo Script

1. Start the system with `docker compose up --build` or the local backend/frontend commands from `README.md`.
2. Open `http://127.0.0.1:5173`.
3. Confirm the Auth panel shows an active bearer token and the capability panel distinguishes implemented, adapter, and planned systems.
4. Run an audit against `./examples/python-vulnerable-api`.
5. Watch the graph trace event, Scout evidence, Engineer patch, sandbox result, Critic risk assessment, and Logical Delta update stream into the UI.
6. Approve the generated SQL injection patch.
7. Use Rollback to restore the pre-patch file and show content-verified recovery.

For an AI-backed demo, export `ANTHROPIC_API_KEY` before starting the backend. The Engineer and Critic will use Anthropic for unsupported patches and risk commentary while keeping deterministic fallbacks for offline judging.
