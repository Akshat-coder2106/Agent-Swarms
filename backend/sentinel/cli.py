from __future__ import annotations

import argparse
import asyncio
import json

from .config import load_settings
from .models import AuditRequest, SessionStatus
from .orchestrator import SentinelOrchestrator


async def audit(repo_path: str, objective: str, *, approve: bool) -> int:
    orchestrator = SentinelOrchestrator(settings=load_settings())
    session = await orchestrator.create_session(AuditRequest(repo_path=repo_path, objective=objective))
    while session.status in {SessionStatus.PENDING, SessionStatus.RUNNING}:
        await asyncio.sleep(0.05)
        session = await orchestrator.get_session(session.session_id)
    if approve and session.patches:
        session = await orchestrator.approve_patch(session.session_id, session.patches[-1].patch_id)
    print(json.dumps(session.model_dump(mode="json"), indent=2))
    return 0 if session.status in {SessionStatus.AWAITING_APPROVAL, SessionStatus.COMPLETED} else 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Project Sentinel audit")
    parser.add_argument("repo_path")
    parser.add_argument("--objective", default="Audit repository for security vulnerabilities")
    parser.add_argument("--approve", action="store_true", help="Apply the approved patch after validation")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(audit(args.repo_path, args.objective, approve=args.approve)))


if __name__ == "__main__":
    main()
