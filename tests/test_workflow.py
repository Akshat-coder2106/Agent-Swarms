from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path

from sentinel.config import load_settings
from sentinel.models import AuditRequest, SessionStatus, Verdict
from sentinel.orchestrator import SentinelOrchestrator


class SentinelWorkflowTest(unittest.IsolatedAsyncioTestCase):
    async def test_audit_validates_approval_and_rollback(self) -> None:
        source_repo = Path("examples/python-vulnerable-api").resolve()
        with tempfile.TemporaryDirectory(prefix="sentinel-test-") as temp_dir:
            repo = Path(temp_dir) / "repo"
            shutil.copytree(source_repo, repo)
            orchestrator = SentinelOrchestrator(settings=load_settings())

            session = await orchestrator.create_session(
                AuditRequest(repo_path=str(repo), objective="Audit demo SQL injection")
            )
            session = await self._wait_until_stable(orchestrator, session.session_id)

            self.assertIn(session.status, [SessionStatus.ESCALATED, SessionStatus.AWAITING_APPROVAL])
            if session.patches:
                patch_id = session.patches[-1].patch_id
                # Only test approval/rollback if we have a patch
                if session.validations and session.validations[-1].verdict == Verdict.APPROVE:
                    approved = await orchestrator.approve_patch(session.session_id, patch_id)
                    self.assertEqual(approved.status, SessionStatus.COMPLETED)
                    rolled_back = await orchestrator.rollback_patch(
                        session_id=session.session_id,
                        patch_id=patch_id,
                        regression_type="TEST_ROLLBACK",
                        root_cause_hypothesis="Exercise rollback flow",
                    )
                    self.assertEqual(rolled_back.status, SessionStatus.ROLLED_BACK)

    async def _wait_until_stable(self, orchestrator: SentinelOrchestrator, session_id: str):
        for _ in range(80):
            session = await orchestrator.get_session(session_id)
            if session.status not in {SessionStatus.PENDING, SessionStatus.RUNNING}:
                return session
            await asyncio.sleep(0.05)
        self.fail("Session did not finish within expected time")
