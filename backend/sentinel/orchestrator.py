from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from pathlib import Path

from .agents import ArchitectAgent, CriticAgent, EngineerAgent, PatchGenerationError, ScoutAgent
from .config import Settings
from .evidence import build_evidence_bundle, patch_digest
from .langgraph_orchestrator import LangGraphConfig, SentinelLangGraph
from .llm import build_llm_provider
from .memory import RepositoryIngestor, resolve_repo_path, safe_read_text
from .models import (
    AgentRole,
    ApprovalRecord,
    AuditEvent,
    AuditRequest,
    AuditSession,
    DiagnosisReport,
    EventType,
    LogicalDeltaSnapshot,
    MCPMessage,
    MessageType,
    PatchProposal,
    RepositoryMemory,
    RollbackReport,
    SessionNotFoundError,
    SessionStatus,
    TaskStatus,
    Verdict,
)
from .policy_gate import evaluate_patch_policy
from .sandbox import SandboxRunner

logger = logging.getLogger(__name__)


class ApprovalError(ValueError):
    pass


def _stage_validated_patch(repo_root: Path, patch: PatchProposal) -> None:
    """Apply a sandbox-approved patch to the session working tree for subsequent tasks."""
    for file_patch in patch.files:
        target = repo_root / file_patch.file_path
        current = safe_read_text(target)
        if current == file_patch.patched:
            continue
        if current != file_patch.original:
            raise ApprovalError(
                f"Cannot stage patch; {file_patch.file_path} changed unexpectedly since validation baseline."
            )
        target.write_text(file_patch.patched, encoding="utf-8")


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[AuditEvent]]] = defaultdict(list)

    async def publish(self, event: AuditEvent) -> None:
        for queue in list(self._subscribers[event.session_id]):
            await queue.put(event)

    async def subscribe(self, session_id: str) -> asyncio.Queue[AuditEvent]:
        queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=200)
        self._subscribers[session_id].append(queue)
        return queue

    def unsubscribe(self, session_id: str, queue: asyncio.Queue[AuditEvent]) -> None:
        if queue in self._subscribers.get(session_id, []):
            self._subscribers[session_id].remove(queue)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, AuditSession] = {}
        self._lock = asyncio.Lock()

    async def create(self, session: AuditSession) -> AuditSession:
        async with self._lock:
            self._sessions[session.session_id] = session
            return session

    async def get(self, session_id: str) -> AuditSession:
        async with self._lock:
            try:
                return self._sessions[session_id]
            except KeyError as exc:
                raise SessionNotFoundError(session_id) from exc

    async def save(self, session: AuditSession) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session

    async def list(self) -> list[AuditSession]:
        async with self._lock:
            return list(self._sessions.values())


class SentinelOrchestrator:
    def __init__(
        self,
        *,
        settings: Settings,
        store: SessionStore | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._settings = settings
        self._store = store or SessionStore()
        self._event_bus = event_bus or EventBus()
        self._ingestor = RepositoryIngestor(settings)
        self._llm_provider = build_llm_provider(settings)
        self._architect = ArchitectAgent()
        self._scout = ScoutAgent(self._ingestor)
        self._engineer = EngineerAgent(self._llm_provider)
        self._critic = CriticAgent(self._llm_provider)
        self._sandbox = SandboxRunner(settings, self._ingestor)
        self._graph = SentinelLangGraph(
            LangGraphConfig(token_budget=settings.token_budget),
            event_bus=self._event_bus,
        ) if settings.enable_langgraph else None
        if self._graph:
            self._graph.set_agents(
                architect=self._architect,
                scout=self._scout,
                engineer=self._engineer,
                critic=self._critic,
                sandbox=self._sandbox,
            )

    @property
    def event_bus(self) -> EventBus:
        return self._event_bus

    async def create_session(self, request: AuditRequest) -> AuditSession:
        repo_root = resolve_repo_path(self._settings, request.repo_path)
        session = AuditSession(objective=request.objective, repo_path=str(repo_root))
        await self._store.create(session)
        await self._emit(
            session,
            EventType.AUDIT_LOG,
            AgentRole.ROUTER,
            {
                "message": "Session accepted",
                "repo_path": session.repo_path,
                "objective": session.objective,
            },
        )
        asyncio.create_task(self.run_session(session.session_id))
        return session

    async def run_session(self, session_id: str) -> AuditSession:
        session = await self._store.get(session_id)
        repo_root = Path(session.repo_path)
        try:
            session.status = SessionStatus.RUNNING
            await self._save(session)
            memory = self._ingestor.ingest(session.repo_path, session.session_id)
            session.memory = memory
            await self._emit(
                session,
                EventType.ARCHITECT_UPDATE,
                AgentRole.ARCHITECT,
                {
                    "status": "repository_ingested",
                    "files_indexed": memory.files_indexed,
                    "symbols": len(memory.symbols),
                    "graph_edges": len(memory.edges),
                    "findings": len(memory.findings),
                    "validation_commands": memory.validation_commands,
                },
            )

            tasks, architect_messages = self._architect.build_tasks(session.session_id, memory)
            session.tasks = tasks
            session.messages.extend(architect_messages)
            await self._emit_budget(session, memory)
            if self._graph:
                return await self._run_graph_session(session=session, memory=memory)
            if not tasks:
                session.status = SessionStatus.COMPLETED
                await self._emit(
                    session,
                    EventType.SESSION_COMPLETE,
                    AgentRole.ARCHITECT,
                    {"summary": "No security findings were detected.", "findings": 0},
                )
                await self._save(session)
                return session

            validated_patches: list[str] = []
            for task in tasks:
                task.status = TaskStatus.ACTIVE
                await self._emit(
                    session,
                    EventType.ARCHITECT_UPDATE,
                    AgentRole.ARCHITECT,
                    {
                        "task_id": task.task_id,
                        "target_path": task.target_path,
                        "status": task.status,
                        "priority": task.priority,
                    },
                    task_id=task.task_id,
                )
                evidence = self._scout.retrieve(memory, task)
                session.messages.append(
                    MCPMessage(
                        session_id=session.session_id,
                        task_id=task.task_id,
                        sender=AgentRole.SCOUT,
                        recipient=AgentRole.ENGINEER,
                        message_type=MessageType.EVIDENCE_PACKAGE,
                        priority=task.priority,
                        payload=evidence.model_dump(mode="json"),
                    ).with_checksum()
                )
                await self._emit(
                    session,
                    EventType.SCOUT_RETRIEVAL,
                    AgentRole.SCOUT,
                    evidence.model_dump(mode="json"),
                    task_id=task.task_id,
                )

                try:
                    # Emulating token-by-token live reasoning updates
                    await self._emit(
                        session,
                        EventType.AUDIT_LOG,
                        AgentRole.ENGINEER,
                        {"message": "Engineer is analyzing root cause and drafting security patch candidates..."},
                        task_id=task.task_id,
                    )
                    patch = self._engineer.propose_patch(
                        repo_root=repo_root,
                        evidence=evidence,
                        iteration=1,
                        operator_hint=session.operator_hint,
                    )
                    
                    # Inter-Agent Adversarial Debate Loop: Critic challenges and Engineer defends!
                    await self._emit(
                        session,
                        EventType.AUDIT_LOG,
                        AgentRole.CRITIC,
                        {"message": "Critic is performing adversarial analysis to identify potential bypasses..."},
                        task_id=task.task_id,
                    )
                    challenges = self._critic.adversarial_challenge(patch)
                    
                    await self._emit(
                        session,
                        EventType.AUDIT_LOG,
                        AgentRole.ENGINEER,
                        {"message": f"Engineer is defending patch against {len(challenges)} adversarial challenges..."},
                        task_id=task.task_id,
                    )
                    original_file = repo_root / patch.files[0].file_path
                    original_content = original_file.read_text(encoding="utf-8") if original_file.exists() else ""
                    patch = self._engineer.defend_patch(original=original_content, patch=patch, challenges=challenges)

                except PatchGenerationError as exc:
                    logger.warning("Patch generation failed for %s: %s", task.task_id, exc)
                    await self._escalate(
                        session=session,
                        task_id=task.task_id,
                        reason=str(exc),
                        last_diff="",
                        suggestion="Provide a one-line implementation constraint for the Engineer.",
                    )
                    task.status = TaskStatus.ESCALATED
                    continue

                session.patches.append(patch)
                session.messages.append(
                    MCPMessage(
                        session_id=session.session_id,
                        task_id=task.task_id,
                        sender=AgentRole.ENGINEER,
                        recipient=AgentRole.CRITIC,
                        message_type=MessageType.PATCH_SUBMISSION,
                        priority=task.priority,
                        payload=patch.model_dump(mode="json"),
                    ).with_checksum()
                )
                await self._emit(
                    session,
                    EventType.ENGINEER_PATCH,
                    AgentRole.ENGINEER,
                    patch.model_dump(mode="json"),
                    task_id=task.task_id,
                )

                await self._emit(
                    session,
                    EventType.VALIDATION_STARTED,
                    AgentRole.CRITIC,
                    {"engine": self._sandbox.engine_name, "status": "booting"},
                    task_id=task.task_id,
                )

                validation = self._sandbox.validate(repo_root=repo_root, memory=memory, patch=patch)
                session.validations.append(validation)

                # Emit sandbox log with engine metadata
                sandbox_meta = validation.sandbox_metadata
                if sandbox_meta:
                    await self._emit(
                        session,
                        EventType.SANDBOX_LOG,
                        AgentRole.CRITIC,
                        {
                            "engine": sandbox_meta.engine,
                            "boot_time_ms": sandbox_meta.boot_time_ms,
                            "isolation_level": sandbox_meta.isolation_level,
                            "vsock_status": sandbox_meta.vsock_status,
                            "status": "completed",
                        },
                        task_id=task.task_id,
                    )

                await self._emit(
                    session,
                    EventType.SANDBOX_RESULT,
                    AgentRole.ROUTER,
                    validation.model_dump(mode="json"),
                    task_id=task.task_id,
                )
                session.messages.append(
                    MCPMessage(
                        session_id=session.session_id,
                        task_id=task.task_id,
                        sender=AgentRole.CRITIC,
                        recipient=AgentRole.ROUTER,
                        message_type=MessageType.VALIDATION_VERDICT,
                        priority=task.priority,
                        payload=validation.model_dump(mode="json"),
                    ).with_checksum()
                )
                await self._emit(
                    session,
                    EventType.CRITIC_VERDICT,
                    AgentRole.CRITIC,
                    {
                        "verdict": validation.verdict,
                        "axes": [axis.model_dump(mode="json") for axis in validation.axes],
                        "risk_assessment": self._critic.risk_assessment(
                            patch=patch,
                            validation=validation,
                        ),
                    },
                    task_id=task.task_id,
                )
                delta = self._calculate_delta(validation, iteration=1)
                session.delta_history.append(delta)
                await self._emit(
                    session,
                    EventType.DELTA_UPDATE,
                    AgentRole.ROUTER,
                    delta.model_dump(mode="json"),
                    task_id=task.task_id,
                )

                if validation.verdict == Verdict.APPROVE and delta.accumulated_delta >= 0.85:
                    task.status = TaskStatus.PASSED
                    validated_patches.append(patch.patch_id)
                    session.evidence_bundles.append(
                        build_evidence_bundle(
                            session_id=session.session_id,
                            repository_path=session.repo_path,
                            patch=patch,
                            validation=validation,
                        )
                    )
                    await self._emit(
                        session,
                        EventType.AUDIT_LOG,
                        AgentRole.CRITIC,
                        {
                            "summary": f"Task {task.task_id} validated; continuing to next finding.",
                            "patch_id": patch.patch_id,
                        },
                        task_id=task.task_id,
                    )
                    continue

                await self._escalate(
                    session=session,
                    task_id=task.task_id,
                    reason="Validation did not converge above approval threshold.",
                    last_diff=patch.unified_diff,
                    suggestion="Inspect failing validation axis and constrain the next patch.",
                )
                task.status = TaskStatus.ESCALATED
                continue

            if validated_patches:
                session.validated_patch_ids = validated_patches
                session.status = SessionStatus.AWAITING_APPROVAL
                await self._emit(
                    session,
                    EventType.SESSION_COMPLETE,
                    AgentRole.CRITIC,
                    {
                        "summary": (
                            f"{len(validated_patches)} patch(es) validated, awaiting operator approval."
                        ),
                        "patch_ids": validated_patches,
                        "validated_patch_ids": validated_patches,
                        "status": session.status,
                    },
                )
            else:
                session.status = SessionStatus.ESCALATED
            await self._save(session)
            return session
        except Exception as exc:
            logger.exception("Session pipeline failed: %s", exc)
            session.status = SessionStatus.FAILED
            await self._emit(
                session,
                EventType.ESCALATION,
                AgentRole.ROUTER,
                {"error": exc.__class__.__name__, "message": str(exc)},
            )
            await self._save(session)
            raise

    async def _run_graph_session(
        self,
        *,
        session: AuditSession,
        memory: RepositoryMemory,
    ) -> AuditSession:
        if not self._graph:
            raise RuntimeError("LangGraph runner is not configured")

        tasks, architect_messages = self._architect.build_tasks(session.session_id, memory)
        session.tasks = tasks
        session.messages.extend(architect_messages)
        if not tasks:
            session.status = SessionStatus.COMPLETED
            await self._emit(
                session,
                EventType.SESSION_COMPLETE,
                AgentRole.ARCHITECT,
                {"summary": "No security findings were detected.", "findings": 0},
            )
            await self._save(session)
            return session

        validated_patch_ids: list[str] = []
        for task in tasks:
            task.status = TaskStatus.ACTIVE
            graph_state = await self._graph.run_task(
                session_id=session.session_id,
                memory=memory,
                repo_path=session.repo_path,
                task=task,
                operator_hint=session.operator_hint,
            )
            await self._emit(
                session,
                EventType.ARCHITECT_UPDATE,
                AgentRole.ARCHITECT,
                {
                    "task_id": task.task_id,
                    "target_path": task.target_path,
                    "graph_engine": graph_state["graph_engine"],
                },
                task_id=task.task_id,
            )
            evidence = graph_state.get("evidence")
            if evidence:
                await self._emit(
                    session,
                    EventType.SCOUT_RETRIEVAL,
                    AgentRole.SCOUT,
                    evidence.model_dump(mode="json"),
                    task_id=task.task_id,
                )
            patch = graph_state.get("patch")
            validation = graph_state.get("validation")
            if not patch or not validation:
                task.status = TaskStatus.ESCALATED
                continue

            session.patches.append(patch)
            session.validations.append(validation)
            await self._emit(
                session,
                EventType.ENGINEER_PATCH,
                AgentRole.ENGINEER,
                patch.model_dump(mode="json"),
                task_id=task.task_id,
            )
            await self._emit(
                session,
                EventType.SANDBOX_RESULT,
                AgentRole.ROUTER,
                validation.model_dump(mode="json"),
                task_id=task.task_id,
            )
            delta = self._calculate_delta(validation, iteration=graph_state["iteration"])
            session.delta_history.append(delta)
            if validation.verdict == Verdict.APPROVE and delta.accumulated_delta >= 0.85:
                task.status = TaskStatus.PASSED
                validated_patch_ids.append(patch.patch_id)
                session.evidence_bundles.append(
                    build_evidence_bundle(
                        session_id=session.session_id,
                        repository_path=session.repo_path,
                        patch=patch,
                        validation=validation,
                    )
                )
            else:
                task.status = TaskStatus.ESCALATED

        if validated_patch_ids:
            session.validated_patch_ids = validated_patch_ids
            session.status = SessionStatus.AWAITING_APPROVAL
            await self._emit(
                session,
                EventType.SESSION_COMPLETE,
                AgentRole.CRITIC,
                {
                    "summary": (
                        f"{len(validated_patch_ids)} graph-validated patch(es) awaiting approval."
                    ),
                    "patch_ids": validated_patch_ids,
                    "validated_patch_ids": validated_patch_ids,
                    "status": session.status,
                },
            )
        else:
            session.status = SessionStatus.ESCALATED
        await self._save(session)
        return session

    async def approve_patch(
        self,
        session_id: str,
        patch_id: str,
        *,
        approved_by: str = "local-test-operator",
        approver_role: str = "Admin",
    ) -> AuditSession:
        session = await self._store.get(session_id)
        patch = next((candidate for candidate in session.patches if candidate.patch_id == patch_id), None)
        if not patch:
            raise ApprovalError(f"Patch not found: {patch_id}")
        validation = next(
            (candidate for candidate in session.validations if candidate.patch_id == patch_id),
            None,
        )
        if not validation or validation.verdict != Verdict.APPROVE:
            raise ApprovalError("Only approved patches can be applied")
        if patch_id in session.approved_patch_ids:
            raise ApprovalError(f"Patch already approved: {patch_id}")
        decision = evaluate_patch_policy(
            patch=patch,
            validation=validation,
            confidence_threshold=self._settings.policy_confidence_threshold,
        )
        if not decision.approval_eligible:
            raise ApprovalError(f"Patch policy rejected approval: {decision.reason}")
        evidence = next(
            (
                item
                for item in session.evidence_bundles
                if item.patch_id == patch_id
            ),
            None,
        )
        if evidence is None:
            raise ApprovalError("Validated patch has no evidence bundle")
        current_digest = patch_digest(patch)
        if evidence.patch_sha256 != current_digest:
            raise ApprovalError("Patch changed after validation; approval evidence is invalid")

        repo_root = Path(session.repo_path)
        for file_patch in patch.files:
            target = repo_root / file_patch.file_path
            current = safe_read_text(target)
            if current == file_patch.patched:
                continue
            if current != file_patch.original:
                raise ApprovalError(f"Target changed since validation: {file_patch.file_path}")
            target.write_text(file_patch.patched, encoding="utf-8")

        session.approved_patch_ids.append(patch_id)
        session.approval_records.append(
            ApprovalRecord(
                patch_id=patch_id,
                patch_sha256=current_digest,
                evidence_id=evidence.evidence_id,
                approved_by=approved_by,
                approver_role=approver_role,
            )
        )

        validated_ids = {
            v.patch_id for v in session.validations if v.verdict == Verdict.APPROVE
        }
        if session.validated_patch_ids:
            validated_ids = set(session.validated_patch_ids)

        pr_link: str | None = None
        import os

        token = os.getenv("GITHUB_TOKEN")
        if token and set(session.approved_patch_ids) >= validated_ids:
            try:
                from .github_integration import create_github_pr

                pr_link = await create_github_pr(session, patch, token)
            except Exception as exc:
                logger.warning("GitHub PR creation failed: %s", exc)

        if set(session.approved_patch_ids) >= validated_ids:
            session.status = SessionStatus.COMPLETED
            summary = f"All {len(session.approved_patch_ids)} validated patch(es) approved and applied."
        else:
            session.status = SessionStatus.AWAITING_APPROVAL
            summary = (
                f"Patch approved ({len(session.approved_patch_ids)}/{len(validated_ids)}). "
                "Additional validated patches await approval."
            )
        if pr_link:
            summary += " GitHub Pull Request created."
        await self._emit(
            session,
            EventType.SESSION_COMPLETE,
            AgentRole.ROUTER,
            {
                "summary": summary,
                "patch_id": patch.patch_id,
                "approved_patch_ids": session.approved_patch_ids,
                "changed_files": [file.file_path for file in patch.files],
                "pull_request_url": pr_link or f"/api/sessions/{session.session_id}/export/sarif",
            },
        )
        await self._save(session)
        return session

    async def rollback_patch(
        self,
        *,
        session_id: str,
        patch_id: str,
        regression_type: str,
        root_cause_hypothesis: str,
    ) -> AuditSession:
        started = time.monotonic()
        session = await self._store.get(session_id)
        patch = next((candidate for candidate in session.patches if candidate.patch_id == patch_id), None)
        if not patch:
            raise ApprovalError(f"Patch not found: {patch_id}")
        repo_root = Path(session.repo_path)
        restored: list[str] = []
        for file_patch in patch.files:
            target = repo_root / file_patch.file_path
            current = safe_read_text(target)
            if current != file_patch.patched:
                raise ApprovalError(f"Cannot rollback changed target safely: {file_patch.file_path}")
            target.write_text(file_patch.original, encoding="utf-8")
            restored.append(file_patch.file_path)
        session.status = SessionStatus.ROLLED_BACK
        session.rollback = RollbackReport(
            session_id=session.session_id,
            patch_id=patch.patch_id,
            regression_type=regression_type,
            affected_files=restored,
            rollback_duration_sec=round(time.monotonic() - started, 3),
            root_cause_hypothesis=root_cause_hypothesis,
            recommended_action="Re-run Sentinel with the rollback report included as mandatory context.",
        )
        await self._emit(
            session,
            EventType.ROLLBACK_INITIATED,
            AgentRole.ROUTER,
            session.rollback.model_dump(mode="json"),
        )
        await self._save(session)
        return session

    async def add_operator_hint(self, session_id: str, hint: str) -> AuditSession:
        session = await self._store.get(session_id)
        session.operator_hint = hint
        if session.diagnosis:
            session.diagnosis.suggested_hint = hint
        await self._emit(
            session,
            EventType.ESCALATION,
            AgentRole.ROUTER,
            {"operator_hint": hint, "status": "recorded"},
            task_id=session.diagnosis.task_id,
        )
        await self._save(session)
        return session

    async def get_session(self, session_id: str) -> AuditSession:
        return await self._store.get(session_id)

    async def list_sessions(self) -> list[AuditSession]:
        return await self._store.list()

    async def _emit(
        self,
        session: AuditSession,
        event_type: EventType,
        agent: AgentRole,
        payload: dict,
        *,
        task_id: str | None = None,
    ) -> None:
        event = AuditEvent(
            session_id=session.session_id,
            event_type=event_type,
            agent=agent,
            task_id=task_id,
            payload=payload,
        )
        session.events.append(event)
        await self._save(session)
        await self._event_bus.publish(event)

    async def _emit_budget(self, session: AuditSession, memory: RepositoryMemory) -> None:
        estimated_tokens = sum(max(1, len(chunk.text) // 4) for chunk in memory.chunks)
        await self._emit(
            session,
            EventType.BUDGET_UPDATE,
            AgentRole.ROUTER,
            {
                "tokens_consumed": estimated_tokens,
                "tokens_remaining": max(0, self._settings.token_budget - estimated_tokens),
                "token_budget": self._settings.token_budget,
                "estimated_cost_usd": round(estimated_tokens / 1000 * 0.0015, 4),
            },
        )

    def _calculate_delta(self, validation, *, iteration: int) -> LogicalDeltaSnapshot:
        test_score = (
            validation.passing_tests / validation.total_tests
            if validation.total_tests
            else (1.0 if validation.exit_code == 0 else 0.0)
        )
        security_score = (
            validation.resolved_findings / validation.total_findings
            if validation.total_findings
            else 1.0
        )
        coverage_score = min(max(validation.coverage_delta / 100, 0.0), 1.0)
        delta = 0.5 * test_score + 0.3 * security_score + 0.2 * coverage_score
        return LogicalDeltaSnapshot(
            iteration=iteration,
            delta=round(delta, 4),
            accumulated_delta=round(delta, 4),
            passing_tests=validation.passing_tests,
            total_tests=validation.total_tests,
            resolved_findings=validation.resolved_findings,
            total_findings=validation.total_findings,
            coverage_delta=validation.coverage_delta,
        )

    async def _escalate(
        self,
        *,
        session: AuditSession,
        task_id: str,
        reason: str,
        last_diff: str,
        suggestion: str,
    ) -> None:
        session.status = SessionStatus.ESCALATED
        session.diagnosis = DiagnosisReport(
            session_id=session.session_id,
            task_id=task_id,
            iteration_count=len(session.delta_history) or 1,
            logical_delta_history=[item.delta for item in session.delta_history],
            deadlock_type="CONVERGED_BELOW_THRESHOLD",
            last_critic_directive=reason,
            last_engineer_diff=last_diff,
            suggested_hint=suggestion,
            tokens_consumed=0,
            tokens_remaining=self._settings.token_budget,
        )
        await self._emit(
            session,
            EventType.ESCALATION,
            AgentRole.ROUTER,
            session.diagnosis.model_dump(mode="json"),
            task_id=task_id,
        )

    async def _save(self, session: AuditSession) -> None:
        from .models import utc_now

        session.updated_at = utc_now()
        await self._store.save(session)
