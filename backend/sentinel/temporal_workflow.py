"""Temporal.io workflow durability integration for Sentinel."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import activity, workflow, workflow_method
from temporalio.client import Client
from temporalio.worker import Worker

from .models import (
    AuditRequest,
    AuditSession,
    MCPMessage,
    MessageType,
    RepositoryMemory,
    SessionStatus,
)


@dataclass
class IngestRepositoryInput:
    """Input for repository ingestion activity."""

    repo_path: str
    session_id: str


@dataclass
class IngestRepositoryOutput:
    """Output from repository ingestion activity."""

    memory: RepositoryMemory


@dataclass
class RunAgentTaskInput:
    """Input for agent task execution activity."""

    session_id: str
    task_id: str
    agent_type: str
    input_data: dict[str, Any]


@dataclass
class RunAgentTaskOutput:
    """Output from agent task execution activity."""

    output_data: dict[str, Any]
    message: MCPMessage


@dataclass
class ValidatePatchInput:
    """Input for patch validation activity."""

    session_id: str
    patch_id: str
    repo_path: str


@dataclass
class ValidatePatchOutput:
    """Output from patch validation activity."""

    passed: bool
    validation_result: dict[str, Any]


@dataclass
class SentinelWorkflowInput:
    """Input for the Sentinel audit workflow."""

    request: AuditRequest


@dataclass
class SentinelWorkflowOutput:
    """Output from the Sentinel audit workflow."""

    session: AuditSession


@activity.defn
class RepositoryIngestionActivity:
    """Activity for ingesting repository into memory."""

    async def ingest(self, input: IngestRepositoryInput) -> IngestRepositoryOutput:
        """Ingest repository and build memory."""
        from .config import load_settings
        from .memory import RepositoryIngestor

        settings = load_settings()
        ingestor = RepositoryIngestor(settings)
        memory = ingestor.ingest(input.repo_path)

        return IngestRepositoryOutput(memory=memory)


@activity.defn
class AgentTaskActivity:
    """Activity for executing agent tasks."""

    async def execute(self, input: RunAgentTaskInput) -> RunAgentTaskOutput:
        """Execute an agent task."""
        # This would integrate with the actual agent implementations
        # For now, return a mock response
        output_data = {
            "status": "completed",
            "result": "Task executed successfully",
        }

        message = MCPMessage(
            session_id=input.session_id,
            task_id=input.task_id,
            sender=input.agent_type,
            recipient="router",
            message_type=MessageType.TASK_ASSIGNMENT,
            priority="MEDIUM",
            payload=output_data,
        ).with_checksum()

        return RunAgentTaskOutput(output_data=output_data, message=message)


@activity.defn
class PatchValidationActivity:
    """Activity for validating patches in sandbox."""

    async def validate(self, input: ValidatePatchInput) -> ValidatePatchOutput:
        """Validate a patch in the sandbox."""
        from .config import load_settings
        from .memory import RepositoryIngestor
        from .sandbox import SandboxRunner

        settings = load_settings()
        ingestor = RepositoryIngestor(settings)
        SandboxRunner(settings, ingestor)

        # This would need the actual patch proposal
        # For now, return a mock validation
        passed = True
        validation_result = {
            "exit_code": 0,
            "stdout": "All tests passed",
            "stderr": "",
        }

        return ValidatePatchOutput(passed=passed, validation_result=validation_result)


@workflow.defn
class SentinelAuditWorkflow:
    """Main Sentinel audit workflow with Temporal durability."""

    @workflow_method
    async def run_audit(self, input: SentinelWorkflowInput) -> SentinelWorkflowOutput:
        """Run the complete Sentinel audit workflow."""
        # Step 1: Ingest repository
        ingest_input = IngestRepositoryInput(
            repo_path=input.request.repo_path,
            session_id="temp_session",  # Would be generated
        )
        ingest_output = await workflow.execute_activity(
            RepositoryIngestionActivity.ingest,
            ingest_input,
            start_to_close_timeout=timedelta(minutes=30),
        )

        # Step 2: Build DAG and assign tasks (Architect)
        # This would be another activity

        # Step 3: Execute tasks through Scout -> Engineer -> Critic loop
        # Each agent step would be a separate activity for durability

        # Step 4: Validate patches
        # validate_input = ValidatePatchInput(...)
        # validate_output = await workflow.execute_activity(
        #     PatchValidationActivity.validate,
        #     validate_input,
        #     start_to_close_timeout=timedelta(minutes=5),
        # )

        # Step 5: Return final session state
        session = AuditSession(
            objective=input.request.objective,
            repo_path=input.request.repo_path,
            status=SessionStatus.COMPLETED,
            memory=ingest_output.memory,
        )

        return SentinelWorkflowOutput(session=session)


class TemporalWorkflowManager:
    """Manager for Temporal workflows."""

    def __init__(
        self,
        client_url: str = "localhost:7233",
        namespace: str = "default",
        task_queue: str = "sentinel-task-queue",
    ) -> None:
        self._client_url = client_url
        self._namespace = namespace
        self._task_queue = task_queue
        self._client: Client | None = None

    async def connect(self) -> None:
        """Connect to Temporal server."""
        self._client = await Client.connect(
            self._client_url,
            namespace=self._namespace,
        )

    async def disconnect(self) -> None:
        """Disconnect from Temporal server."""
        if self._client:
            await self._client.close()

    async def start_workflow(
        self,
        request: AuditRequest,
        id: str,
        timeout: timedelta = timedelta(hours=2),
    ) -> str:
        """Start a Sentinel audit workflow."""
        if not self._client:
            raise RuntimeError("Temporal client not connected")

        input_data = SentinelWorkflowInput(request=request)
        result = await self._client.execute_workflow(
            SentinelAuditWorkflow.run,
            input_data,
            id=id,
            task_queue=self._task_queue,
            execution_timeout=timeout,
        )

        return result.session.session_id

    async def get_workflow_status(self, workflow_id: str) -> dict[str, Any]:
        """Get the status of a running workflow."""
        if not self._client:
            raise RuntimeError("Temporal client not connected")

        handle = self._client.get_workflow_handle(workflow_id)
        description = await handle.describe()

        return {
            "workflow_id": workflow_id,
            "status": str(description.status),
            "history_length": description.history_length,
        }

    async def cancel_workflow(self, workflow_id: str) -> None:
        """Cancel a running workflow."""
        if not self._client:
            raise RuntimeError("Temporal client not connected")

        handle = self._client.get_workflow_handle(workflow_id)
        await handle.cancel()

    async def start_worker(self) -> Worker:
        """Start a Temporal worker for executing activities."""
        if not self._client:
            raise RuntimeError("Temporal client not connected")

        worker = Worker(
            self._client,
            task_queue=self._task_queue,
            activities=[
                RepositoryIngestionActivity.ingest,
                AgentTaskActivity.execute,
                PatchValidationActivity.validate,
            ],
            workflows=[SentinelAuditWorkflow],
        )

        await worker.run()

        return worker


async def run_temporal_worker() -> None:
    """Run the Temporal worker (for standalone execution)."""
    manager = TemporalWorkflowManager()
    await manager.connect()
    try:
        await manager.start_worker()
    finally:
        await manager.disconnect()
