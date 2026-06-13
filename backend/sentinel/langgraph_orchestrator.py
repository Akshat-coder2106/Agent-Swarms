"""LangGraph state-machine orchestration for Sentinel agents.

The class is dependency-tolerant: when LangGraph is installed it executes a real
StateGraph; otherwise it runs the same node functions sequentially so local tests
and demos remain reliable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, NotRequired, TypedDict

try:  # pragma: no cover - exercised when optional integration deps are installed.
    from langgraph.graph import END, StateGraph
except ImportError:  # pragma: no cover - local default path.
    END = "__end__"
    StateGraph = None

from .models import (
    AgentRole,
    AgentTask,
    AuditEvent,
    EventType,
    EvidencePackage,
    PatchProposal,
    RepositoryMemory,
    ValidationResult,
    Verdict,
)


class WorkflowState(TypedDict):
    session_id: str
    repo_path: str
    trace: list[dict[str, Any]]
    memory: RepositoryMemory
    tasks: list[AgentTask]
    task: AgentTask | None
    evidence: EvidencePackage | None
    patch: PatchProposal | None
    validation: ValidationResult | None
    critic_risk: dict[str, str] | None
    iteration: int
    logical_delta: float
    accumulated_delta: float
    escalation_reason: str | None
    graph_engine: str
    mcp_messages: NotRequired[list]
    operator_hint: NotRequired[str | None]


class AgentNode(StrEnum):
    ARCHITECT = "architect"
    SCOUT = "scout"
    ENGINEER = "engineer"
    CRITIC = "critic"
    ROUTER = "router"
    ESCALATION = "escalation"
    APPROVAL = "approval"
    COMPLETION = "completion"


@dataclass(frozen=True)
class LangGraphConfig:
    max_iterations: int = 7
    convergence_threshold: float = 0.85
    circuit_breaker_delta: float = 0.02
    token_budget: int = 2_000_000


class SentinelLangGraph:
    def __init__(self, config: LangGraphConfig, event_bus=None) -> None:
        self._config = config
        self._event_bus = event_bus
        self._architect_agent = None
        self._scout_agent = None
        self._engineer_agent = None
        self._critic_agent = None
        self._sandbox_runner = None
        self._graph = self._build_graph() if StateGraph else None
        self._task_graph = self._build_task_graph() if StateGraph else None

    @property
    def engine_name(self) -> str:
        return "langgraph" if self._graph else "sequential-compatible-graph"

    def set_agents(
        self,
        *,
        architect,
        scout,
        engineer,
        critic,
        sandbox,
    ) -> None:
        self._architect_agent = architect
        self._scout_agent = scout
        self._engineer_agent = engineer
        self._critic_agent = critic
        self._sandbox_runner = sandbox

    def _build_graph(self):
        workflow = StateGraph(WorkflowState)
        workflow.add_node(AgentNode.ARCHITECT.value, self._architect_node)
        workflow.add_node(AgentNode.SCOUT.value, self._scout_node)
        workflow.add_node(AgentNode.ENGINEER.value, self._engineer_node)
        workflow.add_node(AgentNode.CRITIC.value, self._critic_node)
        workflow.add_node(AgentNode.ROUTER.value, self._router_node)
        workflow.add_node(AgentNode.ESCALATION.value, self._terminal_node)
        workflow.add_node(AgentNode.APPROVAL.value, self._terminal_node)
        workflow.add_node(AgentNode.COMPLETION.value, self._terminal_node)

        workflow.set_entry_point(AgentNode.ARCHITECT.value)
        workflow.add_conditional_edges(
            AgentNode.ARCHITECT.value,
            self._route_after_architect,
            {
                "scout": AgentNode.SCOUT.value,
                "completion": AgentNode.COMPLETION.value,
            },
        )
        workflow.add_edge(AgentNode.SCOUT.value, AgentNode.ENGINEER.value)
        workflow.add_conditional_edges(
            AgentNode.ENGINEER.value,
            self._route_after_engineer,
            {
                "critic": AgentNode.CRITIC.value,
                "escalation": AgentNode.ESCALATION.value,
            },
        )
        workflow.add_edge(AgentNode.CRITIC.value, AgentNode.ROUTER.value)
        workflow.add_conditional_edges(
            AgentNode.ROUTER.value,
            self._route_after_router,
            {
                "approval": AgentNode.APPROVAL.value,
                "escalation": AgentNode.ESCALATION.value,
                "completion": AgentNode.COMPLETION.value,
                "engineer": AgentNode.ENGINEER.value,
            },
        )
        workflow.add_edge(AgentNode.ESCALATION.value, END)
        workflow.add_edge(AgentNode.APPROVAL.value, END)
        workflow.add_edge(AgentNode.COMPLETION.value, END)
        return workflow.compile()

    def _build_task_graph(self):
        """Compile the authoritative per-finding remediation loop."""
        workflow = StateGraph(WorkflowState)
        workflow.add_node(AgentNode.SCOUT.value, self._scout_node)
        workflow.add_node(AgentNode.ENGINEER.value, self._engineer_node)
        workflow.add_node(AgentNode.CRITIC.value, self._critic_node)
        workflow.add_node(AgentNode.ROUTER.value, self._router_node)
        workflow.add_node(AgentNode.ESCALATION.value, self._terminal_node)
        workflow.add_node(AgentNode.APPROVAL.value, self._terminal_node)

        workflow.set_entry_point(AgentNode.SCOUT.value)
        workflow.add_edge(AgentNode.SCOUT.value, AgentNode.ENGINEER.value)
        workflow.add_conditional_edges(
            AgentNode.ENGINEER.value,
            self._route_after_engineer,
            {
                "critic": AgentNode.CRITIC.value,
                "escalation": AgentNode.ESCALATION.value,
            },
        )
        workflow.add_edge(AgentNode.CRITIC.value, AgentNode.ROUTER.value)
        workflow.add_conditional_edges(
            AgentNode.ROUTER.value,
            self._route_after_router,
            {
                "approval": AgentNode.APPROVAL.value,
                "escalation": AgentNode.ESCALATION.value,
                "completion": AgentNode.APPROVAL.value,
                "engineer": AgentNode.ENGINEER.value,
            },
        )
        workflow.add_edge(AgentNode.ESCALATION.value, END)
        workflow.add_edge(AgentNode.APPROVAL.value, END)
        return workflow.compile()

    async def run(self, *, session_id: str, memory: RepositoryMemory, repo_path: str) -> WorkflowState:
        state: WorkflowState = {
            "session_id": session_id,
            "repo_path": repo_path,
            "trace": [],
            "memory": memory,
            "tasks": [],
            "task": None,
            "evidence": None,
            "patch": None,
            "validation": None,
            "critic_risk": None,
            "iteration": 1,
            "logical_delta": 0.0,
            "accumulated_delta": 0.0,
            "escalation_reason": None,
            "graph_engine": self.engine_name,
            "mcp_messages": [],
        }
        if self._graph:
            return await self._graph.ainvoke(state)

        state = await self._architect_node(state)
        if self._route_after_architect(state) == "completion":
            return await self._terminal_node(state)
        state = await self._scout_node(state)
        state = await self._engineer_node(state)
        if self._route_after_engineer(state) == "escalation":
            return await self._terminal_node(state)
        state = await self._critic_node(state)
        state = await self._router_node(state)
        return await self._terminal_node(state)

    async def run_task(
        self,
        *,
        session_id: str,
        memory: RepositoryMemory,
        repo_path: str,
        task: AgentTask,
        operator_hint: str | None = None,
    ) -> WorkflowState:
        """Run Scout → Engineer → debate → Critic → Router for a single task."""
        state: WorkflowState = {
            "session_id": session_id,
            "repo_path": repo_path,
            "trace": [],
            "memory": memory,
            "tasks": [task],
            "task": task,
            "evidence": None,
            "patch": None,
            "validation": None,
            "critic_risk": None,
            "iteration": 1,
            "logical_delta": 0.0,
            "accumulated_delta": 0.0,
            "escalation_reason": None,
            "graph_engine": self.engine_name,
            "mcp_messages": [],
            "operator_hint": operator_hint,
        }
        if self._task_graph:
            return await self._task_graph.ainvoke(state)

        state = await self._scout_node(state)
        state = await self._engineer_node(state)
        if self._route_after_engineer(state) == "escalation":
            return state
        state = await self._critic_node(state)
        state = await self._router_node(state)
        return state

    async def _architect_node(self, state: WorkflowState) -> WorkflowState:
        if not self._architect_agent:
            raise RuntimeError("Architect agent not set")
        tasks, messages = self._architect_agent.build_tasks(state["session_id"], state["memory"])
        state["tasks"] = tasks
        state["mcp_messages"] = messages
        state["task"] = tasks[0] if tasks else None
        self._trace(state, AgentRole.ARCHITECT, "planned_tasks", {"task_count": len(tasks)})
        return state

    async def _scout_node(self, state: WorkflowState) -> WorkflowState:
        if not self._scout_agent or not state["task"]:
            raise RuntimeError("Scout agent or task not set")
        evidence = self._scout_agent.retrieve(state["memory"], state["task"])
        state["evidence"] = evidence
        self._trace(
            state,
            AgentRole.SCOUT,
            "retrieved_evidence",
            {"finding": evidence.finding.rule_id, "chunks": len(evidence.related_chunks)},
        )
        return state

    async def _engineer_node(self, state: WorkflowState) -> WorkflowState:
        if not self._engineer_agent or not state["evidence"]:
            raise RuntimeError("Engineer agent or evidence not set")
        failure_reason = None
        if state["iteration"] > 1 and state.get("critic_risk"):
            risk = state["critic_risk"]
            failure_reason = risk.get("reasoning", "Validation failed in sandbox") if isinstance(risk, dict) else str(risk)

        try:
            patch = self._engineer_agent.propose_patch(
                repo_root=Path(state["repo_path"]),
                evidence=state["evidence"],
                iteration=state["iteration"],
                operator_hint=state.get("operator_hint"),
                failure_reason=failure_reason,
            )
            state["patch"] = patch
            self._trace(
                state,
                AgentRole.ENGINEER,
                "generated_patch",
                {"patch_id": patch.patch_id, "files": [file.file_path for file in patch.files]},
            )
        except Exception as exc:
            state["escalation_reason"] = f"Patch generation failed: {exc}"
            self._trace(
                state,
                AgentRole.ENGINEER,
                "patch_generation_failed",
                {"error": exc.__class__.__name__, "message": str(exc)},
            )
        return state

    async def _critic_node(self, state: WorkflowState) -> WorkflowState:
        if not self._critic_agent or not self._sandbox_runner or not state["patch"]:
            raise RuntimeError("Critic agent, sandbox runner, or patch not set")

        patch = state["patch"]
        challenges = self._critic_agent.adversarial_challenge(patch)
        self._trace(
            state,
            AgentRole.CRITIC,
            "adversarial_challenges",
            {"challenges": challenges, "count": len(challenges)},
        )
        original_content = ""
        if patch.files:
            original_path = Path(state["repo_path"]) / patch.files[0].file_path
            if original_path.exists():
                original_content = original_path.read_text(encoding="utf-8")
        if self._engineer_agent and challenges:
            patch = self._engineer_agent.defend_patch(
                original=original_content,
                patch=patch,
                challenges=challenges,
            )
            state["patch"] = patch
            self._trace(
                state,
                AgentRole.ENGINEER,
                "patch_defended",
                {"challenges_count": len(challenges)},
            )

        self._trace(
            state,
            AgentRole.CRITIC,
            "validation_started",
            {"engine": self._sandbox_runner.engine_name, "status": "booting"},
        )

        validation = self._sandbox_runner.validate(
            repo_root=Path(state["repo_path"]),
            memory=state["memory"],
            patch=state["patch"],
        )
        state["validation"] = validation
        state["critic_risk"] = self._critic_agent.risk_assessment(
            patch=state["patch"],
            validation=validation,
        )

        sandbox_meta = validation.sandbox_metadata
        self._trace(
            state,
            AgentRole.CRITIC,
            "validated_patch",
            {
                "verdict": validation.verdict,
                "risk": state["critic_risk"],
                "passing_tests": validation.passing_tests,
                "total_tests": validation.total_tests,
                "sandbox_engine": sandbox_meta.engine if sandbox_meta else "unknown",
                "boot_time_ms": sandbox_meta.boot_time_ms if sandbox_meta else 0,
            },
        )
        return state

    async def _router_node(self, state: WorkflowState) -> WorkflowState:
        validation = state["validation"]
        if not validation:
            state["escalation_reason"] = "Validation did not run"
            return state
        delta = self._calculate_delta(validation)
        state["logical_delta"] = delta
        state["accumulated_delta"] += delta
        if validation.verdict != Verdict.APPROVE:
            if state["iteration"] < self._config.max_iterations:
                # We will retry
                pass
            else:
                state["escalation_reason"] = "Critic rejected the patch (Max iterations reached)"
        elif state["accumulated_delta"] < self._config.convergence_threshold:
            state["escalation_reason"] = "Validation did not converge above approval threshold"
            
        self._trace(
            state,
            AgentRole.ROUTER,
            "routed_verdict",
            {"delta": round(delta, 4), "escalation_reason": state["escalation_reason"], "iteration": state["iteration"]},
        )
        
        # Emit rejection event if we are going to loop
        if validation.verdict != Verdict.APPROVE and not state["escalation_reason"]:
            if self._event_bus:
                import asyncio
                asyncio.ensure_future(self._event_bus.publish(
                    AuditEvent(
                        session_id=state["session_id"],
                        event_type=EventType.CRITIC_REJECTION,
                        agent=AgentRole.CRITIC,
                        payload={"iteration": state["iteration"], "reason": state["critic_risk"].get("reasoning", "Validation failed") if isinstance(state["critic_risk"], dict) else "Validation failed"},
                    )
                ))
            state["iteration"] += 1
        return state

    async def _terminal_node(self, state: WorkflowState) -> WorkflowState:
        route = self._route_after_router(state) if state["validation"] else "completion"
        self._trace(state, AgentRole.ROUTER, f"terminal_{route}", {"engine": state["graph_engine"]})
        return state

    def _route_after_architect(self, state: WorkflowState) -> str:
        return "scout" if state["task"] else "completion"

    def _route_after_router(self, state: WorkflowState) -> str:
        if state["escalation_reason"]:
            return "escalation"
        if state["validation"] and state["validation"].verdict != Verdict.APPROVE:
            return "engineer"
        if state["accumulated_delta"] >= self._config.convergence_threshold:
            return "approval"
        return "completion"

    def _route_after_engineer(self, state: WorkflowState) -> str:
        return "escalation" if state["escalation_reason"] or not state["patch"] else "critic"

    def _calculate_delta(self, validation: ValidationResult) -> float:
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
        return 0.5 * test_score + 0.3 * security_score + 0.2 * coverage_score

    def _trace(
        self,
        state: WorkflowState,
        agent: AgentRole,
        action: str,
        payload: dict[str, Any],
    ) -> None:
        state["trace"].append(
            {
                "agent": agent,
                "action": action,
                "payload": payload,
            }
        )
