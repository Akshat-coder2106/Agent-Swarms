"""Argo Workflows integration for DAG execution on Kubernetes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
from kubernetes import client

from .models import AgentTask, Priority


class WorkflowStatus(StrEnum):
    """Argo workflow status."""

    PENDING = "Pending"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    ERROR = "Error"


@dataclass
class ArgoConfig:
    """Configuration for Argo Workflows integration."""

    namespace: str = "sentinel"
    server_url: str = "http://localhost:2746"
    service_account: str = "sentinel-workflow-sa"
    workflow_template_name: str = "sentinel-audit-dag"


@dataclass
class DAGTask:
    """DAG task representation."""

    name: str
    template: str
    dependencies: list[str]
    arguments: dict[str, Any]
    agent_type: str
    priority: Priority


class ArgoWorkflowManager:
    """Manager for Argo Workflows on Kubernetes."""

    def __init__(self, config: ArgoConfig) -> None:
        self._config = config
        self._http_client = httpx.AsyncClient(
            base_url=config.server_url,
            headers={"Authorization": f"Bearer {self._get_token()}"},
            timeout=30,
        )

        # Load Kubernetes config
        try:
            config.load_kube_config()
        except Exception:
            config.load_incluster_config()

        self._custom_api = client.CustomObjectsApi()

    def _get_token(self) -> str:
        """Get service account token for Argo authentication."""
        # In production, this would fetch the actual service account token
        return "sentinel-token"

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http_client.aclose()

    def create_workflow_from_dag(
        self,
        session_id: str,
        tasks: list[AgentTask],
        repo_path: str,
    ) -> str:
        """Create an Argo Workflow from the Architect's DAG."""
        dag_tasks = self._convert_tasks_to_dag(tasks)
        workflow_manifest = self._build_workflow_manifest(
            session_id, dag_tasks, repo_path
        )

        # Submit workflow to Kubernetes
        try:
            response = self._custom_api.create_namespaced_custom_object(
                group="argoproj.io",
                version="v1alpha1",
                namespace=self._config.namespace,
                plural="workflows",
                body=workflow_manifest,
            )
            return response.get("metadata", {}).get("name", "")
        except Exception as exc:
            raise RuntimeError(f"Failed to create Argo workflow: {exc}") from exc

    def _convert_tasks_to_dag(self, tasks: list[AgentTask]) -> list[DAGTask]:
        """Convert AgentTasks to DAG tasks."""
        dag_tasks = []
        for i, task in enumerate(tasks):
            dependencies = []
            if i > 0:
                dependencies.append(tasks[i - 1].task_id)

            dag_task = DAGTask(
                name=task.task_id,
                template="agent-task",
                dependencies=dependencies,
                arguments={
                    "task_id": task.task_id,
                    "target_path": task.target_path,
                    "objective": task.objective,
                    "priority": task.priority,
                    "execution_profile": task.execution_profile,
                },
                agent_type="scout",  # Would be determined by task type
                priority=task.priority,
            )
            dag_tasks.append(dag_task)

        return dag_tasks

    def _build_workflow_manifest(
        self,
        session_id: str,
        dag_tasks: list[DAGTask],
        repo_path: str,
    ) -> dict[str, Any]:
        """Build the Argo Workflow manifest."""
        workflow_name = f"sentinel-audit-{session_id}"

        # Build DAG tasks
        dag_task_entries = []
        for dag_task in dag_tasks:
            task_entry = {
                "name": dag_task.name,
                "template": dag_task.template,
                "arguments": {
                    "parameters": [
                        {"name": k, "value": json.dumps(v)}
                        for k, v in dag_task.arguments.items()
                    ]
                },
            }
            if dag_task.dependencies:
                task_entry["dependencies"] = dag_task.dependencies
            dag_task_entries.append(task_entry)

        manifest = {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Workflow",
            "metadata": {
                "name": workflow_name,
                "namespace": self._config.namespace,
                "labels": {
                    "app": "sentinel",
                    "session-id": session_id,
                },
            },
            "spec": {
                "entrypoint": "audit-dag",
                "serviceAccountName": self._config.service_account,
                "templates": [
                    {
                        "name": "audit-dag",
                        "dag": {
                            "tasks": dag_task_entries,
                        },
                    },
                    {
                        "name": "agent-task",
                        "inputs": {
                            "parameters": [
                                {"name": "task_id"},
                                {"name": "target_path"},
                                {"name": "objective"},
                                {"name": "priority"},
                                {"name": "execution_profile"},
                            ]
                        },
                        "container": {
                            "image": "sentinel-agent:latest",
                            "command": ["python", "-m", "sentinel.cli"],
                            "args": [
                                "--task-id",
                                "{{inputs.parameters.task_id}}",
                                "--target-path",
                                "{{inputs.parameters.target_path}}",
                                "--objective",
                                "{{inputs.parameters.objective}}",
                            ],
                            "env": [
                                {
                                    "name": "SENTINEL_PRIORITY",
                                    "value": "{{inputs.parameters.priority}}",
                                },
                                {
                                    "name": "SENTINEL_EXECUTION_PROFILE",
                                    "value": "{{inputs.parameters.execution_profile}}",
                                },
                            ],
                        },
                    },
                ],
            },
        }

        return manifest

    async def get_workflow_status(self, workflow_name: str) -> dict[str, Any]:
        """Get the status of a workflow."""
        try:
            response = await self._http_client.get(
                f"/api/v1/workflows/{self._config.namespace}/{workflow_name}"
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status": data.get("status", {}).get("phase", "Unknown"),
                "started_at": data.get("status", {}).get("startedAt"),
                "finished_at": data.get("status", {}).get("finishedAt"),
                "nodes": data.get("status", {}).get("nodes", {}),
            }
        except Exception as exc:
            raise RuntimeError(f"Failed to get workflow status: {exc}") from exc

    async def list_workflows(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """List workflows, optionally filtered by session ID."""
        try:
            params = {}
            if session_id:
                params["labelSelector"] = f"session-id={session_id}"

            response = await self._http_client.get(
                f"/api/v1/workflows/{self._config.namespace}",
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("items", [])
        except Exception as exc:
            raise RuntimeError(f"Failed to list workflows: {exc}") from exc

    async def delete_workflow(self, workflow_name: str) -> None:
        """Delete a workflow."""
        try:
            await self._http_client.delete(
                f"/api/v1/workflows/{self._config.namespace}/{workflow_name}"
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to delete workflow: {exc}") from exc

    async def retry_workflow(self, workflow_name: str) -> str:
        """Retry a failed workflow."""
        try:
            response = await self._http_client.post(
                f"/api/v1/workflows/{self._config.namespace}/{workflow_name}/retry"
            )
            response.raise_for_status()
            data = response.json()
            return data.get("metadata", {}).get("name", "")
        except Exception as exc:
            raise RuntimeError(f"Failed to retry workflow: {exc}") from exc

    async def get_workflow_logs(
        self,
        workflow_name: str,
        pod_name: str | None = None,
    ) -> str:
        """Get logs from a workflow."""
        try:
            url = f"/api/v1/workflows/{self._config.namespace}/{workflow_name}/logs"
            if pod_name:
                url += f"?podName={pod_name}"

            response = await self._http_client.get(url)
            response.raise_for_status()
            data = response.json()
            return data.get("logs", "")
        except Exception as exc:
            raise RuntimeError(f"Failed to get workflow logs: {exc}") from exc

    def create_workflow_template(self) -> None:
        """Create the reusable workflow template."""
        template_manifest = {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "WorkflowTemplate",
            "metadata": {
                "name": self._config.workflow_template_name,
                "namespace": self._config.namespace,
            },
            "spec": {
                "entrypoint": "audit-dag",
                "templates": [
                    {
                        "name": "audit-dag",
                        "dag": {
                            "tasks": [
                                {
                                    "name": "scout-task",
                                    "template": "agent-task",
                                    "arguments": {
                                        "parameters": [
                                            {"name": "agent-type", "value": "scout"},
                                        ]
                                    },
                                },
                                {
                                    "name": "engineer-task",
                                    "template": "agent-task",
                                    "dependencies": ["scout-task"],
                                    "arguments": {
                                        "parameters": [
                                            {"name": "agent-type", "value": "engineer"},
                                        ]
                                    },
                                },
                                {
                                    "name": "critic-task",
                                    "template": "agent-task",
                                    "dependencies": ["engineer-task"],
                                    "arguments": {
                                        "parameters": [
                                            {"name": "agent-type", "value": "critic"},
                                        ]
                                    },
                                },
                            ],
                        },
                    },
                    {
                        "name": "agent-task",
                        "inputs": {
                            "parameters": [
                                {"name": "agent-type"},
                            ]
                        },
                        "container": {
                            "image": "sentinel-agent:latest",
                            "command": ["python", "-m", "sentinel.cli"],
                            "args": [
                                "--agent-type",
                                "{{inputs.parameters.agent-type}}",
                            ],
                        },
                    },
                ],
            },
        }

        try:
            self._custom_api.create_namespaced_custom_object(
                group="argoproj.io",
                version="v1alpha1",
                namespace=self._config.namespace,
                plural="workflowtemplates",
                body=template_manifest,
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to create workflow template: {exc}") from exc

    def create_cron_workflow(
        self,
        schedule: str,
        repo_path: str,
    ) -> None:
        """Create a cron workflow for scheduled audits."""
        cron_manifest = {
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "CronWorkflow",
            "metadata": {
                "name": "sentinel-nightly-audit",
                "namespace": self._config.namespace,
            },
            "spec": {
                "schedule": schedule,
                "workflowSpec": {
                    "entrypoint": "audit-dag",
                    "templates": [
                        {
                            "name": "audit-dag",
                            "container": {
                                "image": "sentinel-agent:latest",
                                "command": ["python", "-m", "sentinel.cli"],
                                "args": [repo_path],
                            },
                        },
                    ],
                },
            },
        }

        try:
            self._custom_api.create_namespaced_custom_object(
                group="argoproj.io",
                version="v1alpha1",
                namespace=self._config.namespace,
                plural="cronworkflows",
                body=cron_manifest,
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to create cron workflow: {exc}") from exc
