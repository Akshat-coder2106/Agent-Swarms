"""Post-deployment regression monitoring and rollback controller."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx
from git import Repo

from .models import (
    AuditSession,
    PatchProposal,
    RollbackReport,
    SessionStatus,
)


class RegressionType(StrEnum):
    """Types of regression triggers."""

    ERROR_RATE_SPIKE = "ERROR_RATE_SPIKE"
    NEW_EXCEPTION_TYPE = "NEW_EXCEPTION_TYPE"
    HEALTH_CHECK_FAILURE = "HEALTH_CHECK_FAILURE"
    MANUAL_OPERATOR_REQUEST = "MANUAL_OPERATOR_REQUEST"


@dataclass
class MonitoringConfig:
    """Configuration for post-deployment monitoring."""

    monitoring_window_minutes: int = 10
    error_rate_threshold_percent: float = 20.0
    health_check_interval_seconds: int = 30
    health_check_max_failures: int = 3
    datadog_api_url: str | None = None
    datadog_api_key: str | None = None
    sentry_api_url: str | None = None
    sentry_api_key: str | None = None
    health_check_url: str | None = None


@dataclass
class RegressionSignal:
    """Signal indicating a regression."""

    regression_type: RegressionType
    timestamp: float
    details: dict[str, Any]
    severity: str = "HIGH"


class RollbackController:
    """Controller for post-deployment monitoring and rollback."""

    def __init__(self, config: MonitoringConfig) -> None:
        self._config = config
        self._http_client = httpx.AsyncClient(timeout=30)
        self._active_monitors: dict[str, asyncio.Task] = {}

    async def close(self) -> None:
        """Close the HTTP client and cancel active monitors."""
        await self._http_client.aclose()
        for task in self._active_monitors.values():
            task.cancel()
        self._active_monitors.clear()

    async def start_monitoring(
        self,
        session: AuditSession,
        patch: PatchProposal,
        repo_path: str,
    ) -> None:
        """Start monitoring for regressions after patch deployment."""
        if patch.patch_id not in session.approved_patch_ids:
            return

        # Start monitoring task
        task = asyncio.create_task(
            self._monitor_deployment(session, patch, repo_path)
        )
        self._active_monitors[session.session_id] = task

    async def _monitor_deployment(
        self,
        session: AuditSession,
        patch: PatchProposal,
        repo_path: str,
    ) -> None:
        """Monitor deployment for regressions."""
        start_time = time.monotonic()
        window_end = start_time + (self._config.monitoring_window_minutes * 60)

        # Get baseline metrics (pre-deployment)
        baseline_error_rate = await self._get_baseline_error_rate(session)

        health_check_failures = 0
        new_exceptions: set[str] = set()

        while time.monotonic() < window_end:
            await asyncio.sleep(self._config.health_check_interval_seconds)

            # Check error rate
            current_error_rate = await self._get_current_error_rate(session)
            if current_error_rate > baseline_error_rate * (1 + self._config.error_rate_threshold_percent / 100):
                regression = RegressionSignal(
                    regression_type=RegressionType.ERROR_RATE_SPIKE,
                    timestamp=time.monotonic(),
                    details={
                        "baseline_error_rate": baseline_error_rate,
                        "current_error_rate": current_error_rate,
                        "threshold_exceeded": self._config.error_rate_threshold_percent,
                    },
                )
                await self._trigger_rollback(session, patch, repo_path, regression)
                return

            # Check for new exception types
            if self._config.sentry_api_url:
                current_exceptions = await self._get_sentry_exceptions(session)
                new_in_window = current_exceptions - new_exceptions
                if new_in_window:
                    regression = RegressionSignal(
                        regression_type=RegressionType.NEW_EXCEPTION_TYPE,
                        timestamp=time.monotonic(),
                        details={
                            "new_exceptions": list(new_in_window),
                            "total_exceptions": len(current_exceptions),
                        },
                    )
                    await self._trigger_rollback(session, patch, repo_path, regression)
                    return
                new_exceptions = current_exceptions

            # Check health endpoint
            if self._config.health_check_url:
                health_ok = await self._check_health_endpoint()
                if not health_ok:
                    health_check_failures += 1
                    if health_check_failures >= self._config.health_check_max_failures:
                        regression = RegressionSignal(
                            regression_type=RegressionType.HEALTH_CHECK_FAILURE,
                            timestamp=time.monotonic(),
                            details={
                                "consecutive_failures": health_check_failures,
                                "max_failures": self._config.health_check_max_failures,
                            },
                        )
                        await self._trigger_rollback(session, patch, repo_path, regression)
                        return
                else:
                    health_check_failures = 0

        # Monitoring window completed successfully
        if session.session_id in self._active_monitors:
            del self._active_monitors[session.session_id]

    async def _get_baseline_error_rate(self, session: AuditSession) -> float:
        """Get baseline error rate before deployment."""
        # In production, this would query Datadog or Prometheus for historical data
        # For now, return a default baseline
        return 0.002  # 0.2% error rate

    async def _get_current_error_rate(self, session: AuditSession) -> float:
        """Get current error rate from monitoring."""
        if not self._config.datadog_api_url or not self._config.datadog_api_key:
            return 0.002  # Default if no monitoring configured

        try:
            # Query Datadog API for error rate
            response = await self._http_client.get(
                f"{self._config.datadog_api_url}/api/v1/query",
                params={
                    "query": f"rate(errors{{service='{session.repo_path}'}}[5m])",
                    "from": int(time.time() - 300),
                },
                headers={"DD-API-KEY": self._config.datadog_api_key},
            )
            response.raise_for_status()
            response.json()
            return 0.002  # Placeholder
        except Exception:
            return 0.002

    async def _get_sentry_exceptions(self, session: AuditSession) -> set[str]:
        """Get current exception types from Sentry."""
        if not self._config.sentry_api_url or not self._config.sentry_api_key:
            return set()

        try:
            response = await self._http_client.get(
                f"{self._config.sentry_api_url}/api/0/issues/",
                headers={"Authorization": f"Bearer {self._config.sentry_api_key}"},
            )
            response.raise_for_status()
            data = response.json()
            return {issue.get("type", "") for issue in data}
        except Exception:
            return set()

    async def _check_health_endpoint(self) -> bool:
        """Check if health endpoint is responding."""
        if not self._config.health_check_url:
            return True

        try:
            response = await self._http_client.get(self._config.health_check_url)
            return response.status_code == 200
        except Exception:
            return False

    async def _trigger_rollback(
        self,
        session: AuditSession,
        patch: PatchProposal,
        repo_path: str,
        regression: RegressionSignal,
    ) -> RollbackReport:
        """Execute rollback when regression is detected."""
        started = time.monotonic()

        try:
            # Git revert the patch
            repo = Repo(repo_path)
            pre_patch_commit = self._find_pre_patch_commit(repo, patch)

            if not pre_patch_commit:
                raise RuntimeError("Could not find pre-patch commit")

            # Create revert commit
            repo.git.revert(pre_patch_commit, no_edit=True)

            # Push revert
            origin = repo.remote(name="origin")
            origin.push()

            rollback_duration = time.monotonic() - started

            # Create rollback report
            report = RollbackReport(
                session_id=session.session_id,
                patch_id=patch.patch_id,
                regression_type=regression.regression_type,
                affected_files=[file.file_path for file in patch.files],
                rollback_duration_sec=rollback_duration,
                root_cause_hypothesis=self._generate_root_cause_hypothesis(regression),
                recommended_action="Re-audit with integration test coverage for the failing scenario",
            )

            # Update session status
            session.status = SessionStatus.ROLLED_BACK
            session.rollback = report

            # Trigger alert (would integrate with PagerDuty in production)
            await self._send_alert(report, regression)

            return report

        except Exception as exc:
            # Log failure and escalate
            raise RuntimeError(f"Rollback failed: {exc}") from exc

    def _find_pre_patch_commit(self, repo: Repo, patch: PatchProposal) -> str | None:
        """Find the commit before the patch was applied."""
        # In production, this would use the patch_id or commit SHA stored during deployment
        # For now, return the second-to-last commit
        commits = list(repo.iter_commits(max_count=2))
        return str(commits[1]) if len(commits) > 1 else None

    def _generate_root_cause_hypothesis(self, regression: RegressionSignal) -> str:
        """Generate a hypothesis for the root cause of the regression."""
        if regression.regression_type == RegressionType.ERROR_RATE_SPIKE:
            return "Patch introduced a bug causing increased error rate"
        elif regression.regression_type == RegressionType.NEW_EXCEPTION_TYPE:
            return f"Patch introduced new exception types: {', '.join(regression.details.get('new_exceptions', []))}"
        elif regression.regression_type == RegressionType.HEALTH_CHECK_FAILURE:
            return "Patch caused service to become unhealthy"
        else:
            return "Unknown regression cause"

    async def _send_alert(
        self,
        report: RollbackReport,
        regression: RegressionSignal,
    ) -> None:
        """Send alert to operations team."""
        # In production, this would integrate with PagerDuty, Slack, etc.
        # For now, log the alert
        print(
            f"ROLLBACK ALERT: {report.regression_type} detected. "
            f"Rollback completed in {report.rollback_duration_sec:.2f}s"
        )

    async def manual_rollback(
        self,
        session: AuditSession,
        patch: PatchProposal,
        repo_path: str,
        reason: str,
    ) -> RollbackReport:
        """Trigger manual rollback by operator request."""
        regression = RegressionSignal(
            regression_type=RegressionType.MANUAL_OPERATOR_REQUEST,
            timestamp=time.monotonic(),
            details={"reason": reason},
        )
        return await self._trigger_rollback(session, patch, repo_path, regression)

    def get_active_monitors(self) -> list[str]:
        """Get list of session IDs with active monitors."""
        return list(self._active_monitors.keys())

    async def stop_monitoring(self, session_id: str) -> None:
        """Stop monitoring for a specific session."""
        if session_id in self._active_monitors:
            self._active_monitors[session_id].cancel()
            del self._active_monitors[session_id]
