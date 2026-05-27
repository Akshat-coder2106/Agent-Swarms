"""Prometheus + Grafana metrics integration."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    exposition,
)


class MetricLabel(StrEnum):
    """Metric label names."""

    AGENT_TYPE = "agent_type"
    SESSION_ID = "session_id"
    TASK_ID = "task_id"
    FINDING_CATEGORY = "finding_category"
    FINDING_SEVERITY = "finding_severity"
    SCANNER_TYPE = "scanner_type"
    SANDBOX_TYPE = "sandbox_type"
    STATUS = "status"
    ERROR_TYPE = "error_type"


@dataclass
class MetricsConfig:
    """Configuration for Prometheus metrics."""

    namespace: str = "sentinel"
    subsystem: str = "audit"
    enable_metrics: bool = True
    histogram_buckets: list[float] | None = None

    def __post_init__(self) -> None:
        if self.histogram_buckets is None:
            self.histogram_buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]


class SentinelMetrics:
    """Prometheus metrics collector for Sentinel."""

    def __init__(self, config: MetricsConfig) -> None:
        self._config = config
        self._registry = CollectorRegistry()

        # Session metrics
        self.sessions_total = Counter(
            "sessions_total",
            "Total number of audit sessions",
            [MetricLabel.STATUS],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.sessions_active = Gauge(
            "sessions_active",
            "Number of currently active sessions",
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Agent metrics
        self.agent_tasks_total = Counter(
            "agent_tasks_total",
            "Total number of agent tasks executed",
            [MetricLabel.AGENT_TYPE, MetricLabel.STATUS],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.agent_task_duration = Histogram(
            "agent_task_duration_seconds",
            "Agent task execution duration",
            [MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
            buckets=config.histogram_buckets,
        )

        # Finding metrics
        self.findings_total = Counter(
            "findings_total",
            "Total number of findings detected",
            [MetricLabel.FINDING_CATEGORY, MetricLabel.FINDING_SEVERITY, MetricLabel.SCANNER_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.findings_resolved = Counter(
            "findings_resolved_total",
            "Total number of findings resolved",
            [MetricLabel.FINDING_CATEGORY, MetricLabel.FINDING_SEVERITY],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Patch metrics
        self.patches_proposed = Counter(
            "patches_proposed_total",
            "Total number of patches proposed",
            [MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.patches_approved = Counter(
            "patches_approved_total",
            "Total number of patches approved",
            [MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.patches_rejected = Counter(
            "patches_rejected_total",
            "Total number of patches rejected",
            [MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Sandbox metrics
        self.sandbox_executions_total = Counter(
            "sandbox_executions_total",
            "Total number of sandbox executions",
            [MetricLabel.SANDBOX_TYPE, MetricLabel.STATUS],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.sandbox_execution_duration = Histogram(
            "sandbox_execution_duration_seconds",
            "Sandbox execution duration",
            [MetricLabel.SANDBOX_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
            buckets=config.histogram_buckets,
        )

        # Memory metrics
        self.memory_chunks_indexed = Gauge(
            "memory_chunks_indexed",
            "Number of code chunks indexed",
            [MetricLabel.SESSION_ID],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        self.memory_symbols_indexed = Gauge(
            "memory_symbols_indexed",
            "Number of code symbols indexed",
            [MetricLabel.SESSION_ID],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Token usage metrics
        self.tokens_consumed = Counter(
            "tokens_consumed_total",
            "Total tokens consumed by LLM calls",
            [MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Error metrics
        self.errors_total = Counter(
            "errors_total",
            "Total number of errors",
            [MetricLabel.ERROR_TYPE, MetricLabel.AGENT_TYPE],
            namespace=config.namespace,
            subsystem=config.subsystem,
            registry=self._registry,
        )

        # Build info
        self.build_info = Info(
            "build",
            "Build information",
            namespace=config.namespace,
            registry=self._registry,
        )

    def record_session_created(self, session_id: str) -> None:
        """Record a session creation."""
        self.sessions_total.labels(status="created").inc()
        self.sessions_active.inc()

    def record_session_completed(self, session_id: str, status: str) -> None:
        """Record a session completion."""
        self.sessions_total.labels(status=status).inc()
        self.sessions_active.dec()

    def record_agent_task(self, agent_type: str, status: str, duration: float) -> None:
        """Record an agent task execution."""
        self.agent_tasks_total.labels(agent_type=agent_type, status=status).inc()
        self.agent_task_duration.labels(agent_type=agent_type).observe(duration)

    def record_finding(self, category: str, severity: str, scanner_type: str) -> None:
        """Record a finding detection."""
        self.findings_total.labels(
            finding_category=category,
            finding_severity=severity,
            scanner_type=scanner_type,
        ).inc()

    def record_finding_resolved(self, category: str, severity: str) -> None:
        """Record a finding resolution."""
        self.findings_resolved.labels(
            finding_category=category,
            finding_severity=severity,
        ).inc()

    def record_patch_proposed(self, agent_type: str) -> None:
        """Record a patch proposal."""
        self.patches_proposed.labels(agent_type=agent_type).inc()

    def record_patch_approved(self, agent_type: str) -> None:
        """Record a patch approval."""
        self.patches_approved.labels(agent_type=agent_type).inc()

    def record_patch_rejected(self, agent_type: str) -> None:
        """Record a patch rejection."""
        self.patches_rejected.labels(agent_type=agent_type).inc()

    def record_sandbox_execution(self, sandbox_type: str, status: str, duration: float) -> None:
        """Record a sandbox execution."""
        self.sandbox_executions_total.labels(
            sandbox_type=sandbox_type,
            status=status,
        ).inc()
        self.sandbox_execution_duration.labels(sandbox_type=sandbox_type).observe(duration)

    def record_memory_indexed(self, session_id: str, chunks: int, symbols: int) -> None:
        """Record memory indexing."""
        self.memory_chunks_indexed.labels(session_id=session_id).set(chunks)
        self.memory_symbols_indexed.labels(session_id=session_id).set(symbols)

    def record_tokens_consumed(self, agent_type: str, tokens: int) -> None:
        """Record token consumption."""
        self.tokens_consumed.labels(agent_type=agent_type).inc(tokens)

    def record_error(self, error_type: str, agent_type: str) -> None:
        """Record an error."""
        self.errors_total.labels(error_type=error_type, agent_type=agent_type).inc()

    def set_build_info(self, version: str, commit: str, build_time: str) -> None:
        """Set build information."""
        self.build_info.info({
            "version": version,
            "commit": commit,
            "build_time": build_time,
        })

    def get_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return exposition.generate_latest(self._registry)

    def reset_session_metrics(self, session_id: str) -> None:
        """Reset metrics for a specific session."""
        self.memory_chunks_indexed.labels(session_id=session_id).set(0)
        self.memory_symbols_indexed.labels(session_id=session_id).set(0)


class MetricsMiddleware:
    """FastAPI middleware for metrics."""

    def __init__(self, metrics: SentinelMetrics) -> None:
        self._metrics = metrics
        self._request_duration = Histogram(
            "http_request_duration_seconds",
            "HTTP request duration",
            ["method", "endpoint", "status"],
            namespace=metrics._config.namespace,
            subsystem="api",
            registry=metrics._registry,
            buckets=metrics._config.histogram_buckets,
        )
        self._request_total = Counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "endpoint", "status"],
            namespace=metrics._config.namespace,
            subsystem="api",
            registry=metrics._registry,
        )

    async def __call__(self, request, call_next):
        """Process request and record metrics."""
        start_time = time.monotonic()
        response = await call_next(request)
        duration = time.monotonic() - start_time

        self._request_total.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).inc()

        self._request_duration.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code,
        ).observe(duration)

        return response
