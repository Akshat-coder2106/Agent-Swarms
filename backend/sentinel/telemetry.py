"""OpenTelemetry distributed tracing integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter


@dataclass
class TelemetryConfig:
    """Configuration for OpenTelemetry integration."""

    service_name: str = "sentinel"
    otlp_endpoint: str = "http://localhost:4317"
    enable_console_exporter: bool = False
    enable_jaeger: bool = False
    jaeger_endpoint: str | None = None
    sample_rate: float = 1.0


class TelemetryManager:
    """Manager for OpenTelemetry distributed tracing."""

    def __init__(self, config: TelemetryConfig) -> None:
        self._config = config
        self._tracer_provider: TracerProvider | None = None

    def setup_tracing(self) -> None:
        """Set up OpenTelemetry tracing."""
        resource = Resource.create(
            {
                SERVICE_NAME: self._config.service_name,
                "service.version": "0.1.0",
                "deployment.environment": self._config.service_name,
            }
        )

        self._tracer_provider = TracerProvider(resource=resource)

        # Add OTLP exporter
        otlp_exporter = OTLPSpanExporter(
            endpoint=self._config.otlp_endpoint,
            insecure=True,
        )
        self._tracer_provider.add_span_processor(
            BatchSpanProcessor(otlp_exporter)
        )

        # Add console exporter for debugging
        if self._config.enable_console_exporter:
            console_exporter = ConsoleSpanExporter()
            self._tracer_provider.add_span_processor(
                BatchSpanProcessor(console_exporter)
            )

        # Set global tracer provider
        trace.set_tracer_provider(self._tracer_provider)

    def instrument_fastapi(self, app) -> None:
        """Instrument FastAPI application."""
        FastAPIInstrumentor.instrument_app(app)

    def instrument_httpx(self) -> None:
        """Instrument HTTPX client."""
        HTTPXClientInstrumentor().instrument()

    def instrument_requests(self) -> None:
        """Instrument requests library."""
        RequestsInstrumentor().instrument()

    def get_tracer(self, name: str = "sentinel"):
        """Get a tracer instance."""
        return trace.get_tracer(name)

    def shutdown(self) -> None:
        """Shutdown the tracer provider."""
        if self._tracer_provider:
            self._tracer_provider.shutdown()


class TracingContext:
    """Context manager for creating spans."""

    def __init__(self, tracer: trace.Tracer, name: str, attributes: dict[str, Any] | None = None):
        self._tracer = tracer
        self._name = name
        self._attributes = attributes or {}
        self._span = None

    def __enter__(self):
        self._span = self._tracer.start_as_current_span(
            self._name,
            attributes=self._attributes,
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self._span.set_status(trace.Status(trace.StatusCode.ERROR, str(exc_val)))
        self._span.end()

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        if self._span:
            self._span.set_attribute(key, value)

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add an event to the span."""
        if self._span:
            self._span.add_event(name, attributes or {})

    def record_exception(self, exception: Exception) -> None:
        """Record an exception in the span."""
        if self._span:
            self._span.record_exception(exception)


def trace_agent_execution(tracer: trace.Tracer, agent_type: str):
    """Decorator for tracing agent execution."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with TracingContext(
                tracer,
                f"agent.{agent_type}.execute",
                attributes={
                    "agent.type": agent_type,
                    "agent.session_id": kwargs.get("session_id", ""),
                },
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("execution.success", True)
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_attribute("execution.success", False)
                    raise
        return wrapper
    return decorator


def trace_memory_operation(tracer: trace.Tracer, operation: str):
    """Decorator for tracing memory operations."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with TracingContext(
                tracer,
                f"memory.{operation}",
                attributes={
                    "memory.operation": operation,
                    "memory.session_id": kwargs.get("session_id", ""),
                },
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("operation.success", True)
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_attribute("operation.success", False)
                    raise
        return wrapper
    return decorator


def trace_sandbox_execution(tracer: trace.Tracer, sandbox_type: str):
    """Decorator for tracing sandbox execution."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with TracingContext(
                tracer,
                f"sandbox.{sandbox_type}.execute",
                attributes={
                    "sandbox.type": sandbox_type,
                    "sandbox.session_id": kwargs.get("session_id", ""),
                },
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("execution.success", True)
                    span.set_attribute("execution.duration_ms", result.get("duration_ms", 0))
                    return result
                except Exception as e:
                    span.record_exception(e)
                    span.set_attribute("execution.success", False)
                    raise
        return wrapper
    return decorator
