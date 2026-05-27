"""
OpenTelemetry Tracing configuration.

Traces workflow duration, LLM latency, and sandbox latency.
"""
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def setup_telemetry(service_name: str = "sentinel-backend"):
    """Initialize OpenTelemetry tracing."""
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    
    # Configure OTLP Exporter (e.g. Jaeger, Honeycomb, Datadog)
    exporter = OTLPSpanExporter(endpoint="http://localhost:4317", insecure=True)
    processor = BatchSpanProcessor(exporter)
    provider.add_span_processor(processor)
    
    trace.set_tracer_provider(provider)
    return trace.get_tracer(service_name)


tracer = setup_telemetry()

# Example usage:
# with tracer.start_as_current_span("sandbox_execution") as span:
#     span.set_attribute("vm_id", "1234")
