import pytest
from fastapi.testclient import TestClient

from sentinel.api import app
from sentinel.capabilities import build_system_capabilities
from sentinel.config import load_settings
from sentinel.llm import build_llm_provider
from sentinel.sk_orchestrator import SentinelSKPlugin

client = TestClient(app)

def test_api_startup():
    """Smoke test to ensure the FastAPI app imports and starts correctly."""
    response = client.get("/api/health", headers={"Host": "127.0.0.1"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_capability_reporting():
    """Ensure capability manifest generates without errors."""
    settings = load_settings()
    llm = build_llm_provider(settings)
    capabilities = build_system_capabilities(
        settings=settings, sandbox_engine="auto", llm_provider=llm
    )
    assert capabilities.spec_version == "Project Sentinel v4.0"
    assert len(capabilities.capabilities) > 0

def test_semantic_kernel_initialization():
    """Ensure the Semantic Kernel plugin initializes and registers functions."""
    # This shouldn't raise any exceptions
    plugin = SentinelSKPlugin(orchestrator=None)
    assert plugin is not None
