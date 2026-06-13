"""Health checks for startup."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def check_imports() -> dict[str, bool]:
    """Check critical imports."""
    checks = {}
    
    try:
        import semantic_kernel  # noqa: F401
        checks["semantic_kernel"] = True
        logger.info("✓ Semantic Kernel available")
    except ImportError:
        checks["semantic_kernel"] = False
        logger.warning("⚠ Semantic Kernel not installed (optional)")
    
    try:
        import autogen  # noqa: F401
        checks["autogen"] = True
        logger.info("✓ AutoGen available")
    except ImportError:
        checks["autogen"] = False
        logger.warning("⚠ AutoGen not installed (optional)")
    
    try:
        import langgraph  # noqa: F401
        checks["langgraph"] = True
        logger.info("✓ LangGraph available")
    except ImportError:
        checks["langgraph"] = False
        logger.warning("⚠ LangGraph not installed (optional for dev)")
    
    return checks


async def check_credentials(settings: Any) -> dict[str, bool]:
    """Check credentials."""
    checks = {}
    
    if settings.azure_openai_key and settings.azure_openai_endpoint:
        checks["azure_openai"] = True
        logger.info("✓ Azure OpenAI configured")
    else:
        checks["azure_openai"] = False
        logger.warning("⚠ Azure OpenAI not configured (optional)")
    
    return checks


async def check_storage(settings: Any) -> dict[str, bool]:
    """Check storage."""
    checks = {}
    
    if settings.session_store_backend == "sqlite":
        try:
            import sqlite3
            conn = sqlite3.connect(":memory:")
            conn.execute("SELECT 1")
            conn.close()
            checks["sqlite"] = True
            logger.info("✓ SQLite available")
        except Exception as e:
            checks["sqlite"] = False
            logger.error(f"✗ SQLite failed: {e}")
    
    return checks


async def run_startup_checks(settings: Any) -> bool:
    """Run all startup checks."""
    logger.info("")
    logger.info("=" * 70)
    logger.info("SENTINEL STARTUP HEALTH CHECK")
    logger.info("=" * 70)
    
    imports = await check_imports()
    credentials = await check_credentials(settings)
    storage = await check_storage(settings)
    
    all_checks = {**imports, **credentials, **storage}
    passed = sum(1 for v in all_checks.values() if v)
    total = len(all_checks)
    
    logger.info(f"Health Check: {passed}/{total} passed")
    logger.info("=" * 70)
    logger.info("")
    
    return True
