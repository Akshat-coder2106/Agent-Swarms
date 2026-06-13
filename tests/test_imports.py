"""Test imports."""

import pytest


def test_config_imports():
    """Test config imports."""
    from sentinel.config import Settings, load_settings
    
    assert Settings is not None
    settings = load_settings()
    assert settings.sentinel_environment in ("development", "staging", "production")


def test_models_imports():
    """Test models import."""
    from sentinel.models import AuditSession, PatchProposal, ValidationResult
    
    assert AuditSession is not None
    assert PatchProposal is not None
    assert ValidationResult is not None


def test_api_imports():
    """Test API imports."""
    from sentinel.api import app
    
    assert app is not None
    assert app.title == "Project Sentinel"


def test_agents_imports():
    """Test agents import."""
    from sentinel.agents import ArchitectAgent, ScoutAgent, EngineerAgent, CriticAgent
    
    assert ArchitectAgent is not None
