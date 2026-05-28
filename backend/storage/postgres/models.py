"""
PostgreSQL SQLAlchemy Models.

Replaces ephemeral in-memory state with durable persistence.
"""
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String, unique=True, nullable=False)
    installation_id = Column(String, nullable=True) # GitHub App installation
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditSessionDurable(Base):
    __tablename__ = "audit_sessions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(String, ForeignKey("repositories.id"), nullable=False)
    status = Column(String, nullable=False, default="running")
    findings = Column(JSON, default=list) # Store structured findings
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

class PatchRecord(Base):
    __tablename__ = "patches"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("audit_sessions.id"), nullable=False)
    rationale = Column(Text, nullable=False)
    unified_diff = Column(Text, nullable=False)
    is_safe = Column(Boolean, default=False)
    exit_code = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
