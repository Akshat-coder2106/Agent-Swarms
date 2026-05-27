"""
Role-Based Access Control (RBAC).

Defines roles, permissions, and access logic.
"""
from enum import Enum


class Role(str, Enum):
    ADMIN = "Admin"
    OPERATOR = "Operator"
    REVIEWER = "Reviewer"
    READONLY = "ReadOnly"


class Permission(str, Enum):
    APPROVE_PATCH = "approve_patch"
    ROLLBACK = "rollback"
    TRIGGER_WORKFLOW = "trigger_workflow"
    VIEW_LOGS = "view_logs"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.ADMIN: {
        Permission.APPROVE_PATCH,
        Permission.ROLLBACK,
        Permission.TRIGGER_WORKFLOW,
        Permission.VIEW_LOGS,
    },
    Role.OPERATOR: {
        Permission.TRIGGER_WORKFLOW,
        Permission.VIEW_LOGS,
    },
    Role.REVIEWER: {
        Permission.APPROVE_PATCH,
        Permission.VIEW_LOGS,
    },
    Role.READONLY: {
        Permission.VIEW_LOGS,
    },
}


def has_permission(role_name: str, permission: Permission) -> bool:
    """Check if a specific role has a permission."""
    try:
        role = Role(role_name)
        return permission in ROLE_PERMISSIONS.get(role, set())
    except ValueError:
        return False
