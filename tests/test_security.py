from __future__ import annotations

import unittest

from sentinel.config import load_settings
from sentinel.models import CapabilityStatus
from sentinel.security import AuthenticationError, issue_token, verify_token


class SecurityTokenTest(unittest.TestCase):
    def test_token_is_signed_and_session_scoped(self) -> None:
        settings = load_settings()
        token = issue_token(settings, subject="operator", session_id="sess_123")

        principal = verify_token(settings, token, required_session_id="sess_123")

        self.assertEqual(principal.subject, "operator")
        self.assertEqual(principal.session_id, "sess_123")

    def test_token_rejects_wrong_session(self) -> None:
        settings = load_settings()
        token = issue_token(settings, subject="operator", session_id="sess_123")

        with self.assertRaises(AuthenticationError):
            verify_token(settings, token, required_session_id="sess_other")

    def test_capability_statuses_are_explicit(self) -> None:
        self.assertEqual(CapabilityStatus.IMPLEMENTED, "IMPLEMENTED")
        self.assertEqual(CapabilityStatus.MVP_ADAPTER, "MVP_ADAPTER")
        self.assertEqual(CapabilityStatus.PLANNED, "PLANNED")
