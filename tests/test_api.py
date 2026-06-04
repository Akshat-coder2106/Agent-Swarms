from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from sentinel.api import app


class ApiAuthTest(unittest.TestCase):
    def test_auth_context_and_capabilities_require_bearer_token(self) -> None:
        client = TestClient(app, base_url="http://localhost")

        token_response = client.post("/api/auth/dev-token", json={"subject": "judge"})
        self.assertEqual(token_response.status_code, 200)
        token = token_response.json()["access_token"]

        auth_response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(auth_response.status_code, 200)
        self.assertEqual(auth_response.json()["subject"], "judge")

        capabilities_response = client.get(
            "/api/system/capabilities",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(capabilities_response.status_code, 200)
        payload = capabilities_response.json()
        self.assertFalse(payload["production_complete"])
        self.assertIn("runtime", payload)
        self.assertIn("sandbox_engine", payload["runtime"])
        self.assertTrue(
            any(item["status"] == "IMPLEMENTED" for item in payload["capabilities"])
        )
        external = next(item for item in payload["capabilities"] if item["key"] == "external_scanners")
        self.assertEqual(external["status"], "MVP_ADAPTER")

        unauthenticated = client.get("/api/system/capabilities")
        self.assertEqual(unauthenticated.status_code, 401)
