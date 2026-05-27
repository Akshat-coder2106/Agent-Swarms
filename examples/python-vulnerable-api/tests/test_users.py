from __future__ import annotations

import unittest
from app.users import search_users, get_db_credentials, generate_reset_token, app

class VulnerableAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_search_by_name(self) -> None:
        response = self.client.get("/search?name=Ada")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"], [[1, "Ada"]])

    def test_search_without_match(self) -> None:
        response = self.client.get("/search?name=Katherine")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"], [])
        
    def test_credentials(self) -> None:
        aws, pwd = get_db_credentials()
        self.assertTrue(len(aws) > 0)
        self.assertTrue(len(pwd) > 0)
        
    def test_math(self) -> None:
        response = self.client.get("/math?expr=5*5")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["result"], 25)

if __name__ == "__main__":
    unittest.main()
