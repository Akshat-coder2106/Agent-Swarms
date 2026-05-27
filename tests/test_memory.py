from __future__ import annotations

import unittest
from pathlib import Path

from sentinel.config import load_settings
from sentinel.memory import RepositoryIngestor


class RepositoryMemoryTest(unittest.TestCase):
    def test_ingestion_finds_python_sql_injection_and_symbols(self) -> None:
        repo = Path("examples/python-vulnerable-api").resolve()
        ingestor = RepositoryIngestor(load_settings())

        memory = ingestor.ingest(str(repo))

        self.assertGreaterEqual(memory.files_indexed, 2)
        self.assertTrue(any(symbol.name == "search_users" for symbol in memory.symbols))
        self.assertTrue(
            any(finding.rule_id == "python.sql_injection.fstring" for finding in memory.findings)
        )
        self.assertEqual(
            memory.validation_commands,
            [["python3", "-m", "unittest", "discover", "-s", "tests"]],
        )

    def test_detection_covers_additional_real_world_patterns(self) -> None:
        from sentinel.memory import detect_findings

        source = "\n".join(
            [
                "import pickle",
                "import random",
                "import yaml",
                "def load(data): return pickle.loads(data)",
                "def token(): return random.choice('abcdef')",
                "def parse(raw): return yaml.load(raw)",
                "def fetch(request): return open(request.args.get('path')).read()",
            ]
        )

        findings = detect_findings(Path("."), Path("app.py"), source)
        rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("python.insecure_deserialization.pickle", rule_ids)
        self.assertIn("python.weak_random.security", rule_ids)
        self.assertIn("python.yaml_load", rule_ids)
        self.assertIn("python.path_traversal.user_controlled_path", rule_ids)
