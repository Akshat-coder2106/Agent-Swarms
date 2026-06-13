from __future__ import annotations

import base64
import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from sandbox_service.guest_agent import handle_sync_workspace


def _archive(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            raw = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


class FirecrackerWorkspaceTransferTest(unittest.TestCase):
    def test_guest_receives_digest_verified_patched_workspace(self) -> None:
        archive = _archive({"app/main.py": "value = 'patched'\n"})
        digest = hashlib.sha256(archive).hexdigest()
        with tempfile.TemporaryDirectory() as temp_dir:
            result = handle_sync_workspace(
                {
                    "archive_b64": base64.b64encode(archive).decode("ascii"),
                    "archive_sha256": digest,
                    "working_dir": temp_dir,
                }
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["workspace_sha256"], digest)
            self.assertEqual(
                (Path(temp_dir) / "app/main.py").read_text(encoding="utf-8"),
                "value = 'patched'\n",
            )

    def test_guest_rejects_archive_path_traversal(self) -> None:
        archive = _archive({"../escape.py": "bad = True\n"})
        with tempfile.TemporaryDirectory() as temp_dir:
            result = handle_sync_workspace(
                {
                    "archive_b64": base64.b64encode(archive).decode("ascii"),
                    "archive_sha256": hashlib.sha256(archive).hexdigest(),
                    "working_dir": temp_dir,
                }
            )
            self.assertNotEqual(result["exit_code"], 0)
