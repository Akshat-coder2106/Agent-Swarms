#!/usr/bin/env python3
"""Create a Windows-compatible submission zip (no dependencies)."""

from __future__ import annotations

import argparse
import zipfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_NAME = f"Project-Sentinel-v4-FINAL-{date.today().isoformat()}.zip"

SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    ".vite",
    "coverage",
    ".cursor",
    "assets",
    "htmlcov",
}

SKIP_FILE_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".log", ".zip"}
SKIP_FILE_NAMES = {
    ".env",
    "benchmark-results.json",
    "coverage.xml",
    ".DS_Store",
}


def should_skip(path: Path) -> bool:
    for part in path.parts:
        if part in SKIP_DIR_NAMES:
            return True
        if part.endswith(".egg-info"):
            return True
    if path.name in SKIP_FILE_NAMES:
        return True
    if path.suffix.lower() in SKIP_FILE_SUFFIXES:
        return True
    return False


def build_zip(output: Path, folder_name: str = "Agent-Swarms") -> int:
    if output.exists():
        output.unlink()

    count = 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zf:
        for file_path in sorted(REPO.rglob("*")):
            if not file_path.is_file():
                continue
            if should_skip(file_path):
                continue
            if file_path.resolve() == output.resolve():
                continue
            rel = file_path.relative_to(REPO)
            arcname = f"{folder_name}/{rel.as_posix()}"
            zinfo = zipfile.ZipInfo(arcname)
            zinfo.compress_type = zipfile.ZIP_STORED
            zinfo.flag_bits |= 0x800
            zf.writestr(zinfo, file_path.read_bytes())
            count += 1

    bad = zipfile.ZipFile(output).testzip()
    if bad is not None:
        raise SystemExit(f"Zip verification failed at: {bad}")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Build submission zip without dependencies.")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO / DEFAULT_NAME,
        help="Output zip path",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Also copy zip to user Desktop",
    )
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    count = build_zip(output)
    size_mb = output.stat().st_size / (1024 * 1024)
    print(f"Created: {output}")
    print(f"Files: {count}")
    print(f"Size: {size_mb:.2f} MB")
    print("OK: zip integrity verified")

    if args.desktop:
        desktop = Path.home() / "Desktop" / output.name
        desktop.write_bytes(output.read_bytes())
        print(f"Copied: {desktop}")


if __name__ == "__main__":
    main()
