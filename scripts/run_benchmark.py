from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from sentinel.models import AuditSession
from sentinel.report_generator import generate_markdown_report


def run_benchmark() -> dict[str, float | int | str]:
    start = time.perf_counter()
    session = AuditSession(objective="benchmark", repo_path=".")
    report = generate_markdown_report(session)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
    return {
        "name": "bundled-fixture",
        "sessions": 1,
        "report_bytes": len(report.encode("utf-8")),
        "elapsed_ms": elapsed_ms,
        "status": "ok",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bundled Project Sentinel benchmark.")
    parser.add_argument("--output", default="benchmark-results.json", help="Path to write benchmark JSON.")
    args = parser.parse_args()

    result = run_benchmark()
    output_path = Path(args.output)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
