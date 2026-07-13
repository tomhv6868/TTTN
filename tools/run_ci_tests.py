from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "config" / "ci-test-manifest.json"
SUITE_NAMES = ("hermetic", "workspace_acceptance")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict[str, tuple[str, ...]]:
    document = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
    )
    if not isinstance(document, dict):
        raise ValueError("CI test manifest must be a JSON object")
    if set(document) != {"schema_version", "suites"}:
        raise ValueError("CI test manifest has missing or unknown top-level fields")
    if document["schema_version"] != "1.0.0":
        raise ValueError("unsupported CI test manifest schema_version")

    suites = document["suites"]
    if not isinstance(suites, dict) or set(suites) != set(SUITE_NAMES):
        raise ValueError("CI test manifest must define the two supported suites")

    normalized: dict[str, tuple[str, ...]] = {}
    listed: list[str] = []
    for suite_name in SUITE_NAMES:
        entries = suites[suite_name]
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"suite {suite_name} must be a non-empty list")
        if any(
            not isinstance(entry, str)
            or Path(entry).name != entry
            or not entry.startswith("test_")
            or not entry.endswith(".py")
            for entry in entries
        ):
            raise ValueError(f"suite {suite_name} contains an invalid test filename")
        normalized[suite_name] = tuple(entries)
        listed.extend(entries)

    if len(listed) != len(set(listed)):
        raise ValueError("a test module appears in more than one CI suite")

    discovered = {path.name for path in (ROOT / "tests").glob("test_*.py")}
    configured = set(listed)
    if configured != discovered:
        missing = sorted(discovered - configured)
        unknown = sorted(configured - discovered)
        raise ValueError(
            f"CI test manifest mismatch: unclassified={missing}, unknown={unknown}"
        )
    return normalized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate the CI test manifest and run one explicit suite."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--suite", choices=SUITE_NAMES, default="hermetic")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        suites = load_manifest(args.manifest.resolve())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"CI test manifest error: {error}", file=sys.stderr)
        return 2

    counts = ", ".join(f"{name}={len(suites[name])}" for name in SUITE_NAMES)
    print(f"CI test manifest valid: {counts}", flush=True)
    if args.check:
        return 0

    command = [
        sys.executable,
        "-m",
        "unittest",
        "-v",
        *(str(ROOT / "tests" / name) for name in suites[args.suite]),
    ]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
