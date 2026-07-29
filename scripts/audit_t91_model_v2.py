#!/usr/bin/env python3
"""Audit the T9.1 live failure and lock the Model V2 training boundary."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from nids_mvp import full_flow_v2_audit as audit  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "run", "validate"))
    parser.add_argument("--project-root", type=Path, default=ROOT)
    parser.add_argument(
        "--contract",
        type=Path,
        default=ROOT / audit.DEFAULT_CONTRACT,
    )
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve()
        inputs = audit.verify_inputs(root, args.contract)
        if args.command == "check":
            live, _ = audit.audit_live_attempt(inputs)
            print(
                f"[T9.1 V2 check] status=passed attempt={live['attempt_id']} "
                "test=sealed",
                flush=True,
            )
        elif args.command == "run":
            receipt = audit.publish(inputs)
            print(
                f"[T9.1 V2 audit] status={receipt['status']} "
                f"gate={receipt['gate']['decision']} test=sealed",
                flush=True,
            )
        else:
            audit.validate_receipt(inputs, audit.audit_receipt_path(inputs))
            print("[T9.1 V2 receipt] status=passed test=sealed", flush=True)
        return 0
    except (
        FileExistsError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        audit.pa.ArrowException,
    ) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
