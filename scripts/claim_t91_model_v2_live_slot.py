#!/usr/bin/env python3
"""Claim a locked T9.1 Model V2 train or validation live slot."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence


SCRIPT_PATH = Path(__file__)
sys.path.insert(0, str(SCRIPT_PATH.parent.parent / "python"))

from nids_mvp import full_flow_v2_split as split  # noqa: E402


def _add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--slot-id", required=True)
    parser.add_argument("--collection-session-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--run-token", required=True)
    parser.add_argument("--run-contract-sha256", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    claim = commands.add_parser("claim")
    commands.add_parser("validate")
    _add_identity_arguments(check)
    _add_identity_arguments(claim)
    return parser


def _request(args: argparse.Namespace) -> split.ClaimRequest:
    return split.ClaimRequest(
        slot_id=args.slot_id,
        collection_session_id=args.collection_session_id,
        attempt_id=args.attempt_id,
        run_token=args.run_token,
        run_contract_sha256=args.run_contract_sha256,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        split._assert_filesystem_allowlist()
        if args.command == "validate":
            claims = split.validate_published_claims()
            print(
                f"[T9.1 V2 claims] status=passed count={len(claims)} "
                "holdout=sealed test=sealed",
                flush=True,
            )
            return 0
        request = _request(args)
        if args.command == "check":
            _target, document = split.prepare_claim(request)
            print(
                f"[T9.1 V2 claim check] status=passed "
                f"slot={document['slot_id']} "
                f"target={split.CLAIM_ROOT}/{document['slot_id']}.json "
                "published=false holdout=sealed test=sealed",
                flush=True,
            )
            return 0
        _target, document = split.publish_claim(request)
        print(
            f"[T9.1 V2 claim] status=published "
            f"slot={document['slot_id']} "
            f"receipt={split.CLAIM_ROOT}/{document['slot_id']}.json "
            "holdout=sealed test=sealed",
            flush=True,
        )
        return 0
    except (
        FileExistsError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
