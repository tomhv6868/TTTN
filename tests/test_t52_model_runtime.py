from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from nids_mvp import model_staging


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def create_workspace(
    root: Path,
    *,
    extra_member: bool = False,
) -> tuple[Path, dict]:
    payloads = {
        name: f"fixture:{name}\n".encode("utf-8")
        for name in model_staging.BUNDLE_MEMBERS[:-1]
    }
    manifest = canonical_json(
        {
            "artifact_id": "nids.native_inference_bundle.v1",
            "checkpoint": "F9",
            "members": [
                {
                    "path": name,
                    "size_bytes": len(payloads[name]),
                    "sha256": sha256_bytes(payloads[name]),
                }
                for name in model_staging.BUNDLE_MEMBERS[:-1]
            ],
        }
    )
    payloads["manifest.json"] = manifest
    archive_path = root / "run_log/t5.1/bundles/F9.bundle.zip"
    archive_path.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in model_staging.BUNDLE_MEMBERS:
            archive.writestr(name, payloads[name])
        if extra_member:
            archive.writestr("../escape", b"blocked")
    artifact = {
        "path": "run_log/t5.1/bundles/F9.bundle.zip",
        "size_bytes": archive_path.stat().st_size,
        "sha256": model_staging.sha256_path(archive_path),
        "manifest_sha256": sha256_bytes(manifest),
    }
    acceptance_path = root / "run_log/t5.1/acceptance.json"
    acceptance_path.write_text(
        json.dumps(
            {
                "task": "T5.1",
                "status": "passed",
                "artifacts": {"F9": artifact},
            }
        ),
        encoding="utf-8",
    )
    return archive_path, artifact


class ModelStagingTests(unittest.TestCase):
    def test_stage_is_atomic_verified_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            create_workspace(root)
            output = root / "staged"

            path, status = model_staging.stage_bundle(root, "F9", output)
            self.assertEqual(status, "staged")
            self.assertEqual(path, output / "F9")
            self.assertEqual(
                sorted(
                    item.relative_to(path).as_posix()
                    for item in path.rglob("*")
                    if item.is_file()
                ),
                sorted(model_staging.BUNDLE_MEMBERS),
            )

            reused, reused_status = model_staging.stage_bundle(root, "F9", output)
            self.assertEqual(reused, path)
            self.assertEqual(reused_status, "reused")

    def test_existing_staging_drift_fails_instead_of_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            create_workspace(root)
            output = root / "staged"
            path, _ = model_staging.stage_bundle(root, "F9", output)
            (path / "thresholds.json").write_bytes(b"drift")

            with self.assertRaisesRegex(ValueError, "staged member content mismatch"):
                model_staging.stage_bundle(root, "F9", output)

    def test_archive_hash_and_member_list_are_locked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, _ = create_workspace(root)
            with archive.open("ab") as output:
                output.write(b"drift")
            with self.assertRaisesRegex(ValueError, "accepted archive content mismatch"):
                model_staging.stage_bundle(root, "F9", root / "staged")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            create_workspace(root, extra_member=True)
            with self.assertRaisesRegex(ValueError, "archive member list mismatch"):
                model_staging.stage_bundle(root, "F9", root / "staged")

    def test_project_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            acceptance = root / "run_log/t5.1/acceptance.json"
            acceptance.parent.mkdir(parents=True)
            acceptance.write_text(
                json.dumps(
                    {
                        "task": "T5.1",
                        "status": "passed",
                        "artifacts": {
                            "F9": {
                                "path": "../outside.zip",
                                "size_bytes": 0,
                                "sha256": "",
                                "manifest_sha256": "",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "path escapes project root"):
                model_staging.stage_bundle(root, "F9", root / "staged")


if __name__ == "__main__":
    unittest.main()
