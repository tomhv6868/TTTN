from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping, Sequence


CHECKPOINTS = ("F3", "F5", "F7", "F9")
BUNDLE_MEMBERS = (
    "feature_schema.json",
    "preprocessing.json",
    "hbos.json",
    "thresholds.json",
    "models/flow_rf.onnx",
    "models/isolation_forest.onnx",
    "models/known_family_rf.onnx",
    "manifest.json",
)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def resolve_inside(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes project root: {relative}") from error
    return candidate


def verify_file(path: Path, size_bytes: int, sha256: str, context: str) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size != size_bytes
        or sha256_path(path) != sha256
    ):
        raise ValueError(f"{context} content mismatch: {path}")


def verify_staged(directory: Path, artifact: Mapping[str, Any]) -> None:
    manifest_path = directory / "manifest.json"
    verify_file(
        manifest_path,
        manifest_path.stat().st_size if manifest_path.is_file() else -1,
        str(artifact["manifest_sha256"]),
        "staged manifest",
    )
    manifest = load_json(manifest_path)
    records = manifest.get("members")
    if not isinstance(records, list) or [
        record.get("path") for record in records if isinstance(record, dict)
    ] != list(BUNDLE_MEMBERS[:-1]):
        raise ValueError("staged manifest member list mismatch")
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("staged manifest member record is not an object")
        relative = str(record.get("path", ""))
        if relative not in BUNDLE_MEMBERS[:-1]:
            raise ValueError(f"unexpected staged member: {relative}")
        verify_file(
            directory / relative,
            int(record.get("size_bytes", -1)),
            str(record.get("sha256", "")),
            "staged member",
        )


def load_artifact(project_root: Path, checkpoint: str) -> tuple[Path, dict[str, Any]]:
    acceptance_path = project_root / "run_log/t5.1/acceptance.json"
    acceptance = load_json(acceptance_path)
    if acceptance.get("task") != "T5.1" or acceptance.get("status") != "passed":
        raise ValueError("T5.1 acceptance is not passed")
    artifact = acceptance.get("artifacts", {}).get(checkpoint)
    if not isinstance(artifact, dict):
        raise ValueError(f"missing accepted T5.1 artifact: {checkpoint}")
    archive = resolve_inside(project_root, str(artifact.get("path", "")))
    verify_file(
        archive,
        int(artifact.get("size_bytes", -1)),
        str(artifact.get("sha256", "")),
        "accepted archive",
    )
    return archive, artifact


def extract_archive(archive_path: Path, temporary: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        if [info.filename for info in infos] != list(BUNDLE_MEMBERS):
            raise ValueError("bundle archive member list mismatch")
        if archive.testzip() is not None:
            raise ValueError("bundle archive CRC failure")
        for info in infos:
            if info.is_dir():
                raise ValueError(f"bundle contains a directory entry: {info.filename}")
            output = temporary / info.filename
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, output.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)


def stage_bundle(
    project_root: Path,
    checkpoint: str,
    output_root: Path,
) -> tuple[Path, str]:
    if checkpoint not in CHECKPOINTS:
        raise ValueError(f"unsupported checkpoint: {checkpoint}")
    root = project_root.resolve()
    archive, artifact = load_artifact(root, checkpoint)
    destination_root = output_root.resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = destination_root / checkpoint
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise ValueError(f"staging destination is not a directory: {destination}")
        verify_staged(destination, artifact)
        return destination, "reused"

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{checkpoint}.", dir=destination_root)
    )
    published = False
    try:
        extract_archive(archive, temporary)
        verify_staged(temporary, artifact)
        try:
            os.replace(temporary, destination)
            published = True
        except FileExistsError:
            verify_staged(destination, artifact)
        return destination, "staged" if published else "reused"
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def main(argv: Sequence[str] | None = None) -> int:
    project_default = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Stage an accepted T5.1 bundle before native runtime startup"
    )
    parser.add_argument("--project-root", type=Path, default=project_default)
    parser.add_argument("--checkpoint", choices=CHECKPOINTS, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        path, status = stage_bundle(
            args.project_root,
            args.checkpoint,
            args.output_root,
        )
        print(
            f"[model staging] status={status} checkpoint={args.checkpoint} path={path}",
            flush=True,
        )
        return 0
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
