#!/usr/bin/env python3
"""Targeted tests for the reusable detection JSONL streaming auditor."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import audit_detection_jsonl as auditor  # noqa: E402


class WorkspaceFiles:
    def __init__(self) -> None:
        token = uuid.uuid4().hex
        self.prefix = ROOT / "run_log" / "t8.5" / f".detection-audit-test-{token}"
        self.paths: list[Path] = []

    def path(self, suffix: str) -> Path:
        path = self.prefix.with_name(f"{self.prefix.name}.{suffix}")
        self.paths.append(path)
        return path

    def __enter__(self) -> WorkspaceFiles:
        return self

    def __exit__(self, *_: object) -> None:
        for path in self.paths:
            path.unlink(missing_ok=True)


def ready() -> dict[str, object]:
    return {
        "event_type": "nids_dpdk_live_ready",
        "checkpoint": "F9",
        "continuous": True,
    }


def alert(
    *,
    timestamp: int,
    sequence: int,
    decision: str,
    candidate: str,
    source: str,
    destination: str,
) -> dict[str, object]:
    return {
        "event_type": "nids_alert",
        "checkpoint_timestamp_ns": timestamp,
        "clock_domain": "monotonic",
        "decision": decision,
        "evidence": {
            "known_family": {
                "top_candidate": candidate,
            }
        },
        "flow": {
            "id": {
                "namespace": "2",
                "sequence": str(sequence),
            },
            "source": {"ip": source},
            "destination": {"ip": destination},
        },
    }


def write_jsonl(path: Path, values: list[object]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        for value in values:
            if isinstance(value, str):
                output.write(value)
            else:
                output.write(json.dumps(value, ensure_ascii=False))
            output.write("\n")


class DetectionAuditTest(unittest.TestCase):
    def test_streaming_counts_and_two_endpoint_lab_rule(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="unknown_candidate",
                        candidate="DDoS",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                    alert(
                        timestamp=110,
                        sequence=2,
                        decision="known_attack",
                        candidate="DoS Hulk",
                        source="192.168.252.10",
                        destination="192.168.252.20",
                    ),
                    alert(
                        timestamp=120,
                        sequence=3,
                        decision="known_attack",
                        candidate="Bot",
                        source="192.168.252.10",
                        destination="10.0.0.3",
                    ),
                    "{broken",
                ],
            )
            result = auditor.audit_detection_log(
                source,
                input_label="detection.jsonl",
                top_gaps=3,
                lab_subnets=["192.168.252.0/24"],
            )

            self.assertEqual(result["input"]["line_count"], 5)
            self.assertEqual(
                result["input"]["sha256"],
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )
            self.assertEqual(result["alerts"]["total"], 3)
            self.assertEqual(result["alerts"]["chronology_scope_non_lab"], 2)
            self.assertEqual(result["alerts"]["lab_hping3_flood"]["count"], 1)
            self.assertEqual(result["integrity"]["invalid_json_lines"], 1)
            self.assertEqual(result["chronology"]["status"], "not_verifiable")
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["tool"]["whole_file_loaded"])

    def test_manifest_passes_only_allowed_known_attack_candidates(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            manifest = files.path("segments.json")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="known_attack",
                        candidate="FTP-Patator",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                    alert(
                        timestamp=110,
                        sequence=2,
                        decision="unknown_candidate",
                        candidate="DoS GoldenEye",
                        source="10.0.0.3",
                        destination="10.0.0.4",
                    ),
                    alert(
                        timestamp=120,
                        sequence=3,
                        decision="known_attack",
                        candidate="DoS GoldenEye",
                        source="10.0.0.5",
                        destination="10.0.0.6",
                    ),
                ],
            )
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "input_sha256": hashlib.sha256(
                            source.read_bytes()
                        ).hexdigest(),
                        "segments": [
                            {
                                "id": "tuesday",
                                "source_pcap": "Tuesday-WorkingHours.pcap",
                                "start_line": 2,
                                "end_line": 3,
                                "allowed_known_attack_candidates": [
                                    "FTP-Patator",
                                    "SSH-Patator",
                                ],
                            },
                            {
                                "id": "wednesday",
                                "source_pcap": "Wednesday-workingHours.pcap",
                                "start_line": 4,
                                "end_line": 4,
                                "allowed_known_attack_candidates": [
                                    "DoS GoldenEye",
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = auditor.audit_detection_log(
                source,
                input_label="detection.jsonl",
                top_gaps=2,
                lab_subnets=[],
                manifest_path=manifest,
                manifest_label="segments.json",
            )

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["chronology"]["status"], "passed")
            self.assertEqual(
                result["chronology"]["segments"][0]["unexpected_known_attacks"],
                0,
            )
            self.assertEqual(
                result["chronology"]["segments"][1]["unexpected_known_attacks"],
                0,
            )

    def test_manifest_rejects_cross_segment_known_attack(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            manifest = files.path("segments.json")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="known_attack",
                        candidate="DoS GoldenEye",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                ],
            )
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0.0",
                        "input_sha256": hashlib.sha256(
                            source.read_bytes()
                        ).hexdigest(),
                        "segments": [
                            {
                                "id": "thursday",
                                "source_pcap": "Thursday-WorkingHours.pcap",
                                "start_line": 2,
                                "end_line": 2,
                                "allowed_known_attack_candidates": [
                                    "Infiltration",
                                    "Web Attack – Brute Force",
                                    "Web Attack – Sql Injection",
                                    "Web Attack – XSS",
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = auditor.audit_detection_log(
                source,
                input_label="detection.jsonl",
                top_gaps=2,
                lab_subnets=[],
                manifest_path=manifest,
            )

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["chronology"]["status"], "failed")
            segment = result["chronology"]["segments"][0]
            self.assertEqual(segment["unexpected_known_attacks"], 1)
            self.assertEqual(
                segment["unexpected_known_attack_samples"][0]["top_candidate"],
                "DoS GoldenEye",
            )

    def test_timestamp_order_and_gaps_are_scoped_to_runtime(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=200,
                        sequence=2,
                        decision="uncertain",
                        candidate="Bot",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="uncertain",
                        candidate="Bot",
                        source="10.0.0.3",
                        destination="10.0.0.4",
                    ),
                ],
            )
            result = auditor.audit_detection_log(
                source,
                input_label="detection.jsonl",
                top_gaps=2,
                lab_subnets=[],
            )

            self.assertEqual(
                result["ordering"]["timestamp_violation_count"],
                0,
            )
            self.assertEqual(
                result["ordering"]["largest_adjacent_non_lab_alert_gaps"],
                [],
            )

    def test_cli_output_is_deterministic_and_requires_force(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            output = files.path("audit.json")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="uncertain",
                        candidate="Bot",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                ],
            )
            arguments = [
                "--input",
                str(source),
                "--output",
                str(output),
                "--top-gaps",
                "2",
            ]
            self.assertEqual(auditor.main(arguments), 0)
            first = output.read_bytes()
            self.assertEqual(auditor.main(arguments), 2)
            self.assertEqual(auditor.main([*arguments, "--force"]), 0)
            self.assertEqual(output.read_bytes(), first)

    def test_cli_creates_content_addressed_single_segment_manifest(self) -> None:
        with WorkspaceFiles() as files:
            source = files.path("detection.jsonl")
            manifest = files.path("segment-manifest.json")
            output = files.path("audit.json")
            write_jsonl(
                source,
                [
                    ready(),
                    alert(
                        timestamp=100,
                        sequence=1,
                        decision="known_attack",
                        candidate="FTP-Patator",
                        source="10.0.0.1",
                        destination="10.0.0.2",
                    ),
                ],
            )

            result = auditor.main(
                [
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--create-single-segment-manifest",
                    str(manifest),
                    "--segment-id",
                    "tuesday",
                    "--source-pcap",
                    "Tuesday-WorkingHours.pcap",
                    "--allow-known-attack-candidate",
                    "SSH-Patator",
                    "--allow-known-attack-candidate",
                    "FTP-Patator",
                    "--require-passed",
                ]
            )

            self.assertEqual(result, 0)
            manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
            audit_value = json.loads(output.read_text(encoding="utf-8"))
            input_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(manifest_value["input_sha256"], input_sha256)
            self.assertEqual(
                manifest_value["segments"],
                [
                    {
                        "allowed_known_attack_candidates": [
                            "FTP-Patator",
                            "SSH-Patator",
                        ],
                        "end_line": 2,
                        "id": "tuesday",
                        "source_pcap": "Tuesday-WorkingHours.pcap",
                        "start_line": 1,
                    }
                ],
            )
            self.assertEqual(audit_value["status"], "passed")
            self.assertEqual(audit_value["chronology"]["status"], "passed")
            self.assertTrue(
                audit_value["configuration"]["segment_manifest"][
                    "input_sha256_matches"
                ]
            )

    def test_segmented_replay_scripts_keep_topspeed_and_isolate_outputs(self) -> None:
        ubuntu = (ROOT / "scripts" / "ubuntu_t85_detection.sh").read_text(
            encoding="utf-8"
        )
        kali = (ROOT / "scripts" / "kali_t85_bulk_replay.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("--segment-id", ubuntu)
        self.assertIn(
            'SEGMENT_ROOT="$PROJECT_ROOT/run_log/t8.5/segments/$SEGMENT_ID"',
            ubuntu,
        )
        self.assertIn('tee "$DETECTION_LOG"', ubuntu)
        self.assertNotIn('tee -a "$DETECTION_LOG"', ubuntu)
        self.assertIn("--pcap-id", kali)
        self.assertIn(
            'LOG_ROOT="$PROJECT_ROOT/run_log/t8.5/segments/$PCAP_ID"',
            kali,
        )
        self.assertIn("receiver_arrival_compressed_not_source_pcap", kali)
        self.assertIn("--topspeed", kali)


if __name__ == "__main__":
    unittest.main(verbosity=2)
