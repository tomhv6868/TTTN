#!/usr/bin/env python3
"""Validate and aggregate the T0.4 passive-visibility receipts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "1.0.0"
TASK = "T0.4"
RESOURCE_TASK = "T0.3"
RESOURCE_PURPOSE = "T0.4_passive_resource"
EXPECTED_PACKETS = 200
MINIMUM_PACKETS = 190
REQUIRED_PREFLIGHT_CHECKS = {
    "management.default_route",
    "management.ping",
    "data.no_default_route",
    "data.driver",
    "data.pci",
    "iommu.available",
    "iommu.group_policy",
    "hugepages.supported",
    "toolchain.testpmd",
    "toolchain.devbind",
}
REQUIRED_ROLLBACK_CHECKS = {
    "iommu_bridges.restored",
    "driver.restored",
    "interface.restored",
    "dpdk_prefix.cleaned",
    "hugepages.restored",
    "management.reachable",
}
HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_timestamp(value: Any) -> dt.datetime | None:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            return None
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def normalize_mac(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("-", ":").lower()


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and HASH_PATTERN.fullmatch(value) is not None


def as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def interval(document: Mapping[str, Any]) -> tuple[dt.datetime | None, dt.datetime | None]:
    return parse_timestamp(document.get("started_at_utc")), parse_timestamp(document.get("ended_at_utc"))


def interval_overlap(
    first: tuple[dt.datetime | None, dt.datetime | None],
    second: tuple[dt.datetime | None, dt.datetime | None],
) -> float:
    first_start, first_end = first
    second_start, second_end = second
    if not all((first_start, first_end, second_start, second_end)):
        return 0.0
    return max(0.0, (min(first_end, second_end) - max(first_start, second_start)).total_seconds())


def validate_receipts(
    config: Any,
    preflight: Any,
    sender: Any,
    receiver: Any,
    sensor: Any,
    rollback: Any,
    artifact_hashes: Mapping[str, str],
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def check(name: str, condition: bool, expected: Any, observed: Any, gate: str = "integrity") -> None:
        checks.append(
            {
                "name": name,
                "gate": gate,
                "status": "passed" if condition else "failed",
                "expected": expected,
                "observed": observed,
            }
        )

    raw_documents = {
        "config": config,
        "preflight": preflight,
        "sender": sender,
        "receiver": receiver,
        "sensor": sensor,
        "rollback": rollback,
    }
    for name, document in raw_documents.items():
        check(f"{name}.object", isinstance(document, Mapping), True, isinstance(document, Mapping))

    config = as_mapping(config)
    preflight = as_mapping(preflight)
    sender = as_mapping(sender)
    receiver = as_mapping(receiver)
    sensor = as_mapping(sensor)
    rollback = as_mapping(rollback)

    check("config.schema", config.get("schema_version") == SCHEMA_VERSION, SCHEMA_VERSION, config.get("schema_version"))
    check("config.task", config.get("task") == TASK, TASK, config.get("task"))
    traffic_config = as_mapping(config.get("traffic"))
    acceptance_config = as_mapping(config.get("acceptance"))
    check("config.packet_count", traffic_config.get("packet_count") == EXPECTED_PACKETS, EXPECTED_PACKETS, traffic_config.get("packet_count"))
    check("config.minimum_count", acceptance_config.get("minimum_packet_count") == MINIMUM_PACKETS, MINIMUM_PACKETS, acceptance_config.get("minimum_packet_count"))
    check("config.rollback_required", acceptance_config.get("require_rollback") is True, True, acceptance_config.get("require_rollback"))
    check("config.sensor_tx_zero", acceptance_config.get("require_sensor_tx_zero") is True, True, acceptance_config.get("require_sensor_tx_zero"))
    check("config.error_counters_zero", acceptance_config.get("require_error_counters_zero") is True, True, acceptance_config.get("require_error_counters_zero"))

    header_contracts = {
        "preflight": (preflight, RESOURCE_TASK, "preflight"),
        "sender": (sender, TASK, "kali_sender"),
        "receiver": (receiver, TASK, "windows_receiver"),
        "sensor": (sensor, TASK, "sensor_probe"),
        "rollback": (rollback, RESOURCE_TASK, "rollback"),
    }
    for name, (document, task, kind) in header_contracts.items():
        check(f"{name}.schema", document.get("schema_version") == SCHEMA_VERSION, SCHEMA_VERSION, document.get("schema_version"))
        check(f"{name}.task", document.get("task") == task, task, document.get("task"))
        check(f"{name}.kind", document.get("kind") == kind, kind, document.get("kind"))

    expected_hash_names = {"config", "preflight", "sender", "receiver", "sensor", "rollback"}
    for name in sorted(expected_hash_names):
        observed_hash = artifact_hashes.get(name)
        check(f"hashes.{name}", is_sha256(observed_hash), "lowercase SHA-256", observed_hash)
    config_hash = artifact_hashes.get("config")
    check("preflight.status", preflight.get("status") == "passed", "passed", preflight.get("status"))
    check("preflight.purpose", preflight.get("purpose") == RESOURCE_PURPOSE, RESOURCE_PURPOSE, preflight.get("purpose"))
    passive_config = as_mapping(preflight.get("passive_config"))
    check("preflight.passive_config_hash", passive_config.get("sha256") == config_hash, config_hash, passive_config.get("sha256"))
    check("preflight.resource_config_hash", is_sha256(as_mapping(preflight.get("config")).get("sha256")), "lowercase SHA-256", as_mapping(preflight.get("config")).get("sha256"))
    data_interface = config.get("ubuntu_sensor", {}).get("data_interface") if isinstance(config.get("ubuntu_sensor"), Mapping) else None
    check("preflight.data_interface", preflight.get("data_interface") == data_interface, data_interface, preflight.get("data_interface"))
    passed_preflight = {
        item.get("name")
        for item in (preflight.get("checks") if isinstance(preflight.get("checks"), list) else [])
        if isinstance(item, Mapping) and item.get("status") == "passed"
    }
    check("preflight.safety_gates", REQUIRED_PREFLIGHT_CHECKS <= passed_preflight, sorted(REQUIRED_PREFLIGHT_CHECKS), sorted(REQUIRED_PREFLIGHT_CHECKS & passed_preflight))
    discovered_interface = as_mapping(as_mapping(as_mapping(preflight.get("discovery")).get("interfaces")).get(str(data_interface)))
    sensor_config = as_mapping(config.get("ubuntu_sensor"))
    check("preflight.data_driver", discovered_interface.get("driver") == sensor_config.get("expected_driver"), sensor_config.get("expected_driver"), discovered_interface.get("driver"))
    check("preflight.data_mac", normalize_mac(discovered_interface.get("mac")) == normalize_mac(sensor_config.get("expected_mac")), normalize_mac(sensor_config.get("expected_mac")), normalize_mac(discovered_interface.get("mac")))
    check("preflight.data_no_default", discovered_interface.get("has_default_route") is False, False, discovered_interface.get("has_default_route"))

    for name, document in {"sender": sender, "receiver": receiver, "sensor": sensor}.items():
        reference = as_mapping(document.get("config"))
        check(f"{name}.config_hash", reference.get("sha256") == config_hash, config_hash, reference.get("sha256"))

    kali_config = as_mapping(config.get("kali"))
    victim_config = as_mapping(config.get("windows_victim"))
    sender_interface = as_mapping(sender.get("interface"))
    sender_source = as_mapping(sender.get("source"))
    sender_destination = as_mapping(sender.get("destination"))
    sender_traffic = as_mapping(sender.get("traffic"))
    check("sender.status", sender.get("status") == "passed", "passed", sender.get("status"))
    check("sender.sent", sender.get("sent_packets") == EXPECTED_PACKETS, EXPECTED_PACKETS, sender.get("sent_packets"))
    check("sender.errors", sender.get("send_errors") == 0, 0, sender.get("send_errors"))
    check("sender.interface", sender_interface.get("name") == kali_config.get("data_interface"), kali_config.get("data_interface"), sender_interface.get("name"))
    check("sender.driver", sender_interface.get("driver") == kali_config.get("expected_driver"), kali_config.get("expected_driver"), sender_interface.get("driver"))
    check("sender.no_default_route", sender_interface.get("has_default_route") is False, False, sender_interface.get("has_default_route"))
    check("sender.source_ip", sender_source.get("ipv4") == kali_config.get("data_ipv4"), kali_config.get("data_ipv4"), sender_source.get("ipv4"))
    check("sender.source_port", sender_source.get("udp_port") == kali_config.get("udp_source_port"), kali_config.get("udp_source_port"), sender_source.get("udp_port"))
    check("sender.destination_ip", sender_destination.get("ipv4") == victim_config.get("data_ipv4"), victim_config.get("data_ipv4"), sender_destination.get("ipv4"))
    check("sender.destination_mac", normalize_mac(sender_destination.get("mac")) == normalize_mac(victim_config.get("expected_mac")), normalize_mac(victim_config.get("expected_mac")), normalize_mac(sender_destination.get("mac")))
    check("sender.destination_port", sender_destination.get("udp_port") == victim_config.get("udp_port"), victim_config.get("udp_port"), sender_destination.get("udp_port"))
    check("sender.traffic_count", sender_traffic.get("requested_packets") == EXPECTED_PACKETS, EXPECTED_PACKETS, sender_traffic.get("requested_packets"))
    sequence_range = as_mapping(sender.get("sequence_range"))
    check("sender.sequence_range", sequence_range.get("first") == 0 and sequence_range.get("last") == EXPECTED_PACKETS - 1, {"first": 0, "last": EXPECTED_PACKETS - 1}, dict(sequence_range))

    receiver_listen = as_mapping(receiver.get("listen"))
    receiver_sender = as_mapping(receiver.get("expected_sender"))
    receiver_firewall = as_mapping(receiver.get("firewall"))
    unique_sequences = receiver.get("unique_sequences")
    matching_datagrams = receiver.get("matching_datagrams")
    receiver_counts_valid = is_int(unique_sequences) and is_int(matching_datagrams) and 0 <= unique_sequences <= matching_datagrams
    check("receiver.counts", receiver_counts_valid, "0 <= unique_sequences <= matching_datagrams", {"unique_sequences": unique_sequences, "matching_datagrams": matching_datagrams})
    victim_delivery = receiver_counts_valid and unique_sequences >= MINIMUM_PACKETS
    check("receiver.delivery", victim_delivery, f">={MINIMUM_PACKETS} unique sequences", unique_sequences, "delivery")
    check("receiver.listen_ip", receiver_listen.get("ip") == victim_config.get("data_ipv4"), victim_config.get("data_ipv4"), receiver_listen.get("ip"))
    check("receiver.listen_port", receiver_listen.get("port") == victim_config.get("udp_port"), victim_config.get("udp_port"), receiver_listen.get("port"))
    check("receiver.sender_ip", receiver_sender.get("ip") == kali_config.get("data_ipv4"), kali_config.get("data_ipv4"), receiver_sender.get("ip"))
    check("receiver.sender_port", receiver_sender.get("port") == kali_config.get("udp_source_port"), kali_config.get("udp_source_port"), receiver_sender.get("port"))
    check("receiver.firewall_name", receiver_firewall.get("name") == victim_config.get("firewall_rule_name"), victim_config.get("firewall_rule_name"), receiver_firewall.get("name"))
    check("receiver.firewall_removed", receiver_firewall.get("removed") is True, True, receiver_firewall.get("removed"))
    check("receiver.error", receiver.get("error") is None, None, receiver.get("error"))
    expected_receiver_status = "passed" if victim_delivery and receiver_firewall.get("removed") is True and receiver.get("error") is None else "failed"
    check("receiver.status", receiver.get("status") == expected_receiver_status, expected_receiver_status, receiver.get("status"))

    victim_mac = normalize_mac(victim_config.get("expected_mac"))
    sensor_mac = normalize_mac(sensor_config.get("expected_mac"))
    check("topology.distinct_victim_sensor_mac", bool(victim_mac and sensor_mac and victim_mac != sensor_mac), "different non-empty MAC addresses", {"victim": victim_mac, "sensor": sensor_mac})
    resource_state = as_mapping(sensor.get("resource_state"))
    sensor_log = as_mapping(sensor.get("log"))
    check("sensor.resource_state_hash", is_sha256(resource_state.get("sha256")), "lowercase SHA-256", resource_state.get("sha256"))
    check("sensor.log_hash", is_sha256(sensor_log.get("sha256")), "lowercase SHA-256", sensor_log.get("sha256"))
    check("sensor.link", sensor.get("link_up") is True, True, sensor.get("link_up"))
    check("sensor.promiscuous", sensor.get("promiscuous_enabled") is True, True, sensor.get("promiscuous_enabled"))
    expected_frames = as_mapping(sensor.get("expected_frames"))
    check("sensor.source_mac", normalize_mac(expected_frames.get("source_mac")) == normalize_mac(sender_interface.get("mac")), normalize_mac(sender_interface.get("mac")), normalize_mac(expected_frames.get("source_mac")))
    check("sensor.destination_mac", normalize_mac(expected_frames.get("destination_mac")) == victim_mac, victim_mac, normalize_mac(expected_frames.get("destination_mac")))
    check("sensor.ethertype", expected_frames.get("ethertype") == "0x0800", "0x0800", expected_frames.get("ethertype"))
    check("sensor.expected_count", expected_frames.get("packet_count") == EXPECTED_PACKETS and expected_frames.get("minimum_count") == MINIMUM_PACKETS, {"packet_count": EXPECTED_PACKETS, "minimum_count": MINIMUM_PACKETS}, {"packet_count": expected_frames.get("packet_count"), "minimum_count": expected_frames.get("minimum_count")})
    matching_frames = sensor.get("matching_frames")
    matching_frames_valid = is_int(matching_frames) and matching_frames >= 0
    check("sensor.matching_frames_type", matching_frames_valid, "non-negative integer", matching_frames)
    sensor_delivery = matching_frames_valid and matching_frames >= MINIMUM_PACKETS
    check("sensor.delivery", sensor_delivery, f">={MINIMUM_PACKETS} matching frames", matching_frames, "delivery")
    counters = as_mapping(sensor.get("counters"))
    rx_packets = counters.get("rx_packets")
    fwd_rx_packets = counters.get("fwd_rx_packets")
    rx_adequate = (
        is_int(rx_packets)
        and is_int(fwd_rx_packets)
        and matching_frames_valid
        and rx_packets >= matching_frames
        and fwd_rx_packets >= matching_frames
    )
    check("sensor.rx_counters", rx_adequate, "rx_packets and fwd_rx_packets >= matching_frames", {"rx_packets": rx_packets, "fwd_rx_packets": fwd_rx_packets, "matching_frames": matching_frames})
    tx_observed = {name: counters.get(name) for name in ("port_tx_packets", "fwd_tx_packets")}
    check("sensor.tx_zero", all(is_int(value) and value == 0 for value in tx_observed.values()), {"port_tx_packets": 0, "fwd_tx_packets": 0}, tx_observed)
    error_observed = {name: counters.get(name) for name in ("rx_missed", "rx_errors", "rx_nombuf", "tx_errors")}
    check("sensor.errors_zero", all(is_int(value) and value == 0 for value in error_observed.values()), {name: 0 for name in error_observed}, error_observed)
    check("sensor.management", as_mapping(sensor.get("management_ping_after")).get("passed") is True, True, as_mapping(sensor.get("management_ping_after")).get("passed"))
    prefix_cleanup = as_mapping(sensor.get("prefix_cleanup"))
    dpdk_config = as_mapping(config.get("dpdk"))
    check("sensor.prefix", prefix_cleanup.get("file_prefix") == dpdk_config.get("file_prefix"), dpdk_config.get("file_prefix"), prefix_cleanup.get("file_prefix"))
    removed_files = prefix_cleanup.get("hugepage_files_removed")
    check("sensor.hugepage_cleanup", is_int(removed_files) and removed_files >= 0, "non-negative integer", removed_files)
    check("sensor.runtime_cleanup", prefix_cleanup.get("runtime_path_removed") is True, True, prefix_cleanup.get("runtime_path_removed"))
    command = sensor.get("command")
    command_valid = isinstance(command, list) and all(isinstance(item, str) for item in command)
    separator = command.index("--") if command_valid and "--" in command else -1
    command_options_valid = (
        command_valid
        and separator > 0
        and f"--file-prefix={dpdk_config.get('file_prefix')}" in command[:separator]
        and f"--huge-unlink={dpdk_config.get('huge_unlink')}" in command[:separator]
        and f"--total-num-mbufs={dpdk_config.get('total_num_mbufs')}" in command[separator + 1 :]
        and f"--forward-mode={dpdk_config.get('forward_mode')}" in command[separator + 1 :]
    )
    check("sensor.command", command_options_valid, "T0.4 EAL and rxonly testpmd options", command)
    check("sensor.interactive_commands", isinstance(sensor.get("interactive_commands"), list), "list", type(sensor.get("interactive_commands")).__name__)
    expected_sensor_status = "passed" if sensor_delivery else "failed"
    check("sensor.status", sensor.get("status") == expected_sensor_status, expected_sensor_status, sensor.get("status"))

    check("rollback.status", rollback.get("status") == "passed", "passed", rollback.get("status"))
    passed_rollback = {
        item.get("name")
        for item in (rollback.get("checks") if isinstance(rollback.get("checks"), list) else [])
        if isinstance(item, Mapping) and item.get("status") == "passed"
    }
    check("rollback.actions", REQUIRED_ROLLBACK_CHECKS <= passed_rollback, sorted(REQUIRED_ROLLBACK_CHECKS), sorted(REQUIRED_ROLLBACK_CHECKS & passed_rollback))
    restored = as_mapping(rollback.get("restored"))
    check("rollback.driver", restored.get("driver") == sensor_config.get("expected_driver"), sensor_config.get("expected_driver"), restored.get("driver"))
    check("rollback.interface", restored.get("interface") == sensor_config.get("data_interface"), sensor_config.get("data_interface"), restored.get("interface"))
    original_hugepages = as_mapping(as_mapping(preflight.get("discovery")).get("hugepages")).get("current_count")
    check("rollback.hugepages", restored.get("hugepage_count") == original_hugepages, original_hugepages, restored.get("hugepage_count"))

    sender_interval = interval(sender)
    receiver_interval = interval(receiver)
    sensor_interval = interval(sensor)
    sender_start, sender_end = sender_interval
    sender_duration = (sender_end - sender_start).total_seconds() if sender_start and sender_end and sender_end >= sender_start else 0.0
    check("sender.timestamps", sender_duration > 0, "ordered UTC interval", {"start": sender.get("started_at_utc"), "end": sender.get("ended_at_utc")})
    receiver_start, receiver_end = receiver_interval
    check("receiver.timestamps", bool(receiver_start and receiver_end and receiver_end >= receiver_start), "ordered UTC interval", {"start": receiver.get("started_at_utc"), "end": receiver.get("ended_at_utc")})
    sensor_start, sensor_end = sensor_interval
    check("sensor.timestamps", bool(sensor_start and sensor_end and sensor_end >= sensor_start), "ordered UTC interval", {"start": sensor.get("started_at_utc"), "end": sensor.get("ended_at_utc")})
    receiver_overlap = interval_overlap(sender_interval, receiver_interval)
    sensor_overlap = interval_overlap(sender_interval, sensor_interval)
    required_overlap = max(1.0, sender_duration - 2.0)
    check("sender_receiver.overlap", receiver_overlap >= required_overlap, f">={required_overlap:.3f}s", round(receiver_overlap, 3))
    check("sender_sensor.overlap", sensor_overlap >= required_overlap, f">={required_overlap:.3f}s", round(sensor_overlap, 3))

    integrity_passed = all(item["status"] == "passed" for item in checks if item["gate"] == "integrity")
    if not integrity_passed:
        outcome = "failed"
    elif not victim_delivery:
        outcome = "inconclusive"
    elif not sensor_delivery:
        outcome = "passive_not_feasible"
    else:
        outcome = "passed"
    summary = {
        "sent_packets": sender.get("sent_packets"),
        "victim_unique_sequences": unique_sequences,
        "sensor_matching_frames": matching_frames,
        "sensor_rx_packets": rx_packets,
        "receiver_overlap_seconds": round(receiver_overlap, 3),
        "sensor_overlap_seconds": round(sensor_overlap, 3),
    }
    return checks, outcome, summary


def write_new_json(path: Path, document: Mapping[str, Any]) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def command_verify(args: argparse.Namespace) -> int:
    paths = {
        "config": args.config,
        "preflight": args.preflight,
        "sender": args.sender,
        "receiver": args.receiver,
        "sensor": args.sensor,
        "rollback": args.rollback,
    }
    documents = {name: load_json(path) for name, path in paths.items()}
    artifact_hashes = {name: sha256_file(path) for name, path in paths.items()}
    checks, outcome, summary = validate_receipts(**documents, artifact_hashes=artifact_hashes)
    receipt = {
        "schema_version": SCHEMA_VERSION,
        "task": TASK,
        "kind": "acceptance",
        "status": outcome,
        "generated_at_utc": utc_now(),
        "artifacts": {
            name: {"file": str(path), "sha256": artifact_hashes[name]}
            for name, path in paths.items()
        },
        "summary": summary,
        "checks": checks,
    }
    write_new_json(args.output, receipt)
    print(f"wrote {args.output} ({outcome})")
    for item in checks:
        if item["status"] == "failed":
            print(f"failed: {item['name']} (observed={item['observed']!r})", file=sys.stderr)
    return 0 if outcome == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--sender", required=True, type=Path)
    parser.add_argument("--receiver", required=True, type=Path)
    parser.add_argument("--sensor", required=True, type=Path)
    parser.add_argument("--rollback", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return command_verify(build_parser().parse_args(argv))
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
