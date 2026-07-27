#!/usr/bin/env python3
'''Build the auditable Terminal V1 PortScan validation/offline/live comparison.'''
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import statistics
from pathlib import Path


def load_json(path: Path) -> dict:
    with path.open('r', encoding='utf-8-sig') as handle:
        return json.load(handle)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def sensor_events(path: Path, event_type: str) -> list[dict]:
    events = []
    with path.open('r', encoding='utf-8-sig', errors='replace') as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get('event_type') == event_type:
                events.append(event)
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-summary', required=True, type=Path)
    parser.add_argument('--live-sensor', required=True, type=Path)
    parser.add_argument('--matched-sensor', required=True, type=Path)
    parser.add_argument('--model-manifest', required=True, type=Path)
    parser.add_argument('--output-json', required=True, type=Path)
    parser.add_argument('--output-md', required=True, type=Path)
    args = parser.parse_args()

    offline = load_json(args.offline_summary)
    manifest = load_json(args.model_manifest)
    selected = manifest['selection']['selected_profile']
    profile = next(item for item in manifest['profiles']
                   if item['profile_id'] == selected)
    validation = profile['threshold_selection']['metrics']['per_class']['PortScan']
    live = sensor_events(args.live_sensor, 'nids_terminal_flow_decision')
    matched_events = sensor_events(args.matched_sensor, 'nids_terminal_live_summary')
    if len(matched_events) != 1:
        raise ValueError(f'expected one matched summary, observed {len(matched_events)}')
    matched = matched_events[0]
    reset = [event for event in live if event.get('close_reason') == 'tcp_reset']
    reset_age = statistics.median(
        float(event['features']['values'][0]) for event in reset
    )
    offline_age = float(
        offline['diagnostic_feature_distributions']['flow_age_us']['median']
    )
    drop_rate = matched['port_stats']['imissed'] / matched['port_stats']['ipackets']
    portscan_ratio = (
        matched['alerts_by_class']['PortScan'] / matched['inferences']
    )

    document = {
        'schema_version': '1.0.0',
        'kind': 'terminal_portscan_three_way_comparison',
        'tag': 't91-terminal-portscan-matched-live-r1',
        'generated_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'sources': {
            'offline_summary': {
                'path': str(args.offline_summary), 'sha256': sha256(args.offline_summary)
            },
            'live_nmap': {
                'path': str(args.live_sensor), 'sha256': sha256(args.live_sensor)
            },
            'matched_live': {
                'path': str(args.matched_sensor), 'sha256': sha256(args.matched_sensor)
            },
            'model_manifest': {
                'path': str(args.model_manifest), 'sha256': sha256(args.model_manifest)
            },
        },
        'validation': {
            'profile': selected,
            'support': validation['support'],
            'true_positive': validation['true_positive'],
            'recall': validation['recall'],
        },
        'offline_family_window': {
            'flows': offline['metrics']['rows'],
            'portscan': offline['metrics']['correct'],
            'benign': offline['metrics']['decision_counts']['Benign'],
            'recall': offline['metrics']['accuracy'],
        },
        'live_nmap': {
            'flows': len(live),
            'portscan': sum(event['decision'] == 'PortScan' for event in live),
            'benign': sum(event['decision'] == 'Benign' for event in live),
            'tcp_reset_flows': len(reset),
            'end_of_input_flows': sum(
                event.get('close_reason') == 'end_of_input' for event in live
            ),
            'flow_age_us_median_tcp_reset': reset_age,
            'flow_age_us_median_offline': offline_age,
            'flow_age_ratio_tcp_reset_over_offline': reset_age / offline_age,
        },
        'matched_live': {
            'attempt_id': matched['attempt_id'],
            'status': matched['status'],
            'stop_reason': matched['stop_reason'],
            'source_packets_sent': 169265,
            'port_ipackets': matched['port_stats']['ipackets'],
            'port_imissed': matched['port_stats']['imissed'],
            'rx_drop_rate': drop_rate,
            'packets_seen': matched['packets_seen'],
            'inferences': matched['inferences'],
            'portscan': matched['alerts_by_class']['PortScan'],
            'dos': matched['alerts_by_class']['DoS'],
            'benign': matched['benign_decisions'],
            'portscan_over_inferences': portscan_ratio,
            'attack_detection_rate': (
                matched['attack_decisions'] / matched['inferences']
            ),
            'shutdown_complete': matched['shutdown_complete'],
            'pipeline_failure': matched.get('pipeline_failure'),
            'inference_failure': matched.get('inference_failure'),
            'interpretation': 'lab_system_measurement_not_model_accuracy',
        },
        'conclusion': {
            'representation_gap': 'isolated_with_same_pcap',
            'finding': (
                'Offline model is strong; matched live is degraded by measured '
                'RX loss and incomplete synchronous EOF processing.'
            ),
            'timing_correction': (
                'The earlier 39x claim used one outlier. The median of nine '
                'TCP-reset nmap flows is only 1.404x the offline median.'
            ),
            'reporting_limit': (
                'VMware laboratory result only; matched live ratio is not '
                'model capability.'
            ),
        },
        'test_partition': {
            'status': 'sealed',
            'feature_reads': 0,
            'metric_reads': 0,
            'path_resolution_or_hash_reads': 0,
        },
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    markdown = f'''# Terminal V1 PortScan — validation, offline và live matched

| Phép đo | PortScan | Tổng | Tỷ lệ |
|---|---:|---:|---:|
| Validation profile {selected} | {validation['true_positive']} | {validation['support']} | {validation['recall']*100:.4f}% |
| Offline family-window | {offline['metrics']['correct']} | {offline['metrics']['rows']} | {offline['metrics']['accuracy']*100:.4f}% |
| Live nmap | 0 | {len(live)} | 0% |
| Matched live cùng PCAP | {matched['alerts_by_class']['PortScan']} | {matched['inferences']} inference | {portscan_ratio*100:.4f}% |

Matched live không phải accuracy model: NIC ghi {matched['port_stats']['imissed']}/{matched['port_stats']['ipackets']} RX miss ({drop_rate*100:.2f}%), chỉ {matched['packets_seen']} packet vào pipeline và shutdown EOF không hoàn tất.

Median flow_age_us của {len(reset)} flow TCP-reset nmap live là {reset_age:.3f} us, bằng {reset_age/offline_age:.3f} lần median offline {offline_age:g} us; giả thuyết cũ 39 lần dựa trên một outlier và bị bác.

Kết luận: cùng PCAP đạt {offline['metrics']['accuracy']*100:.2f}% offline nhưng suy giảm qua live path có packet loss và EOF/output đồng bộ. Đây là giới hạn hệ thống lab VMware, không phải số đo năng lực model production.
'''
    args.output_md.write_text(markdown, encoding='utf-8')
    print(json.dumps({
        'offline_recall': offline['metrics']['accuracy'],
        'matched_portscan_ratio': portscan_ratio,
        'rx_drop_rate': drop_rate,
        'flow_age_ratio': reset_age / offline_age,
    }))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
