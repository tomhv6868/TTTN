#!/usr/bin/env python3
"""Replay matched family-window PCAPs through Terminal V1, one sensor per case."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LABCTL = ROOT / 'tools' / 'labctl.py'
LAB_CONFIG = ROOT / 'config' / 'lab-hosts.json'
CAMPAIGN_CONFIG = ROOT / 'config' / 't91-live-campaign.json'
PCAP_ROOT = ROOT / 'run_log' / 'full-flow-v1' / 'family-windows'
LIVE_ROOT = ROOT / 'run_log' / 'full-flow-v1' / 'matched-terminal-20260809' / 'live'
REMOTE_ROOT = '/mnt/hgfs/TTTN'
KALI_PCAP_ROOT = '/home/kali/terminal-matched-20260809/pcap'
KALI_INTERFACE = 'eth1'
KALI_SOURCE_MAC = '00:0c:29:01:9b:f9'
UBUNTU_MAC = '00:0c:29:30:b9:d3'
PCAP_TARGET_IP = '192.168.10.50'

CASES = (
    ('benign', 'Benign'),
    ('ftp-patator', 'FTP-Bruteforce'),
    ('ssh-patator', 'SSH-Bruteforce'),
    ('portscan', 'PortScan'),
    ('ddos', 'DoS'),
    ('dos-goldeneye', 'DoS'),
    ('dos-hulk', 'DoS'),
    ('dos-slowhttptest', 'DoS'),
    ('dos-slowloris', 'DoS'),
    ('bot', 'Other'),
    ('infiltration', 'Other'),
    ('web-brute-force', 'Other'),
    ('web-sql-injection', 'Other'),
    ('web-xss', 'Other'),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
        encoding='utf-8',
    )
    temporary.replace(path)


def remote_bash(role: str, script: str, timeout: int) -> tuple[int, dict]:
    encoded = base64.b64encode(script.encode('utf-8')).decode('ascii')
    command = f'echo {encoded} | base64 -d | bash'
    process = subprocess.run(
        [
            sys.executable,
            str(LABCTL),
            '--config',
            str(LAB_CONFIG),
            'exec',
            '--timeout-seconds',
            str(timeout),
            role,
            command,
        ],
        cwd=ROOT,
        text=True,
        encoding='utf-8',
        errors='replace',
        capture_output=True,
        check=False,
    )
    try:
        document = json.loads(process.stdout)
    except json.JSONDecodeError:
        document = {
            'status': 'invalid_labctl_output',
            'stdout': process.stdout,
            'stderr': process.stderr,
        }
    return process.returncode, document


def remote_path(path: Path) -> str:
    relative = path.resolve().relative_to(ROOT.resolve()).as_posix()
    return f'{REMOTE_ROOT}/{relative}'


def build_contract(case: str, expected: str, attempt_id: str, index: int) -> dict:
    config = json.loads(CAMPAIGN_CONFIG.read_text(encoding='utf-8'))
    dpdk = dict(config['dpdk'])
    dpdk['file_prefix'] = f'nids-tm-{index:02d}'
    dpdk['memory_mb'] = 128
    return {
        'schema_version': '2.0.0',
        'task': 'T9.1',
        'kind': 'terminal_live_run_contract',
        'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),
        'case_id': case,
        'scenario_label': f'{case} matched family-window replay',
        'expected_model_family': expected,
        'attempt_id': attempt_id,
        'run_token': f'rt-{attempt_id[4:]}',
        'config': {
            'path': remote_path(CAMPAIGN_CONFIG),
            'sha256': sha256(CAMPAIGN_CONFIG),
        },
        'artifact_root': 'run_log/full-flow-v1/matched-terminal-20260809/live',
        'topology': {
            'network': config['topology']['data_network']['name'],
            'scope_mode': 'target_ip',
            'source_ip': None,
            'target_ip': PCAP_TARGET_IP,
            'ubuntu_interface': config['topology']['ubuntu']['interface'],
            'ubuntu_expected_mac': config['topology']['ubuntu']['expected_mac'],
        },
        'model': dict(config['model']),
        'dpdk': dpdk,
        'bounds': {'ready_timeout_seconds': 30},
        'lifecycle': {
            'mode': 'signal_only',
            'lease_timeout_seconds': 300,
            'shutdown_grace_ms': 30000,
        },
        'output': {'mode': 'alerts_only'},
        'acceptance': {'mode': 'observational'},
        'tool': {'name': 'tcpreplay-edit', 'bounded': True},
    }


def wait_for(path: Path, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return True
        time.sleep(1)
    return False


def run_case(run_id: str, index: int, case: str, expected: str) -> dict:
    attempt_id = f't91-matched-{case}-{run_id}'
    attempt = LIVE_ROOT / run_id / case
    result_path = attempt / 'case-result.json'
    if result_path.is_file():
        result = json.loads(result_path.read_text(encoding='utf-8'))
        if result.get('complete') is True:
            print(f'SKIP {case}: complete', flush=True)
            return result

    attempt.mkdir(parents=True, exist_ok=True)
    contract_path = attempt / 'contract.json'
    if not contract_path.exists():
        write_json(contract_path, build_contract(case, expected, attempt_id, index))
    alerts = attempt / 'alerts.jsonl'
    alerts.touch(exist_ok=True)
    heartbeat = attempt / 'operator.heartbeat'
    heartbeat.write_bytes(f'{int(time.time())}\n'.encode('ascii'))
    control = attempt / 'control'
    control.mkdir(exist_ok=True)
    contract_remote = remote_path(contract_path)

    start_script = (
        f'cd {REMOTE_ROOT}\n'
        f'bash scripts/ubuntu_t91_live_sensor.sh start --contract {contract_remote}\n'
    )
    start_rc, start_doc = remote_bash('ubuntu', start_script, 90)
    write_json(control / 'start.json', {'return_code': start_rc, 'labctl': start_doc})
    if start_rc != 0:
        result = {'case': case, 'expected': expected, 'complete': False, 'stage': 'start'}
        write_json(result_path, result)
        print(f'FAIL {case}: sensor start', flush=True)
        return result

    kali_script = f'''set -Eeuo pipefail
original_mtu=$(cat /sys/class/net/{KALI_INTERFACE}/mtu)
cleanup() {{ ip link set dev {KALI_INTERFACE} mtu "$original_mtu"; }}
trap cleanup EXIT INT TERM
ip link set dev {KALI_INTERFACE} mtu 9000
su - kali -c 'sudo -n /usr/bin/tcpreplay-edit --intf1={KALI_INTERFACE} --enet-smac={KALI_SOURCE_MAC} --enet-dmac={UBUNTU_MAC} --multiplier=1 --stats=5 {KALI_PCAP_ROOT}/{case}.pcap'
'''
    replay_rc, replay_doc = remote_bash('kali', kali_script, 330)
    write_json(control / 'replay.json', {'return_code': replay_rc, 'labctl': replay_doc})
    (attempt / 'kali').mkdir(exist_ok=True)
    (attempt / 'kali' / 'replay.log').write_text(
        str(replay_doc.get('stdout') or ''), encoding='utf-8'
    )

    stop_script = (
        f'cd {REMOTE_ROOT}\n'
        f'bash scripts/ubuntu_t91_live_sensor.sh stop --contract {contract_remote}\n'
    )
    stop_rc, stop_doc = remote_bash('ubuntu', stop_script, 90)
    write_json(control / 'stop.json', {'return_code': stop_rc, 'labctl': stop_doc})

    sensor_receipt = attempt / 'ubuntu' / 'sensor.json'
    if not wait_for(sensor_receipt, 120):
        recover_script = (
            f'cd {REMOTE_ROOT}\n'
            f'bash scripts/ubuntu_t91_live_sensor.sh recover --contract {contract_remote}\n'
        )
        recover_rc, recover_doc = remote_bash('ubuntu', recover_script, 90)
        write_json(
            control / 'recover.json',
            {'return_code': recover_rc, 'labctl': recover_doc},
        )
        wait_for(sensor_receipt, 30)

    summary_path = attempt / 'ubuntu' / 'summary.json'
    summary = (
        json.loads(summary_path.read_text(encoding='utf-8'))
        if summary_path.is_file()
        else None
    )
    result = {
        'case': case,
        'expected': expected,
        'attempt_id': attempt_id,
        'complete': sensor_receipt.is_file(),
        'replay_return_code': replay_rc,
        'stop_return_code': stop_rc,
        'summary': summary,
    }
    write_json(result_path, result)
    print(
        f'DONE {case}: replay={replay_rc} stop={stop_rc} '
        f'sensor={sensor_receipt.is_file()}',
        flush=True,
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--case', action='append', dest='cases')
    args = parser.parse_args()
    selected = set(args.cases or [case for case, _ in CASES])
    unknown = selected.difference(case for case, _ in CASES)
    if unknown:
        parser.error(f'unknown case(s): {sorted(unknown)}')
    for case, _ in CASES:
        if case in selected and not (PCAP_ROOT / f'{case}.pcap').is_file():
            parser.error(f'missing PCAP: {PCAP_ROOT / f"{case}.pcap"}')

    results = []
    for index, (case, expected) in enumerate(CASES, start=1):
        if case in selected:
            results.append(run_case(args.run_id, index, case, expected))
    output = LIVE_ROOT / args.run_id / 'run-summary.json'
    write_json(output, {'run_id': args.run_id, 'cases': results})
    return 0 if all(item.get('complete') for item in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
