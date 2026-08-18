#!/usr/bin/env bash
# Run on Ubuntu: bash /mnt/hgfs/TTTN/scripts/ubuntu_offline_flows.sh
# Extracts full flows from original CICIDS PCAPs using oracle flow_ids, then runs offline F9.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
OFFLINE_DIR="$PROJECT_ROOT/run_log/t8.5/scenarios/rebuild-20260808/offline-flows"
TOOLCHAIN_ENV="$HOME/.local/nids-toolchain/env.sh"
BINARY="$HOME/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay"
BUNDLE="$HOME/.cache/nids-partial-flow/t5.2/bundles/F9"
HGFS_ROOT="/mnt/hgfs/TTTN"
ORACLE_DB="$HGFS_ROOT/run_log/t3.3/label-join.sqlite3"
MANIFEST="$HGFS_ROOT/run_log/t8.5/scenarios/rebuild-20260808/pcap/manifest.json"
CAPTURES=(
  "monday:Monday-WorkingHours"
  "tuesday:Tuesday-WorkingHours"
  "wednesday:Wednesday-workingHours"
  "thursday:Thursday-WorkingHours"
  "friday:Friday-WorkingHours"
)

# Source toolchain
source "$TOOLCHAIN_ENV"

mkdir -p "$OFFLINE_DIR"

echo "=== Extracting flows from manifest ==="

# Extract 13 flows using python on Ubuntu
python3 - "$MANIFEST" "$ORACLE_DB" "$OFFLINE_DIR" "$HGFS_ROOT" << 'PYEOF'
import json, struct, sqlite3, sys, os
from pathlib import Path

manifest_path, oracle_db, output_dir, hgfs_root = sys.argv[1:]

def read_packets(pcap_path, start_ns, end_ns, target_tuple):
    """Read packets from PCAP matching 5-tuple and time window."""
    with open(pcap_path, 'rb') as f:
        data = f.read()
    if len(data) < 24:
        return []
    magic = struct.unpack('<I', data[:4])[0]
    byte_order = '<' if magic == 0xa1b2c3d4 else '>'
    off = 24
    fmt = byte_order + 'IIII'
    packets = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(fmt, data, off)
        if incl_len < 14 or incl_len > 65535 or off + 16 + incl_len > len(data):
            break
        ts_ns = ts_sec * 1_000_000_000 + ts_usec * 1000
        if ts_ns < start_ns or ts_ns > end_ns:
            off += 16 + incl_len
            continue
        pkt = data[off + 16: off + 16 + incl_len]
        if len(pkt) < 20:
            off += 16 + incl_len
            continue
        ver = (pkt[0] >> 4) & 0xF
        if ver != 4:
            off += 16 + incl_len
            continue
        ihl = (pkt[0] & 0xF) * 4
        if ihl < 20 or len(pkt) < ihl + 4:
            off += 16 + incl_len
            continue
        proto = pkt[9]
        sip = struct.unpack('>I', pkt[12:16])[0]
        dip = struct.unpack('>I', pkt[16:20])[0]
        spt = dpt = 0
        if proto in (6, 17):
            spt = struct.unpack('>H', pkt[ihl:ihl+2])[0]
            dpt = struct.unpack('>H', pkt[ihl+2:ihl+4])[0]
        # Direction-insensitive key
        a, b = (sip, spt), (dip, dpt)
        lo, hi = (a, b) if a <= b else (b, a)
        tk = (lo[0], lo[1], hi[0], hi[1], proto)
        if tk == target_tuple:
            packets.append((ts_ns, pkt))
        off += 16 + incl_len
    packets.sort(key=lambda x: x[0])
    return packets

def write_pcap(output_path, packets):
    with open(output_path, 'wb') as f:
        f.write(struct.pack('<I', 0xa1b2c3d4))
        f.write(struct.pack('<HH', 2, 4))
        f.write(struct.pack('<i', 0))
        f.write(struct.pack('<I', 0))
        f.write(struct.pack('<I', 65535))
        f.write(struct.pack('<I', 1))
        for ts_ns, pkt in packets:
            ts_sec = ts_ns // 1_000_000_000
            ts_usec = (ts_ns % 1_000_000_000) // 1000
            f.write(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)))
            f.write(pkt)

CAPTURE_FILES = {
    'monday-working-hours':    f'{hgfs_root}/pcap/Monday-WorkingHours.pcap',
    'tuesday-working-hours':  f'{hgfs_root}/pcap/Tuesday-WorkingHours.pcap',
    'wednesday-working-hours': f'{hgfs_root}/pcap/Wednesday-workingHours.pcap',
    'thursday-working-hours':  f'{hgfs_root}/pcap/Thursday-WorkingHours.pcap',
    'friday-working-hours':    f'{hgfs_root}/pcap/Friday-WorkingHours.pcap',
}

# Load manifest
with open(manifest_path) as f:
    manifest = json.load(f)

# Load flow metadata from oracle
flow_ids = [out['flow_id'] for out in manifest['outputs'] if out.get('flow_id')]
con = sqlite3.connect(f'file:{oracle_db}?mode=ro', uri=True)
ph = ','.join('?' * len(flow_ids))
flow_meta = {}
for row in con.execute(
    f'SELECT flow_id, capture_id, protocol, low_ip, low_port, high_ip, high_port,'
    f' creation_timestamp_ns, last_capture_timestamp_ns, packet_count FROM flow'
    f' WHERE flow_id IN ({ph})', flow_ids
):
    fid, cap, proto, lip, lpt, hip, hpt, cts, lcts, pc = row
    a, b = (lip, lpt), (hip, hpt)
    lo, hi = (a, b) if a <= b else (b, a)
    tk = (lo[0], lo[1], hi[0], hi[1], proto)
    flow_meta[fid] = {
        'capture_id': cap, 'tuple': tk, 'creation_ts_ns': cts,
        'last_capture_ts_ns': lcts, 'packet_count': pc,
        'proto': proto,
    }
con.close()

os.makedirs(output_dir, exist_ok=True)
results = []

for out in manifest['outputs']:
    case_id = out['case_id']
    fid = out.get('flow_id')
    if not fid or not out.get('tuple'):
        print(f'SKIP {case_id}: no flow_id')
        continue
    cap = out['capture_id']
    pcap_path = CAPTURE_FILES.get(cap)
    if not pcap_path or not os.path.exists(pcap_path):
        print(f'SKIP {case_id}: no PCAP for {cap}')
        continue
    fm = flow_meta.get(fid)
    if not fm:
        print(f'SKIP {case_id}: flow_id {fid} not in oracle')
        continue
    print(f'{case_id}: fid={fid} cap={cap} pc={fm["packet_count"]}')
    start = fm['creation_ts_ns'] - 5_000_000_000
    end = fm['last_capture_ts_ns'] + 5_000_000_000
    packets = read_packets(pcap_path, start, end, fm['tuple'])
    if not packets:
        print(f'  WARNING: 0 packets! ts={fm["creation_ts_ns"]}')
        continue
    out_pcap = f'{output_dir}/{case_id}.pcap'
    write_pcap(out_pcap, packets)
    print(f'  -> {packets[-1][0] - packets[0][0] + 1} packets, '
          f'span={(packets[-1][0] - packets[0][0])/1e9:.2f}s')
    results.append({
        'case_id': case_id, 'label': out['label'], 'fid': fid,
        'pc': len(packets), 'oracle_pc': fm['packet_count'],
        'pcap': out_pcap,
    })

# Write summary
with open(f'{output_dir}/manifest.json', 'w') as f:
    json.dump({'kind': 'offline_flows', 'cases': results}, f, indent=2)
print(f'Done: {len(results)} flows extracted')
PYEOF

echo ""
echo "=== Running offline F9 on each flow ==="

# Run nids_demo_replay for each case
manifest_json="$OFFLINE_DIR/manifest.json"
if [ ! -f "$manifest_json" ]; then
    echo "ERROR: manifest.json not found at $manifest_json"
    exit 1
fi

# Extract cases from manifest and run
python3 - "$manifest_json" << 'PYEOF2'
import json, subprocess, sys, os, re

manifest_path = sys.argv[1]
bundle = os.environ.get('BUNDLE', '/home/wang/.cache/nids-partial-flow/t5.2/bundles/F9')
binary = os.environ.get('BINARY', '/home/wang/.cache/nids-partial-flow/build/ubuntu-release/nids_demo_replay')
hgfs_root = '/mnt/hgfs/TTTN'

with open(manifest_path) as f:
    data = json.load(f)

print(f"Binary: {binary}")
print(f"Bundle: {bundle}")

for case in data.get('cases', []):
    case_id = case['case_id']
    pcap_rel = case.get('pcap', '')
    # Convert Windows path to Ubuntu path
    pcap_path = pcap_rel.replace('E:\\\\DATTTN\\\\TTTN', hgfs_root)
    pcap_path = pcap_path.replace('\\\\', '/').replace('E:', hgfs_root.rstrip('/'))
    # Actually, the script already writes Ubuntu paths
    # Just use the path as-is if it exists
    if not os.path.exists(pcap_path):
        # Try hgfs path directly
        pcap_path_alt = f"{hgfs_root}/run_log/t8.5/scenarios/rebuild-20260808/offline-flows/{case_id}.pcap"
        if os.path.exists(pcap_path_alt):
            pcap_path = pcap_path_alt

    if not os.path.exists(pcap_path):
        print(f"SKIP {case_id}: PCAP not found at {pcap_path}")
        continue

    size_kb = os.path.getsize(pcap_path) / 1024
    print(f"\n=== {case_id} ({size_kb:.1f} KB): GT={case['label']} ===")

    out_json = pcap_path.replace('.pcap', '-offline.json')
    cmd = [
        binary,
        '--input', pcap_path,
        '--bundle', bundle,
        '--max-records', str(case['pc'] + 100),
        '--expect-records', str(case['pc']),
        '--expect-f9', '1',
    ]

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60
    )

    print(f"Exit: {result.returncode}")
    if result.stdout:
        # Try to extract useful info from output
        for line in result.stdout.split('\n')[:10]:
            print(f"  {line}")
    if result.stderr and result.returncode != 0:
        print(f"  ERR: {result.stderr[:200]}")

    # Save output
    with open(out_json, 'w') as f:
        json.dump({
            'case_id': case_id,
            'label': case['label'],
            'fid': case['fid'],
            'oracle_pc': case['oracle_pc'],
            'extracted_pc': case['pc'],
            'exit_code': result.returncode,
            'stdout': result.stdout[:2000],
            'stderr': result.stderr[:500],
        }, f, indent=2)

print("\nDone!")
PYEOF2
