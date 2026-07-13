"""
packet_parser.py — Per-packet feature extraction for Layer 1 inference.

Extracts 5 features in LAYER1_FEATURES order from a raw Scapy packet.
Also returns a metadata dict consumed by the flow aggregator.
"""

import ipaddress

import numpy as np

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
except ImportError as exc:
    raise ImportError("scapy is required: pip install scapy") from exc

# Private/loopback ranges — used to infer packet direction (pkts_sent heuristic)
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def parse_packet(pkt) -> tuple[np.ndarray, dict] | None:
    """
    Extract Layer 1 features + flow metadata from a Scapy packet.

    Feature vector shape (5,) float32, LAYER1_FEATURES order:
        [dst_port, nat_src_port, total_bytes, pkt_count, pkts_sent]

    nat_src_port is the source port at runtime (proxy for NAT source port
    which is only available in firewall-logged traffic, not live sniffing).

    Returns None if packet has no IP layer.
    """
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip: str = ip.src
    dst_ip: str = ip.dst
    total_bytes: int = len(pkt)
    # pkts_sent=1 when source is a private address (outbound from LAN)
    pkts_sent: int = 1 if _is_private(src_ip) else 0
    ts: float = float(pkt.time)

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        proto = 6
        flags = int(tcp.flags)
        win = int(tcp.window)
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        proto = 17
        flags = 0
        win = 0
    else:
        # Non-TCP/UDP (ICMP, IGMP, GRE, etc.) — L1 was trained on TCP/UDP
        # firewall logs only. ICMP and others produce dst_port=0 which the DT
        # classifies as ATTACK at conf=1.0 regardless of actual content.
        return None

    features = np.array(
        [dst_port, src_port, total_bytes, 1, pkts_sent],
        dtype=np.float32,
    )
    meta = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "flags": flags,
        "win": win,
        "pkt_len": total_bytes,
        "ts": ts,
    }
    return features, meta
