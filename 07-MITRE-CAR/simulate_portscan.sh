#!/usr/bin/env bash
# Week 7 - generate port-scan-like network flows to test CAR-2021-01-001.
# Scan ONLY your own lab machine. Default target is the VM itself (127.0.0.1).
# Usage: bash simulate_portscan.sh [target_ip]
set -u
TARGET="${1:-127.0.0.1}"
PORTS="20-40"   # 21 distinct destination ports, well above the CAR threshold of 5

echo "Scanning $TARGET ports $PORTS (TCP connect scan)"
if command -v nmap >/dev/null 2>&1; then
  nmap -sT -Pn -n -p "$PORTS" "$TARGET"
else
  echo "nmap not found - falling back to bash /dev/tcp connects"
  for p in $(seq 20 40); do
    (timeout 1 bash -c "exec 3<>/dev/tcp/$TARGET/$p" 2>/dev/null) || true
  done
fi
date -u +"Finished at %Y-%m-%d %H:%M:%S UTC"
