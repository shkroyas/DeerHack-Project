import os
import csv
import time
import json
import queue
import logging
import threading
import subprocess
import requests
from scapy.all import sniff, TCP, IP
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

INTERFACE = os.getenv("INTERFACE", "wlp2s0")
API_URL = os.getenv("API_URL", "http://localhost:8000/pipeline/run")
BPF_FILTER = os.getenv("BPF_FILTER", "tcp or udp")

# Cache to store JA3 hashes by 4-tuple (src_ip, dst_ip, src_port, dst_port)
ja3_cache = {}
ja3_lock = threading.Lock()

# Standard CICIDS-2017 feature mapping (to match FlowRecordRequest)
FEATURE_MAPPING = {
    "flow duration": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "flow bytes/s": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow iat mean": "Flow IAT Mean",
    "flow iat std": "Flow IAT Std",
    "fwd iat total": "Fwd IAT Total",
    "fwd iat mean": "Fwd IAT Mean",
    "fwd iat std": "Fwd IAT Std",
    "bwd iat mean": "Bwd IAT Mean",
    "bwd iat std": "Bwd IAT Std",
    "destination port": "Destination Port",
}

def extract_ja3(packet):
    """
    Very lightweight Scapy callback to parse TLS Client Hello and extract a JA3 hash.
    Note: Full JA3 extraction requires detailed TLS parsing. This is a placeholder 
    that caches a pseudo-hash for demonstration, or you can drop in a full JA3 library.
    """
    try:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Check for TLS Client Hello (Dest Port 443, payload starts with 0x16 0x03)
            payload = bytes(packet[TCP].payload)
            if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                # This is a Client Hello. 
                # (A true JA3 would parse the cipher suites and extensions here)
                pseudo_ja3 = hashlib.md5(payload[5:50]).hexdigest()
                
                src = packet[IP].src
                dst = packet[IP].dst
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                
                with ja3_lock:
                    ja3_cache[(src, dst, sport, dport)] = pseudo_ja3
    except Exception as e:
        pass

def run_scapy_sniffer():
    """Runs a background sniffer just for TLS JA3 extraction"""
    logging.info(f"Starting Scapy TLS JA3 sniffer on {INTERFACE}...")
    sniff(iface=INTERFACE, filter="tcp dst port 443", prn=extract_ja3, store=0)

def tail_csv_and_forward(csv_path):
    """Tails the cicflowmeter CSV output, merges with JA3, and forwards to API."""
    logging.info(f"Waiting for {csv_path} to be created by cicflowmeter...")
    while not os.path.exists(csv_path):
        time.sleep(1)
        
    logging.info(f"Found {csv_path}. Tailing flows...")
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        # cicflowmeter writes headers first.
        
        while True:
            # Try to read the next line
            try:
                row = next(reader)
                
                if row:
                    # Parse basic flow info
                    src_ip = row.get("src_ip", "0.0.0.0")
                    dst_ip = row.get("dst_ip", "0.0.0.0")
                    src_port = int(row.get("src_port", 0))
                    dst_port = int(row.get("dst_port", 0))
                    protocol = int(row.get("protocol", 6))
                    
                    # Map cicflowmeter features to BankSentinel features
                    features = {}
                    for cic_key, val in row.items():
                        cic_key_lower = cic_key.strip().lower()
                        if cic_key_lower in FEATURE_MAPPING:
                            bs_key = FEATURE_MAPPING[cic_key_lower]
                            try:
                                features[bs_key] = float(val)
                            except ValueError:
                                features[bs_key] = 0.0
                                
                    # Try to attach JA3 if we caught the ClientHello
                    ja3_hash = None
                    with ja3_lock:
                        if (src_ip, dst_ip, src_port, dst_port) in ja3_cache:
                            ja3_hash = ja3_cache.pop((src_ip, dst_ip, src_port, dst_port))
                            
                    # Construct Request
                    payload = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "features": features,
                        "label": "BENIGN", # Assume benign until proven anomaly
                        "regime": "normal",
                        "ja3_hash": ja3_hash
                    }
                    
                    # Forward to BankSentinel
                    try:
                        resp = requests.post(API_URL, json=payload, timeout=2.0)
                        if resp.status_code == 200:
                            logging.info(f"-> Forwarded flow {src_ip}:{src_port} -> {dst_ip}:{dst_port} (JA3: {bool(ja3_hash)})")
                        else:
                            logging.warning(f"API Error {resp.status_code}: {resp.text}")
                    except Exception as e:
                        logging.error(f"Failed to forward flow: {e}")
            
            except StopIteration:
                # EOF reached, wait for more data
                time.sleep(1)

def main():
    if not os.path.exists("flows.csv"):
        # Create empty file so tail doesn't fail
        open("flows.csv", "w").close()

    # 1. Start JA3 Sniffer
    scapy_thread = threading.Thread(target=run_scapy_sniffer, daemon=True)
    scapy_thread.start()
    
    # 2. Start Tailing Thread
    tail_thread = threading.Thread(target=tail_csv_and_forward, args=("flows.csv",), daemon=True)
    tail_thread.start()
    
    # 3. Start cicflowmeter
    logging.info(f"Starting cicflowmeter on {INTERFACE}...")
    cmd = ["cicflowmeter", "-i", INTERFACE, "-c", "flows.csv"]
    
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        logging.info("Shutting down sensor...")

if __name__ == "__main__":
    main()
