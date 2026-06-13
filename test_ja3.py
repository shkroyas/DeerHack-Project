from scapy.all import sniff, TCP, IP, load_layer
load_layer("tls")
from scapy.layers.tls.all import TLSClientHello

def check_ja3():
    print(hasattr(TLSClientHello, "ja3_hash"))

check_ja3()
