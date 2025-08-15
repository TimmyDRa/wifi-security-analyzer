from scapy.layers.dot11 import Dot11
from scapy.layers.inet import IP
from utils import alert

# Simple rule examples. Expand as needed.
DEAUTH_SUBTYPE = 12  # Deauthentication frame subtype in Dot11

def process_dot11(pkt):
    # Detect deauth frames
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == DEAUTH_SUBTYPE:
            src = pkt.addr2
            dst = pkt.addr1
            alert(f"Deauthentication frame detected: {src} -> {dst}")

def process_ip(pkt):
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        # Example suspicious check: private IP communicating with unusual port (customize)
        if ip_layer.src == "192.168.1.100":  # example; in practice, maintain list/patterns
            alert(f"Suspicious source IP detected: {ip_layer.src}")

def process_packet(pkt):
    # dispatch to handlers
    try:
        process_dot11(pkt)
    except Exception:
        pass
    try:
        process_ip(pkt)
    except Exception:
        pass
