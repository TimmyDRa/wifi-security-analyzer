import threading
from scapy.all import sniff, Dot11
from utils import alert
from intrusion_detection import process_packet

def packet_handler(pkt):
    # Run detection rules
    try:
        process_packet(pkt)
    except Exception as e:
        print("Error processing packet:", e)

def start_sniffing(interface=None, monitor_required=False, packet_count=0):
    """
    Start sniffing on interface. If interface is None, sniff on all interfaces (may require root).
    If monitor_required=True, check that interface is in monitor mode before sniffing.
    packet_count: number of packets to capture (0 means infinite)
    """
    iface = interface
    if iface is None:
        # let scapy decide, but best to provide an interface
        iface = None

    print(f"[*] Starting sniff on {iface or 'default'} (monitor_required={monitor_required})")
    # sniff in a separate thread so flask UI or CLI is not blocked
    t = threading.Thread(target=lambda: sniff(iface=iface, prn=packet_handler, store=False, count=packet_count))
    t.daemon = True
    t.start()
    return t

if __name__ == "__main__":
    # Example usage (requires root)
    start_sniffing()
    print("Sniffer started (background). Ctrl-C to exit main program.")
    while True:
        pass
