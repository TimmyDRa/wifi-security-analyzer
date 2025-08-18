
import threading
from scapy.all import AsyncSniffer, Dot11
from utils import alert
from intrusion_detection import process_packet

_sniffer = None
_state = {"running": False, "iface": None}

def packet_handler(pkt):
    # Run detection rules
    try:
        process_packet(pkt)
    except Exception as e:
        print("Error processing packet:", e)

def start_sniffing(interface=None, monitor_required=False, packet_count=0):
    """
    Start sniffing on interface using AsyncSniffer so we can stop later.
    Returns the AsyncSniffer instance.
    """
    global _sniffer, _state
    if _state["running"]:
        return _sniffer
    iface = interface
    print(f"[*] Starting sniff on {iface or 'default'} (monitor_required={monitor_required})")
    _sniffer = AsyncSniffer(iface=iface, prn=packet_handler, store=False, count=packet_count)
    _sniffer.start()
    _state.update({"running": True, "iface": iface})
    return _sniffer

def stop_sniffing():
    global _sniffer, _state
    if _sniffer is not None and _state["running"]:
        try:
            _sniffer.stop()
        except Exception as e:
            print("Error stopping sniffer:", e)
        finally:
            _state.update({"running": False})
            _sniffer = None
    return True

def is_sniffing():
    return _state["running"]

def current_iface():
    return _state["iface"]

if __name__ == "__main__":
    # Example usage (requires root)
    start_sniffing()
    print("Sniffer started (background). Ctrl-C to exit main program.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        stop_sniffing()
        print("Stopped.")
