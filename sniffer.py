import threading
import time
from scapy.all import AsyncSniffer, sniff
from utils import alert
from intrusion_detection import process_packet

_sniffer = None
_sniffer_thread = None
_state = {"running": False, "iface": None, "packets_captured": 0}
_stop_sniffing = False

def packet_handler(pkt):
    """Handle captured packets"""
    global _state
    try:
        # Update packet counter
        _state["packets_captured"] += 1
        
        # Run detection rules
        process_packet(pkt)
        
        # Log every 100 packets
        if _state["packets_captured"] % 100 == 0:
            alert(f"Packet sniffer: {_state['packets_captured']} packets captured on {_state['iface']}")
            
    except Exception as e:
        print(f"Error processing packet: {e}")

def detect_wireless_interface():
    """Try to detect a wireless interface that can be used for monitoring"""
    import subprocess
    try:
        # Try to find wireless interfaces
        result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.DEVNULL)
        lines = result.stdout.split('\n')
        
        for line in lines:
            if 'IEEE 802.11' in line or 'ESSID' in line:
                # Extract interface name
                iface = line.split()[0]
                if iface and not iface.startswith('lo'):
                    return iface
                    
        # Fallback: try common wireless interface names
        common_names = ['wlan0', 'wlp3s0', 'wlp2s0', 'wlo1']
        for name in common_names:
            try:
                result = subprocess.run(['iwconfig', name], capture_output=True, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    return name
            except:
                continue
                
    except Exception as e:
        print(f"Error detecting wireless interface: {e}")
    
    return None

def start_sniffing(interface=None, monitor_required=False, packet_count=0):
    """
    Start sniffing on interface using AsyncSniffer or regular sniff
    """
    global _sniffer, _sniffer_thread, _state, _stop_sniffing
    
    if _state["running"]:
        alert("Sniffer already running")
        return _sniffer
    
    # Determine interface
    if not interface:
        interface = detect_wireless_interface()
        if not interface:
            alert("No wireless interface found for sniffing")
            return None
    
    alert(f"Starting packet sniffer on interface {interface}")
    
    try:
        _stop_sniffing = False
        _state.update({
            "running": True, 
            "iface": interface, 
            "packets_captured": 0
        })
        
        # Try AsyncSniffer first (preferred)
        try:
            _sniffer = AsyncSniffer(
                iface=interface, 
                prn=packet_handler, 
                store=False, 
                count=packet_count if packet_count > 0 else 0
            )
            _sniffer.start()
            alert(f"Packet sniffer started successfully on {interface} (AsyncSniffer mode)")
            return _sniffer
            
        except Exception as e:
            # Fallback to threaded sniffing
            alert(f"AsyncSniffer failed ({str(e)}), trying threaded mode")
            
            def sniff_worker():
                try:
                    sniff(
                        iface=interface,
                        prn=packet_handler,
                        store=False,
                        count=packet_count if packet_count > 0 else 0,
                        stop_filter=lambda x: _stop_sniffing
                    )
                except Exception as e:
                    alert(f"Sniffing thread error: {str(e)}")
                    _state["running"] = False
            
            _sniffer_thread = threading.Thread(target=sniff_worker, daemon=True)
            _sniffer_thread.start()
            alert(f"Packet sniffer started in threaded mode on {interface}")
            return True
            
    except Exception as e:
        alert(f"Failed to start packet sniffer: {str(e)}")
        _state["running"] = False
        return None

def stop_sniffing():
    """Stop the packet sniffer"""
    global _sniffer, _sniffer_thread, _state, _stop_sniffing
    
    if not _state["running"]:
        alert("Sniffer is not running")
        return True
    
    try:
        _stop_sniffing = True
        
        # Stop AsyncSniffer if it exists
        if _sniffer is not None:
            try:
                _sniffer.stop()
            except Exception as e:
                print(f"Error stopping AsyncSniffer: {e}")
        
        # Wait for thread to finish
        if _sniffer_thread and _sniffer_thread.is_alive():
            _sniffer_thread.join(timeout=5)
        
        packets = _state["packets_captured"]
        iface = _state["iface"]
        
        _state.update({"running": False, "iface": None})
        _sniffer = None
        _sniffer_thread = None
        
        alert(f"Packet sniffer stopped. Captured {packets} packets on {iface}")
        return True
        
    except Exception as e:
        alert(f"Error stopping sniffer: {str(e)}")
        _state["running"] = False
        return False

def is_sniffing():
    """Check if sniffer is running"""
    return _state["running"]

def current_iface():
    """Get current sniffing interface"""
    return _state["iface"]

def get_stats():
    """Get sniffer statistics"""
    return dict(_state)

def test_sniffing_capability():
    """Test if packet sniffing can work on this system"""
    import os
    import subprocess
    
    issues = []
    
    # Check if running as root
    if os.geteuid() != 0:
        issues.append("Not running as root - packet sniffing requires root privileges")
    
    # Check if scapy is available
    try:
        from scapy.all import sniff
    except ImportError:
        issues.append("Scapy not installed or not working")
    
    # Check for wireless interfaces
    iface = detect_wireless_interface()
    if not iface:
        issues.append("No wireless interface detected")
    else:
        # Test if interface is up
        try:
            result = subprocess.run(['ip', 'link', 'show', iface], 
                                  capture_output=True, text=True)
            if 'UP' not in result.stdout:
                issues.append(f"Interface {iface} is not UP")
        except:
            issues.append(f"Cannot check status of interface {iface}")
    
    return {
        "can_sniff": len(issues) == 0,
        "issues": issues,
        "detected_interface": iface,
        "is_root": os.geteuid() == 0
    }

if __name__ == "__main__":
    # Test sniffing capability
    test_result = test_sniffing_capability()
    print("Sniffing capability test:")
    print(f"Can sniff: {test_result['can_sniff']}")
    print(f"Detected interface: {test_result['detected_interface']}")
    print(f"Running as root: {test_result['is_root']}")
    
    if test_result['issues']:
        print("Issues found:")
        for issue in test_result['issues']:
            print(f"  - {issue}")
    
    if test_result['can_sniff']:
        print(f"\nStarting test sniff on {test_result['detected_interface']}...")
        start_sniffing(test_result['detected_interface'])
        print("Sniffer started (background). Press Ctrl-C to stop.")
        try:
            while True:
                time.sleep(5)
                stats = get_stats()
                print(f"Packets captured: {stats['packets_captured']}")
        except KeyboardInterrupt:
            print("\nStopping sniffer...")
            stop_sniffing()
            print("Done.")