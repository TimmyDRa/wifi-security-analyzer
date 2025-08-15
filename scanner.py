import re
import subprocess
from utils import alert

def get_wireless_interface():
    """
    Attempts to detect a wireless interface name. Returns interface string (e.g., wlp3s0),
    or None if not found.
    """
    try:
        out = subprocess.getoutput("ip -brief link")
        # lines like: wlp3s0    UP ...
        for line in out.splitlines():
            if line.startswith("wl") or line.startswith("wlan") or "wireless" in line.lower():
                return line.split()[0]
        # fallback: check 'iw dev' output
        iw = subprocess.getoutput("iw dev")
        match = re.search(r'Interface\s+(\S+)', iw)
        if match:
            return match.group(1)
    except Exception:
        return None
    return None

def scan_wifi(interface=None, use_sudo=True):
    """
    Scans WiFi networks using iwlist. Returns raw output string or None on failure.
    """
    if interface is None:
        interface = get_wireless_interface()
    if interface is None:
        alert("No wireless interface found for scanning.")
        return None

    cmd = ["iwlist", interface, "scanning"]
    if use_sudo:
        cmd.insert(0, "sudo")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        alert(f"iwlist scanning failed on {interface}: {e.returncode}")
        return None
    except FileNotFoundError:
        alert("iwlist command not found. Install wireless tools (wireless-tools).")
        return None

def parse_scan_output(raw_output):
    """
    Parse iwlist scan output and return a list of dicts: [{'ssid':..., 'mac':..., 'signal':...}, ...]
    If raw_output is None, returns [].
    """
    if not raw_output:
        return []

    networks = []
    cells = raw_output.split("Cell ")
    for cell in cells[1:]:
        ssid_match = re.search(r'ESSID:"(.*?)"', cell)
        mac_match = re.search(r'Address: ([0-9A-Fa-f:]{17})', cell)
        signal_match = re.search(r'Signal level[=:-](-?\d+)', cell)
        ssid = ssid_match.group(1) if ssid_match else ""
        mac = mac_match.group(1) if mac_match else ""
        signal = signal_match.group(1) if signal_match else ""
        networks.append({"ssid": ssid, "mac": mac, "signal": signal})
    return networks

if __name__ == "__main__":
    iface = get_wireless_interface()
    print("Detected interface:", iface)
    raw = scan_wifi(iface)
    parsed = parse_scan_output(raw)
    print(parsed)
