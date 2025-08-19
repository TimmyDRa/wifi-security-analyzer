from collections import defaultdict, deque
from time import time
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
try:
    from scapy.layers.eap import EAPOL
except Exception:
    EAPOL = None
from scapy.layers.inet import IP, TCP, UDP, ICMP
from utils import alert

# --- Existing constants ---
DEAUTH_SUBTYPE = 12  # Deauthentication frame subtype in Dot11

# --- Detection state ---
_window_seconds = 10
_deauth_times = deque(maxlen=2048)                   # timestamps of deauth frames
_probe_counts = defaultdict(lambda: deque())         # STA -> timestamps for probe requests
_eapol_times = deque(maxlen=2048)                    # timestamps of EAPOL frames
_ssid_profiles = defaultdict(lambda: set())          # SSID -> set of tuples (bssid, privacy_flag)
_last_weak_alert = set()                             # (ssid, bssid) we've warned about

# --- NEW: Abnormal traffic tracking ---
_ip_counts = defaultdict(lambda: deque())            # srcIP -> timestamps of packets
_portscan_tracker = defaultdict(set)                 # srcIP -> set of dstPorts seen in window

def _trim_deque(dq, window=_window_seconds):
    now = time()
    while dq and now - dq[0] > window:
        dq.popleft()

def process_dot11(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot = pkt[Dot11]

    # --- 1) Deauth detection + flood ---
    if dot.type == 0 and dot.subtype == DEAUTH_SUBTYPE:
        src = dot.addr2
        dst = dot.addr1
        alert(f"Deauthentication frame detected: {src} -> {dst}", key="wifi_deauth")
        # flood
        _deauth_times.append(time())
        _trim_deque(_deauth_times)
        if len(_deauth_times) >= 20:  # >=20 in ~10s
            alert(f"Deauthentication flood detected: {len(_deauth_times)} events in {_window_seconds}s", key="wifi_deauth_flood")

    # --- 2) Probe request storm ---
    if dot.type == 0 and dot.subtype == 4:  # Probe Request
        sta = dot.addr2 or "unknown"
        ts = _probe_counts[sta]
        ts.append(time())
        _trim_deque(ts)
        if len(ts) > 50:  # >50 in ~10s
            alert(f"Probe request storm: STA {sta} sent {len(ts)} probes in {_window_seconds}s", key="wifi_probe_storm")

    # --- 3) Rogue AP & Weak Security from beacons ---
    if pkt.haslayer(Dot11Beacon):
        bssid = dot.addr2 or "unknown"
        ssid = None
        privacy = False
        rsn_present = False
        wpa_present = False

        el = pkt.getlayer(Dot11Elt)
        while isinstance(el, Dot11Elt):
            if el.ID == 0 and not ssid:
                try:
                    ssid = el.info.decode(errors='ignore')
                except Exception:
                    ssid = None
            elif el.ID == 48:  # RSN
                rsn_present = True
            elif el.ID == 221 and el.info[:4] == b'\x00P\xf2\x01':  # WPA OUI
                wpa_present = True
            el = el.payload.getlayer(Dot11Elt)

        if ssid is None:
            ssid = "(hidden)"

        try:
            privacy = bool(pkt[Dot11Beacon].cap and pkt[Dot11Beacon].cap.privacy)
        except Exception:
            privacy = False

        profile = ("secure" if (rsn_present or wpa_present) else ("wep_or_unknown" if privacy else "open"))
        before = len(_ssid_profiles[ssid])
        _ssid_profiles[ssid].add((bssid, profile))

        key = (ssid, bssid)
        if profile == "open" and key not in _last_weak_alert:
            alert(f"Weak security AP detected: SSID='{ssid}' BSSID={bssid} (OPEN network)", key="wifi_weak_ap")
            _last_weak_alert.add(key)
        elif profile == "wep_or_unknown" and key not in _last_weak_alert:
            alert(f"Potentially weak AP detected: SSID='{ssid}' BSSID={bssid} (WEP/unknown, no RSN/WPA IE)", key="wifi_weak_ap")
            _last_weak_alert.add(key)

        if len(_ssid_profiles[ssid]) >= 2:
            kinds = {p for _, p in _ssid_profiles[ssid]}
            if len(kinds) >= 2:
                bssids = ", ".join(sorted({b for b, _ in _ssid_profiles[ssid]}))
                alert(f"Possible rogue AP for SSID '{ssid}': mixed security across BSSIDs [{bssids}]", key="wifi_rogue_ap")

def process_ip(pkt):
    if not pkt.haslayer(IP):
        return

    ip_layer = pkt[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    now = time()

    # Track traffic per IP
    dq = _ip_counts[src]
    dq.append(now)
    _trim_deque(dq)

    # --- 1) Burst traffic detection ---
    if len(dq) > 200:  # >200 packets in 10s
        alert(f"High traffic burst from {src}: {len(dq)} packets in {_window_seconds}s", key="ip_burst")

    # --- 2) Port scan detection (TCP/UDP only) ---
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        _portscan_tracker[src].add(dport)
    elif pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        _portscan_tracker[src].add(dport)

    if len(_portscan_tracker[src]) > 50:  # >50 unique ports in 10s
        ports = list(_portscan_tracker[src])[:10]
        alert(f"Possible port scan from {src}: {len(_portscan_tracker[src])} unique dst ports (e.g. {ports}...)", key="ip_portscan")
        _portscan_tracker[src].clear()

    # --- 3) ICMP flood detection ---
    if pkt.haslayer(ICMP):
        if len(dq) > 100:  # >100 ICMP in 10s
            alert(f"ICMP flood suspected from {src}: {len(dq)} ICMP packets in {_window_seconds}s", key="icmp_flood")

def process_eapol(pkt):
    if EAPOL is None:
        return
    if pkt.haslayer(EAPOL):
        _eapol_times.append(time())
        _trim_deque(_eapol_times)
        if len(_eapol_times) > 80:  # >80 EAPOL frames in ~10s
            alert(f"EAPOL anomaly: {len(_eapol_times)} EAPOL frames in {_window_seconds}s", key="wifi_eapol_anomaly")

def process_packet(pkt):
    try:
        process_dot11(pkt)
    except Exception:
        pass
    try:
        process_eapol(pkt)
    except Exception:
        pass
    try:
        process_ip(pkt)
    except Exception:
        pass
