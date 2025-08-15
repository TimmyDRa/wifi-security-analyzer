import argparse
from scanner import get_wireless_interface, scan_wifi, parse_scan_output
from sniffer import start_sniffing
from vuln_scanner import scan_vulnerabilities
from utils import read_alerts

def cli():
    parser = argparse.ArgumentParser(prog="wifi-analyzer")
    parser.add_argument("--scan", action="store_true", help="Scan for Wi-Fi networks")
    parser.add_argument("--sniff", action="store_true", help="Start packet sniffer (background)")
    parser.add_argument("--vuln", metavar="IP", help="Run nmap vuln scan against target IP")
    parser.add_argument("--iface", metavar="IFACE", help="Specify wireless interface")
    parser.add_argument("--alerts", action="store_true", help="Show recent alerts")
    args = parser.parse_args()

    if args.scan:
        iface = args.iface or get_wireless_interface()
        print("Using interface:", iface)
        raw = scan_wifi(iface)
        parsed = parse_scan_output(raw)
        for p in parsed:
            print(p)
    elif args.sniff:
        iface = args.iface or get_wireless_interface()
        print("Starting sniffer on:", iface)
        start_sniffing(interface=iface)
        print("Sniffer started (background).")
        # Keep process alive
        try:
            while True:
                pass
        except KeyboardInterrupt:
            print("Stopping.")
    elif args.vuln:
        out = scan_vulnerabilities(args.vuln)
        print(out)
    elif args.alerts:
        for l in read_alerts():
            print(l.strip())
    else:
        parser.print_help()

if __name__ == "__main__":
    cli()
