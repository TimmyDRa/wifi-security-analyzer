from flask import Flask, render_template, request, redirect, url_for
from scanner import get_wireless_interface, scan_wifi, parse_scan_output
from vuln_scanner import scan_vulnerabilities
from utils import read_alerts, alert, ensure_logs
from sniffer import start_sniffing

app = Flask(__name__)
ensure_logs()

# Start sniffer optionally when app starts (comment out if you prefer manual start)
# iface = get_wireless_interface()
# if iface:
#     start_sniffing(interface=iface)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/wifi")
def wifi():
    iface = request.args.get("iface") or get_wireless_interface()
    raw = scan_wifi(iface)
    networks = parse_scan_output(raw)
    return render_template("wifi.html", networks=networks, iface=iface)

@app.route("/alerts")
def alerts():
    lines = read_alerts()
    # reverse for newest first
    lines = list(reversed(lines))
    return render_template("alerts.html", alerts=lines)

@app.route("/vuln", methods=["GET", "POST"])
def vuln():
    output = None
    if request.method == "POST":
        target = request.form.get("target")
        output = scan_vulnerabilities(target)
        # also write to alert log as an event
        alert(f"Vulnerability scan initiated against {target}")
    return render_template("vuln.html", output=output)

@app.route("/start-sniff")
def start_sniff_route():
    iface = request.args.get("iface") or get_wireless_interface()
    if not iface:
        alert("Sniff endpoint called but no interface detected.")
        return redirect(url_for("index"))
    start_sniffing(interface=iface)
    alert(f"Sniffer started on {iface} via web.")
    return redirect(url_for("alerts"))

if __name__ == "__main__":
    app.run(debug=True)
