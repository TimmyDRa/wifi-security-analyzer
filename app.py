from flask import Flask, render_template, request, redirect, url_for
from scanner import get_wireless_interface, scan_wifi, parse_scan_output
from vuln_scanner import scan_vulnerabilities, quick_port_scan
from utils import read_alerts, alert, ensure_logs
from sniffer import start_sniffing

app = Flask(__name__)
ensure_logs()

# Start sniffer optionally when app starts (comment out if you prefer manual start)
# iface = get_wireless_interface()
# if iface:
#     start_sniffing(interface=iface)

from flask import Response, stream_with_context
import time, os

def tail_f(path):
    # Simple non-blocking tail that yields new lines
    with open(path, "r") as f:
        # seek to end
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1.0)
                continue
            yield line

@app.route("/alerts/stream")
def alerts_stream():
    from utils import ALERT_FILE, ensure_logs
    ensure_logs()
    def event_stream():
        for line in tail_f(ALERT_FILE):
            yield f"data: {line.strip()}\n\n"
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

from flask import jsonify
from utils import get_stats

@app.route("/stats")
def stats():
    return jsonify(get_stats())

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
        fast_mode = request.form.get("fast") == "on"
        
        # Show immediate feedback
        alert(f"Vulnerability scan initiated against {target}")
        
        try:
            output = scan_vulnerabilities(target, fast=fast_mode)
            alert(f"Vulnerability scan completed for {target}")
        except Exception as e:
            output = f"Scan failed: {str(e)}"
            alert(f"Vulnerability scan failed for {target}: {str(e)}")
    
    return render_template("vuln.html", output=output)

@app.route("/quick-scan", methods=["POST"])
def quick_scan():
    target = request.form.get("target")
    if target:
        alert(f"Quick port scan initiated for {target}")
        try:
            output = quick_port_scan(target)
            alert(f"Quick port scan completed for {target}")
        except Exception as e:
            output = f"Quick scan failed: {str(e)}"
            alert(f"Quick scan failed for {target}: {str(e)}")
        
        return render_template("vuln.html", output=output)
    return redirect(url_for("vuln"))

@app.route("/start-sniff")
def start_sniff_route():
    iface = request.args.get("iface") or get_wireless_interface()
    if not iface:
        alert("Sniff endpoint called but no interface detected.")
        return redirect(url_for("index"))
    start_sniffing(interface=iface)
    alert(f"Sniffer started on {iface} via web.")
    return redirect(url_for("alerts"))

@app.route("/settings", methods=["GET", "POST"])
def settings():
    """
    Configure email alert settings (stored in config_email.json).
    """
    import json, os
    from emailer import load_email_config
    cfg_path = os.path.join(os.path.dirname(__file__), "config_email.json")
    if request.method == "POST":
        # Basic parse; trust form inputs
        cfg = {
            "enabled": request.form.get("enabled") == "on",
            "smtp_host": request.form.get("smtp_host") or "",
            "smtp_port": int(request.form.get("smtp_port") or 587),
            "use_tls": request.form.get("use_tls") == "on",
            "username": request.form.get("username") or "",
            "password": request.form.get("password") or "",
            "from_addr": request.form.get("from_addr") or "",
            "to_addrs": [x.strip() for x in (request.form.get("to_addrs") or "").split(",") if x.strip()],
        }
        with open(cfg_path, "w") as f:
            json.dump(cfg, f, indent=2)
        alert("Email configuration updated via web UI.")
        return redirect(url_for("settings"))
    cfg = load_email_config()
    return render_template("settings.html", cfg=cfg)

@app.route("/test-email")
def test_email():
    from emailer import send_email
    ok = send_email("WiFi Analyzer Test", "This is a test alert email.")
    alert("Test email sent." if ok else "Test email failed.")
    return redirect(url_for("alerts"))

from sniffer import start_sniffing as _start, stop_sniffing as _stop, is_sniffing as _is_running, current_iface as _iface
from scanner import get_wireless_interface

@app.route("/sniffer", methods=["GET"])
def sniffer_page():
    return render_template("sniffer.html")

@app.route("/sniffer/status")
def sniffer_status():
    return jsonify({"running": _is_running(), "iface": _iface()})

@app.route("/sniffer/start", methods=["POST"])
def sniffer_start():
    iface = request.form.get("iface") or get_wireless_interface()
    if not iface:
        alert("Sniffer start requested but no interface found.", key="sniffer_control")
        return redirect(url_for("sniffer_page"))
    _start(interface=iface)
    alert(f"Sniffer started on {iface} via web.", key="sniffer_control")
    return redirect(url_for("sniffer_page"))

@app.route("/sniffer/stop", methods=["POST"])
def sniffer_stop():
    _stop()
    alert("Sniffer stopped via web.", key="sniffer_control")
    return redirect(url_for("sniffer_page"))

if __name__ == "__main__":
    app.run(debug=True)
    # Add these routes to your app.py file

@app.route("/test-sniffing", methods=["POST"])
def test_sniffing_capability():
    """Test if packet sniffing can work on this system"""
    try:
        from sniffer import test_sniffing_capability
        result = test_sniffing_capability()
        
        if result["can_sniff"]:
            alert("Sniffing capability test: PASSED - System ready for packet sniffing")
        else:
            issues = "; ".join(result["issues"])
            alert(f"Sniffing capability test: FAILED - Issues: {issues}")
        
        return jsonify({
            "success": result["can_sniff"],
            "message": "Sniffing test passed" if result["can_sniff"] else f"Issues found: {'; '.join(result['issues'])}",
            "details": result
        })
    except Exception as e:
        alert(f"Sniffing test error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Test failed: {str(e)}"
        })

@app.route("/email-test", methods=["POST"])
def test_email_system():
    """Test email system functionality"""
    try:
        from emailer import send_test_email, get_email_status
        
        # Get current status
        status = get_email_status()
        
        if not status["enabled"]:
            alert("Email test failed: Email alerts are disabled in configuration")
            return jsonify({
                "success": False,
                "message": "Email alerts are disabled"
            })
        
        if not status["can_connect"]:
            alert(f"Email test failed: Cannot connect to SMTP server - {status['connection_message']}")
            return jsonify({
                "success": False, 
                "message": f"SMTP connection failed: {status['connection_message']}"
            })
        
        # Try to send test email
        success = send_test_email()
        
        if success:
            alert("Email test successful: Test email sent")
            return jsonify({
                "success": True,
                "message": "Test email sent successfully"
            })
        else:
            alert("Email test failed: Could not send test email")
            return jsonify({
                "success": False,
                "message": "Failed to send test email - check configuration"
            })
            
    except Exception as e:
        alert(f"Email test error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Email test failed: {str(e)}"
        })

@app.route("/system-status")
def system_status():
    """Get comprehensive system status"""
    try:
        from sniffer import test_sniffing_capability, get_stats as get_sniffer_stats
        from emailer import get_email_status
        from utils import get_stats as get_alert_stats
        import os
        
        # Sniffer status
        sniffer_test = test_sniffing_capability()
        sniffer_stats = get_sniffer_stats()
        
        # Email status
        email_status = get_email_status()
        
        # Alert stats
        alert_stats = get_alert_stats()
        
        # System info
        is_root = os.geteuid() == 0
        
        return jsonify({
            "sniffer": {
                "can_sniff": sniffer_test["can_sniff"],
                "issues": sniffer_test["issues"],
                "detected_interface": sniffer_test["detected_interface"],
                "current_stats": sniffer_stats
            },
            "email": {
                "enabled": email_status["enabled"],
                "can_connect": email_status["can_connect"],
                "connection_message": email_status["connection_message"],
                "smtp_host": email_status["smtp_host"]
            },
            "alerts": alert_stats,
            "system": {
                "is_root": is_root,
                "python_version": os.sys.version,
                "working_directory": os.getcwd()
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": str(e),
            "system": {
                "is_root": os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            }
        })

# Update the existing stats route to include sniffer stats
@app.route("/stats")
def stats():
    try:
        from utils import get_stats as get_alert_stats
        from sniffer import get_stats as get_sniffer_stats
        
        alert_stats = get_alert_stats()
        sniffer_stats = get_sniffer_stats()
        
        return jsonify({
            **alert_stats,
            **sniffer_stats,
            "packets_captured": sniffer_stats.get("packets_captured", 0)
        })
    except Exception as e:
        return jsonify({"error": str(e)})