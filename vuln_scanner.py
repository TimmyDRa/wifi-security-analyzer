import subprocess
from utils import alert

def scan_vulnerabilities(target_ip, fast=False):
    """
    Run an nmap vulnerability scan using --script vuln.
    Returns output string or error string.
    """
    if not target_ip:
        return "No target IP provided."

    cmd = ["nmap", "-sV", "--script", "vuln", target_ip]
    if fast:
        cmd = ["nmap", "--script", "vuln", "-T4", target_ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        alert(f"Nmap scan failed on {target_ip}: {e.returncode}")
        return e.stdout + "\n" + e.stderr
    except FileNotFoundError:
        alert("nmap not found. Install nmap with apt.")
        return "nmap not found on system."

if __name__ == "__main__":
    print(scan_vulnerabilities("127.0.0.1", fast=True))
