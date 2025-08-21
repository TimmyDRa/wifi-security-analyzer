import subprocess
from utils import alert

def scan_vulnerabilities(target_ip, fast=False):
    """
    Run an nmap vulnerability scan using --script vuln.
    Returns output string or error string.
    """
    if not target_ip:
        return "No target IP provided."

    if fast:
        # Much faster scan - only top 1000 ports, faster timing
        cmd = ["nmap", "-T4", "-F", "--script", "vuln", target_ip]
    else:
        # Original slower, comprehensive scan
        cmd = ["nmap", "-sV", "--script", "vuln", target_ip]
    
    try:
        # Add timeout to prevent hanging
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return result.stdout
        else:
            alert(f"Nmap scan completed with warnings for {target_ip}")
            return result.stdout + "\n" + (result.stderr or "")
    except subprocess.TimeoutExpired:
        alert(f"Nmap scan timed out after 5 minutes for {target_ip}")
        return f"Scan timed out after 5 minutes for {target_ip}"
    except FileNotFoundError:
        alert("nmap not found. Install nmap with apt.")
        return "nmap not found on system. Please install with: sudo apt install nmap"
    except Exception as e:
        alert(f"Nmap scan error for {target_ip}: {str(e)}")
        return f"Scan error: {str(e)}"

def quick_port_scan(target_ip):
    """
    Very fast basic port scan for testing - completes in seconds
    """
    if not target_ip:
        return "No target IP provided."
    
    cmd = ["nmap", "-T4", "-F", target_ip]  # Fast scan of top 100 ports
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stdout + "\n" + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return f"Quick scan timed out for {target_ip}"
    except FileNotFoundError:
        alert("nmap not found. Install nmap with apt.")
        return "nmap not found on system. Please install with: sudo apt install nmap"
    except Exception as e:
        return f"Quick scan error: {str(e)}"

if __name__ == "__main__":
    print(scan_vulnerabilities("127.0.0.1", fast=True))