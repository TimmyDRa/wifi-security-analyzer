import smtplib
import json
import os
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Path to config file
CONFIG_PATH = "config_email.json"

# Per-signature rate limiting memory
_last_sent = {}

def load_email_config():
    """Load email configuration from JSON file."""
    if not os.path.exists(CONFIG_PATH):
        return {
            "enabled": False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "from_addr": "",
            "to_addrs": []
        }
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
            # Ensure all required fields exist
            defaults = {
                "enabled": False,
                "smtp_host": "smtp.gmail.com", 
                "smtp_port": 587,
                "use_tls": True,
                "username": "",
                "password": "",
                "from_addr": "",
                "to_addrs": []
            }
            for key, default_value in defaults.items():
                if key not in config:
                    config[key] = default_value
            return config
    except Exception as e:
        print(f"Error loading email config: {e}")
        return {
            "enabled": False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "from_addr": "",
            "to_addrs": []
        }

def save_email_config(config):
    """Save email configuration back to JSON file."""
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving email config: {e}")
        return False

def test_email_connection(config=None):
    """Test email connection without sending a message"""
    if config is None:
        config = load_email_config()
    
    # Get credentials from env or config
    email_user = os.getenv("EMAIL_USER", config.get("username", ""))
    email_pass = os.getenv("EMAIL_PASS", config.get("password", ""))
    smtp_host = os.getenv("SMTP_HOST", config.get("smtp_host", "smtp.gmail.com"))
    smtp_port = int(os.getenv("SMTP_PORT", config.get("smtp_port", 587)))
    smtp_tls = os.getenv("SMTP_USE_TLS", str(config.get("use_tls", True))).lower() == "true"
    
    if not email_user or not email_pass:
        return False, "Email credentials not configured"
    
    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(0)  # Set to 1 for debugging
        
        if smtp_tls:
            server.starttls()
        
        server.login(email_user, email_pass)
        server.quit()
        
        return True, "Connection successful"
        
    except smtplib.SMTPAuthenticationError as e:
        return False, f"Authentication failed: {str(e)}"
    except smtplib.SMTPConnectError as e:
        return False, f"Connection failed: {str(e)}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def send_email(subject, body, key="default", min_seconds=60):
    """
    Sends an email alert.
    Uses .env values first, then falls back to config_email.json if it exists.
    Rate-limited by key (default = "default").
    """
    
    # Check rate limiting first
    now = time.time()
    last = _last_sent.get(key, 0)
    if now - last < min_seconds:
        print(f"[!] Email rate limited for key '{key}' (last sent {int(now-last)}s ago)")
        return False

    # Load config
    config = load_email_config()
    
    # Check if emails are enabled
    if not config.get("enabled", False) and not os.getenv("EMAIL_USER"):
        print("[!] Email alerts are disabled in configuration")
        return False

    # Environment vars override config.json
    email_user = os.getenv("EMAIL_USER", config.get("username", ""))
    email_pass = os.getenv("EMAIL_PASS", config.get("password", ""))
    email_from = os.getenv("EMAIL_FROM", config.get("from_addr", email_user))
    email_to = os.getenv("EMAIL_TO", ",".join(config.get("to_addrs", [])))
    smtp_host = os.getenv("SMTP_HOST", config.get("smtp_host", "smtp.gmail.com"))
    smtp_port = int(os.getenv("SMTP_PORT", config.get("smtp_port", 587)))
    smtp_tls = os.getenv("SMTP_USE_TLS", str(config.get("use_tls", True))).lower() == "true"

    # Validate required fields
    if not email_user:
        print("[!] Email username not configured")
        return False
    if not email_pass:
        print("[!] Email password not configured") 
        return False
    if not email_to:
        print("[!] Email recipient(s) not configured")
        return False

    # Clean up email addresses
    to_addresses = [addr.strip() for addr in email_to.split(",") if addr.strip()]
    if not to_addresses:
        print("[!] No valid recipient email addresses")
        return False

    try:
        # Build message
        msg = MIMEMultipart()
        msg["From"] = email_from
        msg["To"] = ", ".join(to_addresses)
        msg["Subject"] = subject
        
        # Add body
        msg.attach(MIMEText(body, "plain"))
        
        # Connect and send
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.set_debuglevel(0)  # Set to 1 for debugging
        
        if smtp_tls:
            server.starttls()
        
        server.login(email_user, email_pass)
        server.sendmail(email_from, to_addresses, msg.as_string())
        server.quit()
        
        # Update rate limiting
        _last_sent[key] = now
        
        print(f"[+] Email alert sent successfully: {subject}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"[!] Email authentication failed: {e}")
        print("[!] For Gmail, make sure you're using an App Password, not your regular password")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"[!] Email recipients refused: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {e}")
        return False
    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        return False

def send_test_email():
    """Send a test email to verify configuration"""
    subject = "WiFi Security Analyzer - Test Email"
    body = f"""This is a test email from WiFi Security Analyzer.

Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
System: Operational

If you received this email, your email alerts are working correctly.
"""
    
    return send_email(subject, body, key="test_email", min_seconds=10)

def get_email_status():
    """Get current email configuration status"""
    config = load_email_config()
    
    # Check environment variables
    has_env_config = bool(os.getenv("EMAIL_USER") and os.getenv("EMAIL_PASS"))
    
    # Test connection
    can_connect, connection_msg = test_email_connection(config)
    
    return {
        "enabled": config.get("enabled", False) or has_env_config,
        "has_config": bool(config.get("username") and config.get("password")),
        "has_env_config": has_env_config,
        "smtp_host": config.get("smtp_host", "Not configured"),
        "smtp_port": config.get("smtp_port", "Not configured"),
        "from_addr": config.get("from_addr", "Not configured"),
        "to_addrs": config.get("to_addrs", []),
        "can_connect": can_connect,
        "connection_message": connection_msg,
        "rate_limited_keys": list(_last_sent.keys())
    }

if __name__ == "__main__":
    print("=== Email Configuration Test ===")
    status = get_email_status()
    
    for key, value in status.items():
        print(f"{key}: {value}")
    
    print("\n=== Connection Test ===")
    can_connect, msg = test_email_connection()
    print(f"Can connect: {can_connect}")
    print(f"Message: {msg}")
    
    if can_connect:
        print("\n=== Sending Test Email ===")
        success = send_test_email()
        print(f"Test email sent: {success}")
    else:
        print("\n[!] Cannot send test email - connection failed")
        print("Common fixes:")
        print("  1. For Gmail: Use App Password instead of regular password")
        print("  2. Check SMTP host and port settings")
        print("  3. Verify username/password are correct")
        print("  4. Check firewall/network restrictions")