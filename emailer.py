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
    print("[INFO] python-dotenv not installed. Using config file only.")

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
        return False, f"Authentication failed: {str(e)} - For Gmail, use App Password not regular password"
    except smtplib.SMTPConnectError as e:
        return False, f"Connection failed: {str(e)}"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def send_email(subject, body, key="default", min_seconds=None):
    """
    Sends an email alert.
    Uses .env values first, then falls back to config_email.json if it exists.
    Rate-limited by key (default = "default").
    """
    
    # Get rate limit from environment or use default
    if min_seconds is None:
        min_seconds = int(os.getenv("EMAIL_RATE_LIMIT", "60"))
    
    # Check rate limiting first
    now = time.time()
    last = _last_sent.get(key, 0)
    if now - last < min_seconds:
        print(f"[!] Email rate limited for key '{key}' (last sent {int(now-last)}s ago)")
        return False

    # Load config
    config = load_email_config()
    
    # Check if emails are enabled (env vars override config)
    env_enabled = bool(os.getenv("EMAIL_USER") and os.getenv("EMAIL_PASS"))
    config_enabled = config.get("enabled", False)
    
    if not (env_enabled or config_enabled):
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
        msg["Subject"] = f"[WiFi Analyzer] {subject}"
        
        # Enhanced body with context
        enhanced_body = f"""WiFi Security Analyzer Alert

Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
Alert Type: {key}

{body}

---
This alert was generated by WiFi Security Analyzer
Dashboard: http://localhost:5000/alerts
"""
        
        # Add body
        msg.attach(MIMEText(enhanced_body, "plain"))
        
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
        print("[!] Enable 2FA first: myaccount.google.com → Security → 2-Step Verification")
        print("[!] Then create App Password: Security → App passwords → Mail")
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
    subject = "Test Email - System Working"
    body = f"""This is a test email from WiFi Security Analyzer.

Configuration Test Results:
✅ Email system is properly configured
✅ SMTP connection successful
✅ Authentication working
✅ Message delivery successful

System Information:
- Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
- Status: Operational
- Dashboard: http://localhost:5000

If you received this email, your email alerts are working correctly!
"""
    
    return send_email(subject, body, key="test_email", min_seconds=10)

def get_email_status():
    """Get current email configuration status"""
    config = load_email_config()
    
    # Check environment variables
    has_env_config = bool(os.getenv("EMAIL_USER") and os.getenv("EMAIL_PASS"))
    
    # Test connection
    can_connect, connection_msg = test_email_connection(config)
    
    # Get effective configuration (env overrides config)
    effective_user = os.getenv("EMAIL_USER", config.get("username", ""))
    effective_host = os.getenv("SMTP_HOST", config.get("smtp_host", ""))
    
    return {
        "enabled": config.get("enabled", False) or has_env_config,
        "has_config": bool(config.get("username") and config.get("password")),
        "has_env_config": has_env_config,
        "effective_user": effective_user,
        "smtp_host": effective_host,
        "smtp_port": config.get("smtp_port", 587),
        "from_addr": os.getenv("EMAIL_FROM", config.get("from_addr", effective_user)),
        "to_addrs": os.getenv("EMAIL_TO", ",").split(",") if os.getenv("EMAIL_TO") else config.get("to_addrs", []),
        "can_connect": can_connect,
        "connection_message": connection_msg,
        "rate_limited_keys": list(_last_sent.keys()),
        "using_env": has_env_config
    }

def clear_rate_limits():
    """Clear all rate limiting - useful for testing"""
    global _last_sent
    _last_sent = {}
    print("[+] Email rate limits cleared")

if __name__ == "__main__":
    print("=== WiFi Analyzer Email System Test ===")
    status = get_email_status()
    
    print("\n--- Configuration Status ---")
    for key, value in status.items():
        if key == "to_addrs" and isinstance(value, list):
            value = ", ".join(value)
        print(f"{key}: {value}")
    
    print("\n--- Connection Test ---")
    can_connect, msg = test_email_connection()
    print(f"Can connect: {can_connect}")
    print(f"Message: {msg}")
    
    if can_connect:
        print("\n--- Sending Test Email ---")
        success = send_test_email()
        print(f"Test email sent: {success}")
        
        if success:
            print("\n✅ Email system is fully working!")
            print("Check your email for the test message.")
        else:
            print("\n❌ Test email failed - check configuration")
    else:
        print("\n❌ Cannot send test email - connection failed")
        print("\nCommon fixes for Gmail:")
        print("  1. Enable 2-Factor Authentication")
        print("  2. Generate App Password (not regular password)")
        print("  3. Use App Password in EMAIL_PASS environment variable")
        print("  4. Check firewall/network restrictions")
        print("\nSetup guide:")
        print("  1. Go to: myaccount.google.com")
        print("  2. Security → 2-Step Verification → Enable")
        print("  3. Security → App passwords → Generate for Mail")
        print("  4. Copy 16-character password to .env file")