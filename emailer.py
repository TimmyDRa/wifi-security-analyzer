import smtplib
import json
import os
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Per-signature rate limiting memory
_last_sent = {}

def send_email(subject, body, key="default", min_seconds=60):
    """
    Sends an email alert.
    Uses .env values first, then falls back to config_email.json if it exists.
    Rate-limited by key (default = "default").
    """

    now = time.time()
    last = _last_sent.get(key, 0)
    if now - last < min_seconds:
        return False  # Skip sending if too soon

    # Load config.json if present
    config = {}
    try:
        with open("config_email.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        pass

    # Environment vars override config.json
    email_user = os.getenv("EMAIL_USER", config.get("user"))
    email_pass = os.getenv("EMAIL_PASS", config.get("pass"))
    email_from = os.getenv("EMAIL_FROM", config.get("from", email_user))
    email_to = os.getenv("EMAIL_TO", ",".join(config.get("to", [])))
    smtp_host = os.getenv("SMTP_HOST", config.get("host", "smtp.gmail.com"))
    smtp_port = int(os.getenv("SMTP_PORT", config.get("port", 587)))
    smtp_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    if not email_user or not email_pass or not email_to:
        print("[!] Email not configured properly. Skipping send.")
        return False

    # Build message
    msg = MIMEMultipart()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        if smtp_tls:
            server.starttls()
        server.login(email_user, email_pass)
        server.sendmail(email_from, email_to.split(","), msg.as_string())
        server.quit()
        _last_sent[key] = now
        print(f"[+] Email alert sent: {subject}")
        return True
    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        return False
