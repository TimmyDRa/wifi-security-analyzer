
import os
from datetime import datetime
from emailer import send_email
from collections import defaultdict

LOG_DIR = "logs"
ALERT_FILE = os.path.join(LOG_DIR, "alerts.log")
COUNTS = defaultdict(int)

def ensure_logs():
    os.makedirs(LOG_DIR, exist_ok=True)
    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w") as f:
            f.write(f"{datetime.now()} - Log initialized\n")

def alert(message, email_subject: str = "Suspicious activity detected", key: str = 'default'):
    """
    Append alert to local log, print to stdout, and (optionally) email it
    using config_email.json or EMAIL_* env vars.
    """
    ensure_logs()
    timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
    line = f"{timestamp} - {message}\n"
    with open(ALERT_FILE, "a") as f:
        f.write(line)
    print("[ALERT]", line.strip())

    # bump stat counter
    try:
        COUNTS[key] += 1
    except Exception:
        pass

    # Try email; ignore errors.
    try:
        send_email(email_subject, line.strip(), key=key)
    except Exception:
        pass

def read_alerts(last_n=100):
    ensure_logs()
    try:
        with open(ALERT_FILE, "r") as f:
            lines = f.readlines()
            return lines[-last_n:]
    except FileNotFoundError:
        return []


# Global IDS statistics counter
stats = {}

def update_stats(key):
    stats[key] = stats.get(key, 0) + 1


def get_stats():
    # return a plain dict copy for JSON
    return dict(COUNTS)
