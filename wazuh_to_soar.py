#!/usr/bin/env python3
import time
import json
import requests

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
SOAR_WEBHOOK = "http://127.0.0.1:8080/webhook"
SOAR_SECRET = "db298fe74eb301aac9e4c3ab98dc41ee65190071339f3a62a441fa6b60ff821c"

def follow(file):
    """Generator function that yields new lines as they are written to file"""
    file.seek(0, 2)  # Move to EOF
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)  # Wait for new line
            continue
        yield line

def send_to_soar(alert_line):
    """Send a single alert line to SOAR"""
    try:
        data = json.loads(alert_line)
        headers = {
            "Content-Type": "application/json",
            "X-Wazuh-Secret": SOAR_SECRET
        }
        response = requests.post(SOAR_WEBHOOK, json=data, headers=headers, timeout=5)
        print(f"[SOAR] Sent alert {data.get('id')} -> {response.status_code}")
    except json.JSONDecodeError:
        print("Skipped invalid JSON line")
    except Exception as e:
        print("Failed to send alert:", e)

if __name__ == "__main__":
    with open(ALERTS_FILE, "r") as f:
        for line in follow(f):
            send_to_soar(line)
