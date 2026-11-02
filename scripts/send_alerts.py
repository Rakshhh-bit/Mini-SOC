import json
import os
import socket
import urllib.request
import urllib.error
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"

SECURITY_ALERTS_FILE = LOG_DIR / "security_alerts.json"
NETWORK_ALERTS_FILE = LOG_DIR / "network_alerts.json"
STATE_FILE = LOG_DIR / "sent_alert_state.json"

SERVER_URL = "http://192.168.64.5:5000/api/alerts"


def load_alert_file(file_path):
    if not file_path.exists():
        return []

    try:
        with file_path.open("r", encoding="utf-8") as file:
            alerts = json.load(file)

        if not isinstance(alerts, list):
            print(f"[WARNING] Invalid alert format: {file_path.name}")
            return []

        return alerts

    except (json.JSONDecodeError, OSError) as error:
        print(f"[WARNING] Could not read {file_path.name}: {error}")
        return []


def load_all_alerts():
    security_alerts = load_alert_file(SECURITY_ALERTS_FILE)
    network_alerts = load_alert_file(NETWORK_ALERTS_FILE)

    return security_alerts + network_alerts


def get_alert_key(alert):
    return (
        str(alert.get("alert_id", "")),
        str(alert.get("title", ""))
    )


def load_previous_state():
    if not STATE_FILE.exists():
        return set()

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            saved_state = json.load(file)

        return {
            tuple(item)
            for item in saved_state
            if isinstance(item, list) and len(item) == 2
        }

    except (json.JSONDecodeError, OSError, TypeError):
        print("[WARNING] Previous alert state could not be read.")
        return set()


def save_current_state(active_keys):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    temporary_file = STATE_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(sorted([list(key) for key in active_keys]), file, indent=4)

    temporary_file.replace(STATE_FILE)


def send_new_alerts(alerts):
    api_token = os.environ.get("SOC_API_TOKEN")

    if not api_token:
        print("[ERROR] SOC_API_TOKEN is not set.")
        print("Set your API key in this terminal session and retry.")
        return False

    payload = {
        "hostname": socket.gethostname(),
        "alerts": alerts
    }

    request_data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        SERVER_URL,
        data=request_data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_token
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response_data = response.read().decode("utf-8")
            result = json.loads(response_data) if response_data else {}

            print("[SUCCESS] Alerts sent to Ubuntu SOC server.")
            print(f"HTTP status: {response.status}")
            print(f"Server response: {result}")
            print(f"Alerts submitted: {len(alerts)}")

            return True

    except urllib.error.HTTPError as error:
        print(f"[ERROR] Server rejected the request: HTTP {error.code}")
        print(error.read().decode("utf-8", errors="replace"))
        return False

    except (urllib.error.URLError, TimeoutError, OSError) as error:
        print(f"[ERROR] Could not connect to Ubuntu SOC server: {error}")
        return False


def main():
    print("\n========== MINI SOC CENTRAL ALERT SENDER ==========\n")

    all_alerts = load_all_alerts()

    # Remove duplicate records within the two input files.
    unique_alerts = {}
    for alert in all_alerts:
        key = get_alert_key(alert)
        unique_alerts[key] = alert

    active_alerts = list(unique_alerts.values())
    active_keys = set(unique_alerts.keys())

    previous_keys = load_previous_state()

    new_alerts = [
        alert for alert in active_alerts
        if get_alert_key(alert) not in previous_keys
    ]

    print(f"Active alerts: {len(active_alerts)}")
    print(f"New alerts: {len(new_alerts)}")

    if not new_alerts:
        print("[INFO] No new alerts to send.")
        save_current_state(active_keys)
        return

    if send_new_alerts(new_alerts):
        save_current_state(active_keys)
        print("[SUCCESS] Alert deduplication state updated.")
    else:
        print("[WARNING] Alert state unchanged. Sending can be retried.")

    print("\n===================================================\n")


if __name__ == "__main__":
    main()