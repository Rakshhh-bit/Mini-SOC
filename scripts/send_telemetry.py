
import json
import os
import urllib.request
import urllib.error
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TELEMETRY_FILE = BASE_DIR / "logs" / "system_monitor.json"

SERVER_URL = "http://192.168.64.5:5000/api/telemetry"


def send_telemetry():

    api_token = os.environ.get("SOC_API_TOKEN")

    if not api_token:
        print("[ERROR] SOC_API_TOKEN is not configured.")
        return

    if not TELEMETRY_FILE.exists():
        print("[ERROR] System telemetry file not found.")
        return

    try:
        with open(TELEMETRY_FILE, "r") as file:
            telemetry = json.load(file)

        payload = json.dumps(telemetry).encode("utf-8")

        request = urllib.request.Request(
            SERVER_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_token
            },
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))

            print("\n========== MINI SOC TELEMETRY SENDER ==========")
            print("[SUCCESS] Telemetry sent to Ubuntu SOC server.")
            print("Hostname:", result.get("hostname"))
            print("Server status:", result.get("status"))
            print("HTTP status:", response.status)

    except urllib.error.HTTPError as error:
        print("[ERROR] Server rejected the request.")
        print("HTTP status:", error.code)
        print(error.read().decode("utf-8"))

    except urllib.error.URLError as error:
        print("[ERROR] Could not connect to Ubuntu server.")
        print(error.reason)

    except (OSError, json.JSONDecodeError) as error:
        print("[ERROR] Could not process telemetry:", error)


if __name__ == "__main__":
    send_telemetry()
