
import json
import os
import hashlib
import socket
import urllib.request
import urllib.error

from pathlib import Path
from datetime import datetime, timezone


# ---------------- CONFIGURATION ----------------

BASE_DIR = Path(__file__).resolve().parent.parent

ALERT_FILE = BASE_DIR / "logs" / "security_alerts.json"
REPORT_DIR = BASE_DIR / "incident-reports"
HISTORY_FILE = REPORT_DIR / "incident_history.json"

SOC_SERVER_URL = "http://192.168.64.5:5000/api/incidents"


# ---------------- JSON FUNCTIONS ----------------

def load_json(file_path, default):
    """Load JSON data safely."""

    if not file_path.exists():
        return default

    try:
        with open(file_path, "r") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        print(f"Warning: Could not read {file_path}")
        return default


def save_json(file_path, data):
    """Save formatted JSON data."""

    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)


# ---------------- INCIDENT FINGERPRINT ----------------

def generate_fingerprint(alert):
    """Create a stable identifier for duplicate detection."""

    identity = {
        "rule_id": alert.get("alert_id"),
        "title": alert.get("title"),
        "description": alert.get("description")
    }

    content = json.dumps(identity, sort_keys=True)

    return hashlib.sha256(
        content.encode()
    ).hexdigest()


# ---------------- SEVERITY ----------------

def get_severity(severity):
    """Normalize severity values."""

    allowed = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    }

    severity = str(severity).upper()

    return severity if severity in allowed else "LOW"


# ---------------- INCIDENT ID ----------------

def generate_incident_id(history):
    """Generate the next incident ID."""

    highest_number = 0

    for incident in history:

        incident_id = incident.get("incident_id", "")

        if incident_id.startswith("INC-"):

            try:
                number = int(incident_id.split("-")[1])

                highest_number = max(
                    highest_number,
                    number
                )

            except (ValueError, IndexError):
                continue

    return f"INC-{highest_number + 1:04d}"


# ---------------- CREATE INCIDENT ----------------

def create_incident(alert, history):
    """Convert a security alert into an incident."""

    incident_id = generate_incident_id(history)

    return {
        "incident_id": incident_id,
        "rule_id": alert.get("alert_id", "UNKNOWN"),
        "title": alert.get("title", "Untitled Alert"),
        "severity": get_severity(
            alert.get("severity")
        ),
        "description": alert.get("description", ""),
        "detected_at": alert.get("timestamp"),
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "status": "OPEN",
        "assigned_to": "SOC Analyst",
        "fingerprint": generate_fingerprint(alert)
    }


# ---------------- SEND INCIDENTS TO UBUNTU ----------------

def send_incidents_to_server(incidents):
    """Send incident history to the central Ubuntu SOC server."""

    print("\n========== CENTRAL INCIDENT SYNC ==========")

    api_token = os.environ.get("SOC_API_TOKEN", "")

    if not api_token:
        print("[ERROR] SOC_API_TOKEN is not set.")
        print("[INFO] Local incident reports are preserved.")
        return False

    payload = {
        "hostname": socket.gethostname(),
        "incidents": incidents
    }

    try:
        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            SOC_SERVER_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_token
            },
            method="POST"
        )

        with urllib.request.urlopen(
            request,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

            print("[SUCCESS] Incidents sent to Ubuntu SOC server.")
            print(f"Hostname: {payload['hostname']}")
            print(f"HTTP Status: {response.status}")
            print(f"New incidents stored: {result.get('count', 0)}")

            return True

    except urllib.error.HTTPError as error:

        print(f"[ERROR] HTTP Error: {error.code}")
        print(error.read().decode("utf-8", errors="replace"))

    except urllib.error.URLError as error:

        print("[ERROR] Could not connect to Ubuntu SOC server.")
        print(error.reason)

    except (TimeoutError, OSError, json.JSONDecodeError) as error:

        print(f"[ERROR] Incident synchronization failed: {error}")

    return False


# ---------------- INCIDENT MANAGER ----------------

def process_alerts():
    """Generate incidents, save reports and sync centrally."""

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    alerts = load_json(ALERT_FILE, [])
    history = load_json(HISTORY_FILE, [])

    if not isinstance(alerts, list) or not isinstance(history, list):

        print("[ERROR] Invalid alert or incident history format.")
        return

    existing_fingerprints = {
        incident.get("fingerprint")
        for incident in history
    }

    new_incidents = []

    for alert in alerts:

        if not isinstance(alert, dict):
            continue

        fingerprint = generate_fingerprint(alert)

        if fingerprint in existing_fingerprints:
            continue

        incident = create_incident(
            alert,
            history
        )

        report_path = REPORT_DIR / (
            f"{incident['incident_id']}.json"
        )

        save_json(
            report_path,
            incident
        )

        history.append(incident)

        existing_fingerprints.add(fingerprint)

        new_incidents.append(incident)

    # Save local incident history before network transmission.
    save_json(
        HISTORY_FILE,
        history
    )

    print("\n========== MINI SOC INCIDENT MANAGER ==========")

    if new_incidents:

        for incident in new_incidents:

            print(f"\nIncident ID: {incident['incident_id']}")
            print(f"Title: {incident['title']}")
            print(f"Severity: {incident['severity']}")
            print(f"Status: {incident['status']}")

    else:

        print("\nNo new incidents to create.")

    print(f"\nNew incidents created: {len(new_incidents)}")
    print(f"Total incidents: {len(history)}")
    print(f"Reports saved in: {REPORT_DIR}/")

    # Sync complete history so previously unsent incidents
    # can be retried if an earlier network request failed.
    send_incidents_to_server(history)


# ---------------- MAIN ----------------

if __name__ == "__main__":
    process_alerts()
