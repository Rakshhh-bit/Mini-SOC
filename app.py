
from flask import Flask, render_template, jsonify, request
from pathlib import Path
from datetime import datetime, timezone
import json
import socket

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"

SYSTEM_FILE = LOG_DIR / "system_monitor.json"
ALERT_FILE = LOG_DIR / "security_alerts.json"
NETWORK_ALERT_FILE = LOG_DIR / "network_alerts.json"
HISTORY_FILE = BASE_DIR / "incident-reports" / "incident_history.json"

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def load_json(file_path, default):
    """Safely load JSON data."""
    try:
        if not file_path.exists():
            return default

        with file_path.open("r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        return default


def load_alerts():
    """Load and combine security and network alerts."""
    security_alerts = load_json(ALERT_FILE, [])
    network_alerts = load_json(NETWORK_ALERT_FILE, [])

    if not isinstance(security_alerts, list):
        security_alerts = []

    if not isinstance(network_alerts, list):
        network_alerts = []

    combined = security_alerts + network_alerts

    # Remove duplicate alerts.
    unique = {}
    for alert in combined:
        if isinstance(alert, dict):
            key = (
                alert.get("alert_id"),
                alert.get("title")
            )
            unique[key] = alert

    return list(unique.values())


def load_incidents():
    incidents = load_json(HISTORY_FILE, [])
    return incidents if isinstance(incidents, list) else []


def get_dashboard_data():
    """Return local Mac monitoring data."""

    system_data = load_json(SYSTEM_FILE, {})

    if not isinstance(system_data, dict):
        system_data = {}

    alerts = load_alerts()
    incidents = load_incidents()

    cpu = system_data.get("cpu", {})
    memory = system_data.get("memory", {})
    disk = system_data.get("disk", {})
    system = system_data.get("system", {})

    severity_counts = {
        severity: 0 for severity in SEVERITIES
    }

    for alert in alerts:
        severity = str(alert.get("severity", "LOW")).upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    open_incidents = sum(
        1 for incident in incidents
        if str(incident.get("status", "")).upper() == "OPEN"
    )

    return {
        "system": system,
        "cpu": cpu,
        "memory": memory,
        "disk": disk,
        "alerts": alerts,
        "incidents": incidents,
        "summary": {
            "total_alerts": len(alerts),
            "total_incidents": len(incidents),
            "open_incidents": open_incidents,
            "severity": severity_counts
        },
        "updated_at": datetime.now(timezone.utc).isoformat()
    }


# --------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/dashboard")
def dashboard_api():
    return jsonify(get_dashboard_data())


@app.route("/api/health")
def health():
    return jsonify({
        "status": "online",
        "application": "Mini SOC Mac Endpoint Dashboard",
        "hostname": socket.gethostname()
    })


# --------------------------------------------------
# LOCAL DASHBOARD API ROUTES
# Compatible with redesigned dashboard.js
# --------------------------------------------------

@app.route("/dashboard/api/telemetry")
def local_telemetry_api():
    system_data = load_json(SYSTEM_FILE, {})

    if not isinstance(system_data, dict) or not system_data:
        return jsonify({
            "status": "success",
            "count": 0,
            "telemetry": []
        })

    record = {
        "id": 1,
        "hostname": system_data.get(
            "system", {}
        ).get("hostname", socket.gethostname()),
        "received_at": system_data.get(
            "system", {}
        ).get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "data": json.dumps(system_data)
    }

    return jsonify({
        "status": "success",
        "count": 1,
        "telemetry": [record]
    })


@app.route("/dashboard/api/alerts")
def local_alerts_api():
    alerts = load_alerts()

    return jsonify({
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    })


@app.route("/dashboard/api/incidents")
def local_incidents_api():
    incidents = load_incidents()

    return jsonify({
        "status": "success",
        "count": len(incidents),
        "incidents": incidents
    })


# --------------------------------------------------
# LOCAL INCIDENT RESPONSE
# --------------------------------------------------

@app.route(
    "/dashboard/api/incidents/<incident_id>/status",
    methods=["PATCH"]
)
def update_local_incident_status(incident_id):

    payload = request.get_json(silent=True) or {}
    new_status = str(payload.get("status", "")).upper()

    allowed_statuses = {
        "OPEN",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED"
    }

    if new_status not in allowed_statuses:
        return jsonify({
            "status": "error",
            "message": "Invalid incident status"
        }), 400

    incidents = load_incidents()
    found = False

    for incident in incidents:
        if incident.get("incident_id") == incident_id:
            incident["status"] = new_status
            incident["updated_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            found = True
            break

    if not found:
        return jsonify({
            "status": "error",
            "message": "Incident not found"
        }), 404

    try:
        HISTORY_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with HISTORY_FILE.open("w", encoding="utf-8") as file:
            json.dump(incidents, file, indent=4)

    except OSError as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500

    return jsonify({
        "status": "success",
        "message": "Incident status updated",
        "incident_id": incident_id,
        "new_status": new_status
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
