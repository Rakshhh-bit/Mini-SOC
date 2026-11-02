import json
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "logs" / "network_connections.json"
OUTPUT_FILE = BASE_DIR / "logs" / "network_alerts.json"

SUSPICIOUS_NETWORK_TOOLS = {
    "nc", "ncat", "netcat", "socat", "masscan", "nmap"
}

# Known macOS services. Their presence alone is not suspicious.
KNOWN_SYSTEM_SERVICES = {
    "mdnsresponder",
    "rapportd"
}


def is_wildcard_address(ip):
    """Check whether a service listens on all interfaces."""
    return ip in ("0.0.0.0", "::")


def create_alert(rule_id, title, severity, description,
                 connection=None, confidence="LOW"):

    connection = connection or {}

    local_address = connection.get("local_address") or {}
    remote_address = connection.get("remote_address") or {}

    pid = connection.get("pid")
    process_name = connection.get("process_name")
    port = local_address.get("port")

    # Stable unique ID for deduplication on the central server.
    alert_id = f"{rule_id}-{pid or 'unknown'}-{port or 'unknown'}"

    return {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "hostname": None,
        "process_name": process_name,
        "pid": pid,
        "local_address": local_address,
        "remote_address": remote_address,
        "protocol": connection.get("transport"),
        "connection_status": connection.get("status"),
        "confidence": confidence,
        "mitre_tactic": None,
        "mitre_technique_id": None,
        "mitre_technique_name": None,
        "mitre_mapping_confidence": "NOT_MAPPED",
        "mitre_mapping_note": (
            "No ATT&CK technique assigned. Additional investigation "
            "is required before mapping this network activity."
        )
    }


def deduplicate_connections(connections):
    """Collapse IPv4 and IPv6 entries for the same socket."""
    unique_connections = {}
    
    for connection in connections:

        local = connection.get("local_address") or {}
        remote = connection.get("remote_address") or {}

        key = (
            connection.get("pid"),
            connection.get("process_name"),
            connection.get("transport"),
            local.get("port"),
            remote.get("ip"),
            remote.get("port"),
            connection.get("status")
        )

        # Keep the first record for each logical connection.
        unique_connections.setdefault(key, connection)

    return list(unique_connections.values())


def analyze_network_data(data):

    alerts = []

    hostname = data.get("hostname", "Unknown")
    connections = data.get("connections", [])

    connections = deduplicate_connections(connections)

    for connection in connections:

        process_name = connection.get("process_name")
        normalized_name = (
            process_name.lower() if process_name else ""
        )

        local_address = connection.get("local_address") or {}
        local_ip = local_address.get("ip")
        local_port = local_address.get("port")
        status = connection.get("status")

        # NET-001: Network activity from dual-use utilities.
        if normalized_name in SUSPICIOUS_NETWORK_TOOLS:

            alert = create_alert(
                "NET-001",
                "Network Activity From Dual-Use Utility",
                "MEDIUM",
                (
                    f"Network utility '{process_name}' was observed "
                    f"using port {local_port}, with status '{status}'. "
                    "Verify whether its execution was authorized."
                ),
                connection,
                "LOW"
            )

            alert["hostname"] = hostname
            alerts.append(alert)

        # NET-002: Listening on all network interfaces.
        if status == "LISTEN" and is_wildcard_address(local_ip):

            # Known macOS services are retained as observations,
            # not automatically treated as security alerts.
            if normalized_name in KNOWN_SYSTEM_SERVICES:
                continue

            alert = create_alert(
                "NET-002",
                "Service Listening On All Network Interfaces",
                "MEDIUM",
                (
                    f"Process '{process_name or 'Unknown'}' "
                    f"(PID: {connection.get('pid')}) is listening "
                    f"on {local_ip}:{local_port}. "
                    "Verify the process identity, service purpose, "
                    "and firewall exposure."
                ),
                connection,
                "LOW"
            )

            alert["hostname"] = hostname
            alerts.append(alert)

    # NET-003: Monitoring collection errors.
    collection_errors = data.get("collection_errors", [])

    if collection_errors:

        alert = create_alert(
            "NET-003",
            "Network Monitoring Collection Error",
            "LOW",
            (
                "Network monitoring reported collection errors: "
                + "; ".join(str(error) for error in collection_errors)
            ),
            confidence="HIGH"
        )

        alert["hostname"] = hostname
        alerts.append(alert)

    return alerts


def main():

    print("\n========== MINI SOC NETWORK DETECTOR ==========\n")

    if not INPUT_FILE.exists():
        print("[ERROR] Network monitoring file not found.")
        print(f"Expected file: {INPUT_FILE}")
        return

    try:
        with INPUT_FILE.open("r", encoding="utf-8") as file:
            network_data = json.load(file)

    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Unable to read network data: {error}")
        return

    if not isinstance(network_data, dict):
        print("[ERROR] Invalid network data format.")
        return

    alerts = analyze_network_data(network_data)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    if alerts:
        print(f"[WARNING] {len(alerts)} network alert(s) detected:\n")

        for alert in alerts:
            print(
                f"[{alert['severity']}] "
                f"{alert['rule_id']} - {alert['title']}"
            )
            print(f"Process: {alert['process_name']}")
            print(f"PID: {alert['pid']}")
            print(f"Description: {alert['description']}")
            print(f"Confidence: {alert['confidence']}\n")

    else:
        print("[INFO] No suspicious network indicators detected.")

    print(f"Total network alerts: {len(alerts)}")
    print(f"Results saved to: {OUTPUT_FILE}")
    print("\n===============================================\n")


if __name__ == "__main__":
    main()