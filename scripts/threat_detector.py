
import json
from pathlib import Path
from datetime import datetime, timezone

# ---------------- PROJECT PATHS ----------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "logs" / "system_monitor.json"
OUTPUT_FILE = BASE_DIR / "logs" / "security_alerts.json"


# ---------------- DETECTION THRESHOLDS ----------------

CPU_THRESHOLD = 90
MEMORY_THRESHOLD = 90
DISK_THRESHOLD = 90

PROCESS_CPU_THRESHOLD = 80
PROCESS_MEMORY_THRESHOLD = 25


# ---------------- PROCESS WATCHLIST ----------------

WATCHLIST = {
    "ncat",
    "netcat",
    "nc",
    "socat",
    "masscan",
    "xmrig"
}


# ---------------- MITRE ATT&CK MAPPINGS ----------------

# Resource anomalies alone do not establish an ATT&CK technique.
UNMAPPED_RESOURCE = {
    "mitre_tactic": None,
    "mitre_technique_id": None,
    "mitre_technique_name": None,
    "mitre_mapping_confidence": "NOT_MAPPED",
    "mitre_mapping_note": (
        "Resource anomaly only. Additional investigation is required "
        "before assigning a MITRE ATT&CK technique."
    )
}


# Candidate mappings for specific watchlisted processes.
# These mappings are indicators for investigation, not proof of an attack.

PROCESS_MITRE_MAPPINGS = {
    "masscan": {
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_mapping_confidence": "LOW",
        "mitre_mapping_note": (
            "Candidate mapping based on the process name. "
            "Confirm execution arguments and network activity."
        )
    },

    "xmrig": {
        "mitre_tactic": "Impact",
        "mitre_technique_id": "T1496",
        "mitre_technique_name": "Resource Hijacking",
        "mitre_mapping_confidence": "LOW",
        "mitre_mapping_note": (
            "Candidate mapping for possible unauthorized cryptomining. "
            "Confirm process legitimacy and mining activity."
        )
    }
}


# ---------------- ALERT CREATION ----------------

def create_alert(
    rule_id,
    title,
    severity,
    description,
    mitre_mapping=None
):
    """Create a standardized alert with MITRE ATT&CK metadata."""

    mapping = mitre_mapping or UNMAPPED_RESOURCE

    return {
        "alert_id": rule_id,
        "title": title,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # MITRE ATT&CK fields
        "mitre_tactic": mapping["mitre_tactic"],
        "mitre_technique_id": mapping["mitre_technique_id"],
        "mitre_technique_name": mapping["mitre_technique_name"],
        "mitre_mapping_confidence": mapping["mitre_mapping_confidence"],
        "mitre_mapping_note": mapping["mitre_mapping_note"]
    }


# ---------------- THREAT ANALYSIS ----------------

def analyze_system(data):
    """Analyze system monitoring data and generate security alerts."""

    alerts = []

    cpu = data.get("cpu", {})
    memory = data.get("memory", {})
    disk = data.get("disk", {})
    processes = data.get("top_processes", [])

    # Rule 1: High CPU usage

    cpu_usage = cpu.get("cpu_usage_percent")

    if (
        isinstance(cpu_usage, (int, float))
        and cpu_usage >= CPU_THRESHOLD
    ):
        alerts.append(create_alert(
            "SOC-001",
            "High CPU Usage",
            "HIGH",
            f"CPU usage reached {cpu_usage}%.",
            UNMAPPED_RESOURCE
        ))

    # Rule 2: High memory usage

    memory_usage = memory.get("usage_percent")

    if (
        isinstance(memory_usage, (int, float))
        and memory_usage >= MEMORY_THRESHOLD
    ):
        alerts.append(create_alert(
            "SOC-002",
            "High Memory Usage",
            "HIGH",
            f"Memory usage reached {memory_usage}%.",
            UNMAPPED_RESOURCE
        ))

    # Rule 3: High disk usage

    disk_usage = disk.get("usage_percent")

    if (
        isinstance(disk_usage, (int, float))
        and disk_usage >= DISK_THRESHOLD
    ):
        alerts.append(create_alert(
            "SOC-003",
            "High Disk Usage",
            "MEDIUM",
            f"Disk usage reached {disk_usage}%.",
            UNMAPPED_RESOURCE
        ))

    # Rule 4: Watchlisted process detection

    for process in processes:

        name = process.get("name")

        if not isinstance(name, str):
            continue

        normalized_name = name.lower()

        if normalized_name in WATCHLIST:

            mapping = PROCESS_MITRE_MAPPINGS.get(
                normalized_name,
                {
                    "mitre_tactic": None,
                    "mitre_technique_id": None,
                    "mitre_technique_name": None,
                    "mitre_mapping_confidence": "NOT_MAPPED",
                    "mitre_mapping_note": (
                        "Dual-use network utility detected. "
                        "Process name alone does not establish "
                        "a MITRE ATT&CK technique."
                    )
                }
            )

            alerts.append(create_alert(
                "SOC-004",
                "Watchlisted Process Detected",
                "HIGH",
                (
                    f"Process '{name}' (PID: {process.get('pid')}) "
                    "requires investigation."
                ),
                mapping
            ))

    # Rule 5: High CPU process

    for process in processes:

        process_cpu = process.get("cpu_percent")

        if (
            isinstance(process_cpu, (int, float))
            and process_cpu >= PROCESS_CPU_THRESHOLD
        ):
            alerts.append(create_alert(
                "SOC-005",
                "High CPU Process",
                "MEDIUM",
                (
                    f"Process '{process.get('name')}' "
                    f"(PID: {process.get('pid')}) is using "
                    f"{process_cpu}% CPU."
                ),
                UNMAPPED_RESOURCE
            ))

    # Rule 6: High memory process

    for process in processes:

        process_memory = process.get("memory_percent")

        if (
            isinstance(process_memory, (int, float))
            and process_memory >= PROCESS_MEMORY_THRESHOLD
        ):
            alerts.append(create_alert(
                "SOC-006",
                "High Memory Process",
                "MEDIUM",
                (
                    f"Process '{process.get('name')}' "
                    f"(PID: {process.get('pid')}) is using "
                    f"{process_memory}% memory."
                ),
                UNMAPPED_RESOURCE
            ))

    return alerts


# ---------------- MAIN FUNCTION ----------------

def main():

    print("\n========== MINI SOC THREAT DETECTOR ==========")

    if not INPUT_FILE.exists():
        print("\nERROR: System monitoring data not found.")
        print(f"Expected file: {INPUT_FILE}")
        return

    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

    except (OSError, json.JSONDecodeError) as error:
        print(f"\nERROR: Could not read monitoring data: {error}")
        return

    if not isinstance(data, dict):
        print("\nERROR: Invalid monitoring data format.")
        return

    alerts = analyze_system(data)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    if alerts:

        for alert in alerts:

            print(f"\n[{alert['severity']}] {alert['title']}")
            print(f"Rule: {alert['alert_id']}")
            print(f"Details: {alert['description']}")

            if alert["mitre_technique_id"]:
                print(
                    "MITRE ATT&CK: "
                    f"{alert['mitre_technique_id']} - "
                    f"{alert['mitre_technique_name']}"
                )

                print(
                    f"Tactic: {alert['mitre_tactic']}"
                )

                print(
                    "Mapping confidence: "
                    f"{alert['mitre_mapping_confidence']}"
                )

            else:
                print("MITRE ATT&CK: No direct mapping assigned.")

            print(
                f"Mapping note: {alert['mitre_mapping_note']}"
            )

    else:
        print("\nNo security alerts detected.")

    print(f"\nTotal alerts: {len(alerts)}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
