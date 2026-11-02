
import json
import socket
import platform
from pathlib import Path
from datetime import datetime, timezone

import psutil


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "logs" / "network_connections.json"


def get_process_name(pid):
    """Return process name when permission allows."""
    if pid is None:
        return None

    try:
        return psutil.Process(pid).name()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ):
        return None


def get_address(address):
    """Convert a psutil address into a JSON-friendly dictionary."""
    if not address:
        return None

    return {
        "ip": address.ip,
        "port": address.port
    }


def collect_network_connections():
    connections = []
    errors = []

    try:
        system_connections = psutil.net_connections(kind="inet")

        for connection in system_connections:
            try:
                if connection.family == socket.AF_INET:
                    protocol = "IPv4"
                elif connection.family == socket.AF_INET6:
                    protocol = "IPv6"
                else:
                    protocol = "Unknown"

                if connection.type == socket.SOCK_STREAM:
                    transport = "TCP"
                elif connection.type == socket.SOCK_DGRAM:
                    transport = "UDP"
                else:
                    transport = "Unknown"

                local_address = get_address(connection.laddr)
                remote_address = get_address(connection.raddr)

                connections.append({
                    "protocol": protocol,
                    "transport": transport,
                    "local_address": local_address,
                    "remote_address": remote_address,
                    "status": connection.status or "NONE",
                    "pid": connection.pid,
                    "process_name": get_process_name(connection.pid)
                })

            except (OSError, ValueError) as error:
                errors.append(str(error))

    except psutil.AccessDenied:
        errors.append(
            "Permission denied while reading system network connections. "
            "Try running the script with sudo if necessary."
        )

    except (OSError, RuntimeError) as error:
        errors.append(f"Network collection failed: {error}")

    listening_connections = [
        connection for connection in connections
        if connection["status"] == "LISTEN"
    ]

    established_connections = [
        connection for connection in connections
        if connection["status"] == "ESTABLISHED"
    ]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "operating_system": platform.platform(),
        "total_connections": len(connections),
        "listening_ports_count": len(listening_connections),
        "established_connections_count": len(established_connections),
        "connections": connections,
        "collection_errors": errors
    }


def main():
    print("\n========== MINI SOC NETWORK MONITOR ==========\n")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    network_data = collect_network_connections()

    with OUTPUT_FILE.open("w", encoding="utf-8") as file:
        json.dump(network_data, file, indent=4)

    print("[SUCCESS] Network monitoring completed.")
    print(f"Hostname: {network_data['hostname']}")
    print(f"Total connections: {network_data['total_connections']}")
    print(f"Listening ports: {network_data['listening_ports_count']}")
    print(
        "Established connections: "
        f"{network_data['established_connections_count']}"
    )

    if network_data["collection_errors"]:
        print("\n[WARNING] Collection issues:")
        for error in network_data["collection_errors"]:
            print(f"- {error}")

    print(f"\nResults saved to: {OUTPUT_FILE}")
    print("\n==============================================\n")


if __name__ == "__main__":
    main()
