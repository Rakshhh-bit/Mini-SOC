
import psutil
import platform
import socket
import json
import time
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
OUTPUT_FILE = LOG_DIR / "system_monitor.json"


def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "operating_system": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "timestamp": datetime.now().isoformat()
    }


def get_cpu_info():
    return {
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "cpu_cores": psutil.cpu_count(logical=True)
    }


def get_memory_info():
    memory = psutil.virtual_memory()

    return {
        "total_gb": round(memory.total / (1024 ** 3), 2),
        "used_gb": round(memory.used / (1024 ** 3), 2),
        "available_gb": round(memory.available / (1024 ** 3), 2),
        "usage_percent": memory.percent
    }


def get_disk_info():
    disk = psutil.disk_usage("/")

    return {
        "total_gb": round(disk.total / (1024 ** 3), 2),
        "used_gb": round(disk.used / (1024 ** 3), 2),
        "free_gb": round(disk.free / (1024 ** 3), 2),
        "usage_percent": disk.percent
    }


def get_network_info():
    network = psutil.net_io_counters()

    return {
        "bytes_sent": network.bytes_sent,
        "bytes_received": network.bytes_recv,
        "packets_sent": network.packets_sent,
        "packets_received": network.packets_recv
    }


def get_top_processes(limit=10):
    """Measure process CPU and memory usage."""

    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username"]
    ):
        try:
            # Start CPU measurement
            process.cpu_percent(interval=None)
            processes.append(process)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    # Allow time for CPU usage to accumulate
    time.sleep(0.5)

    total_memory = psutil.virtual_memory().total

    process_data = []

    for process in processes:
        try:
            cpu_usage = process.cpu_percent(interval=None)

            memory_info = process.memory_info()
            memory_usage = (
                memory_info.rss / total_memory
            ) * 100

            process_data.append({
                "pid": process.pid,
                "name": process.name(),
                "username": process.username(),
                "cpu_percent": round(cpu_usage, 2),
                "memory_percent": round(memory_usage, 2)
            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    process_data.sort(
        key=lambda item: item["cpu_percent"],
        reverse=True
    )

    return process_data[:limit]


def collect_system_data():
    return {
        "system": get_system_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        "top_processes": get_top_processes()
    }


def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    data = collect_system_data()

    print("\n========== MINI SOC SYSTEM MONITOR ==========\n")
    print(json.dumps(data, indent=4))

    with open(OUTPUT_FILE, "w") as file:
        json.dump(data, file, indent=4)

    print(f"\nMonitoring data saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main() 
