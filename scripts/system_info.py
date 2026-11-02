
import platform
import psutil
import socket
from datetime import datetime


def collect_system_information():

    print("=" * 50)
    print("       MINI SOC - SYSTEM INFORMATION")
    print("=" * 50)

    print("Timestamp:", datetime.now())
    print("Operating System:", platform.system())
    print("OS Version:", platform.version())
    print("Architecture:", platform.machine())
    print("Hostname:", socket.gethostname())
    print("CPU Usage:", psutil.cpu_percent(interval=1), "%")
    print("RAM Usage:", psutil.virtual_memory().percent, "%")
    print("Disk Usage:", psutil.disk_usage("/").percent, "%")

    print("=" * 50)


if __name__ == "__main__":
    collect_system_information()
