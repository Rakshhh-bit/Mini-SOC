
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SCRIPTS = [
    "scripts/system_monitor.py",
    "scripts/threat_detector.py",
    "scripts/incident_manager.py",
    "scripts/send_telemetry.py",
    "scripts/send_alerts.py"
]

INTERVAL = 10


def run_script(script):
    script_path = BASE_DIR / script

    print(f"\n[RUNNING] {script}")

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=BASE_DIR,
            check=True
        )
        print(f"[SUCCESS] {script}")

    except subprocess.CalledProcessError as error:
        print(f"[ERROR] {script} failed: {error}")


def main():
    print("====================================")
    print("       MINI SOC AUTOMATED MONITOR")
    print("====================================")
    print("Central SOC: Ubuntu Server")
    print(f"Monitoring interval: {INTERVAL} seconds")
    print("Press CTRL+C to stop.\n")

    try:
        while True:
            print("\n========== NEW MONITORING CYCLE ==========")

            for script in SCRIPTS:
                run_script(script)

            print(f"\n[WAITING] Next cycle in {INTERVAL} seconds.")
            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\n[STOPPED] Mini SOC monitoring stopped.")


if __name__ == "__main__":
    main()
