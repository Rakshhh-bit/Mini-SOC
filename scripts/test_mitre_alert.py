
import json
import os
import socket
import urllib.request
import urllib.error
from datetime import datetime, timezone

SERVER_URL = "http://192.168.64.5:5000/api/alerts"

API_TOKEN = os.environ.get("SOC_API_TOKEN")

if not API_TOKEN:
    raise SystemExit("[ERROR] SOC_API_TOKEN is not set.")

test_alert = {
    "alert_id": "SOC-MITRE-TEST-001",
    "title": "Simulated Resource Hijacking Detection",
    "severity": "HIGH",
    "description": "Controlled test alert for verifying MITRE ATT&CK integration.",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "mitre_tactic": "Impact",
    "mitre_technique_id": "T1496",
    "mitre_technique_name": "Resource Hijacking",
    "mitre_mapping_confidence": "LOW",
    "mitre_mapping_note": "Simulated test only. No suspicious process was executed."
}

payload = {
    "hostname": socket.gethostname(),
    "alerts": [test_alert]
}

request = urllib.request.Request(
    SERVER_URL,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "X-API-Key": API_TOKEN
    },
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode("utf-8"))

        print("\n========== MITRE ALERT TEST ==========")
        print("HTTP Status:", response.status)
        print("Server Response:", result)
        print("Alert ID:", test_alert["alert_id"])
        print("MITRE Technique:", test_alert["mitre_technique_id"])
        print("MITRE Tactic:", test_alert["mitre_tactic"])
        print("======================================")

except urllib.error.HTTPError as error:
    print("[ERROR] HTTP:", error.code)
    print(error.read().decode("utf-8"))

except urllib.error.URLError as error:
    print("[ERROR] Could not connect to Ubuntu:", error.reason)

