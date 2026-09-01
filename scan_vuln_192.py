import urllib.request
import json

data = {
    "company_name": "TestCompany",
    "target": "192.168.100.17",
    "network_zone": "Internal",
    "scan_type": "VULNERABILITY"
}

req = urllib.request.Request(
    'http://localhost:8000/api/v1/scans',
    data=json.dumps(data).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)

try:
    with urllib.request.urlopen(req) as response:
        print("Status:", response.status)
        print("Response:", response.read().decode('utf-8'))
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code)
    print("Response:", e.read().decode('utf-8'))
except Exception as e:
    print("Error:", str(e))
