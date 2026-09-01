import urllib.request
import json

req = urllib.request.Request('http://localhost:8000/api/v1/scans')
with urllib.request.urlopen(req) as response:
    print("Scans:", json.loads(response.read().decode('utf-8')))

# There is no unauthenticated way to get assets without a token, so we'll just check the celery logs.
