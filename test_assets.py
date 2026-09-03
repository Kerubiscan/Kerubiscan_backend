from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

try:
    response = client.get("/api/assets")
    print("Status:", response.status_code)
    print("Body:", response.json())
except Exception as e:
    import traceback
    traceback.print_exc()
