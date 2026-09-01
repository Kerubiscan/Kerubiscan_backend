import sys
import os

# Add src to path so we can import from src
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.core.database import SessionLocal
from src.scans.domain.entities import ScanEntity
from src.assets.domain.entities import AssetEntity

db = SessionLocal()

print("--- Scans ---")
for scan in db.query(ScanEntity).all():
    print(f"[{scan.id}] {scan.name} - Status: {scan.status.name} - Progress: {scan.progress}%")

print("\n--- Assets ---")
for asset in db.query(AssetEntity).all():
    print(f"[{asset.id}] {asset.name} - IP: {asset.ip_address} - Ports: {asset.ports}")

db.close()
