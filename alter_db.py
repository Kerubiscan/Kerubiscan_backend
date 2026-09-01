import os
from sqlalchemy import create_engine, text
from src.core.config import settings

def upgrade_db():
    engine = create_engine(settings.POSTGRES_URL)
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE schedules ADD COLUMN scan_type VARCHAR NOT NULL DEFAULT 'VULNERABILITY';"))
            print("Added scan_type")
        except Exception as e:
            print(f"Error adding scan_type: {e}")
            
        try:
            conn.execute(text("ALTER TABLE schedules ADD COLUMN network_zone VARCHAR;"))
            print("Added network_zone")
        except Exception as e:
            print(f"Error adding network_zone: {e}")
            
        try:
            conn.execute(text("ALTER TABLE schedules ADD COLUMN scanner_engine VARCHAR NOT NULL DEFAULT 'OPENVAS';"))
            print("Added scanner_engine")
        except Exception as e:
            print(f"Error adding scanner_engine: {e}")

if __name__ == "__main__":
    upgrade_db()
