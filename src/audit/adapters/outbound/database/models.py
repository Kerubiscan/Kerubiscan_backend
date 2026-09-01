import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base
import uuid

Base = declarative_base()

class AuditLogModel(Base):
    __tablename__ = 'audit_logs'

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=True)
    status = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    details = Column(Text, nullable=True)
