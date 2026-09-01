from sqlalchemy.orm import Session
from src.audit.domain.models import AuditLog
import json
from typing import Optional, Dict

class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def log_action(self, user_id: str, username: Optional[str], action: str, resource_type: str, resource_id: str, details: Optional[Dict] = None, ip_address: Optional[str] = None):
        """
        Log an administrative or system action.
        """
        audit_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details,
            ip_address=ip_address
        )
        self.db.add(audit_entry)
        self.db.commit()
        self.db.refresh(audit_entry)
        return audit_entry
