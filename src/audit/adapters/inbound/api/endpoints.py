from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.audit.domain.entities import AuditLogResponse
from src.audit.domain.models import AuditLog
from src.auth.adapters.inbound.api.dependencies import get_current_user
from src.core.database import get_db

router = APIRouter(prefix="/admin/audits", tags=["Admin Audits"])

@router.get("", response_model=list[AuditLogResponse])
def get_audit_logs(
    limit: int = 100, 
    offset: int = 0,
    db: Session = Depends(get_db), 
    current_user: dict = Depends(get_current_user)
):
    # realm_access = current_user.get("realm_access", {}).get("roles", [])
    # if "Platform Administrator" not in realm_access:
    #     raise HTTPException(status_code=403, detail="Not enough permissions")

    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    return logs
