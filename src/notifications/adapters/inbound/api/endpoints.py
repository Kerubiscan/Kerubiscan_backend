from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class NotificationCount(BaseModel):
    unread_count: int

from src.core.database import get_db
from sqlalchemy.orm import Session
from fastapi import Depends
from src.audit.domain.models import AuditLog
from datetime import datetime, timedelta, timezone

@router.get("/unread-count", response_model=NotificationCount)
async def get_unread_count(db: Session = Depends(get_db)):
    # Calculate how many audits happened in the last 24 hours as a proxy for "notifications"
    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    # Removing timezone info for SQLAlchemy SQLite/PostgreSQL compatibility if needed, but utcnow is deprecated so we use timezone.utc, though models use datetime.utcnow? Wait, models.py uses `datetime.now(timezone.utc)`.
    # Let's use datetime.utcnow() for simplicity to avoid timezone offset issues if DB has no timezone. But actually model uses `timezone.utc`.
    yesterday = datetime.now(timezone.utc).replace(tzinfo=None) # fallback to naive utc
    recent_audits = db.query(AuditLog).filter(AuditLog.timestamp >= yesterday).count()
    return NotificationCount(unread_count=recent_audits)
