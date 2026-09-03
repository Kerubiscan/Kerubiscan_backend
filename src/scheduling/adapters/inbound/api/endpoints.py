from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from typing import Optional

from src.core.database import get_db
from src.core.pagination import PaginationParams, PaginatedResponse
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter

from src.scheduling.domain.models import ScheduleResponse
from src.scheduling.adapters.outbound.repository import ScheduleRepository

router = APIRouter()

def get_schedule_repository(db: Session = Depends(get_db)) -> ScheduleRepository:
    return ScheduleRepository(db)

@router.get("", response_model=PaginatedResponse[ScheduleResponse])
@limiter.limit("50/minute")
async def get_schedules(
    request: Request,
    company_id: Optional[str] = Query(None, description="Filter by company ID"),
    pagination: PaginationParams = Depends(),
    repo: ScheduleRepository = Depends(get_schedule_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    skip = (pagination.page - 1) * pagination.size
    items, total = repo.get_all(skip=skip, limit=pagination.size, company_id=company_id)
    pages = (total + pagination.size - 1) // pagination.size
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        size=pagination.size,
        pages=pages
    )

from src.scheduling.domain.models import ScheduleCreate
from fastapi import status

@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_schedule(
    request: Request,
    schedule_in: ScheduleCreate,
    repo: ScheduleRepository = Depends(get_schedule_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_WRITE]))
):
    return repo.create(schedule_in)
