from datetime import date
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional

from src.core.database import get_db
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter
from src.dashboard.adapters.outbound.repository import DashboardRepository

router = APIRouter()

# A past local day (YYYY-MM-DD) picked on the over-time chart; absent: the current dashboard
DayParam = Query(None, description="Jour local (AAAA-MM-JJ) choisi sur le graphique ; absent : vue actuelle")

def get_dashboard_repository(db: Session = Depends(get_db)) -> DashboardRepository:
    return DashboardRepository(db)

@router.get("/kpis")
@limiter.limit("50/minute")
async def get_kpis(
    request: Request,
    date: Optional[date] = DayParam,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_kpis(date)

@router.get("/charts/distribution")
@limiter.limit("50/minute")
async def get_distribution_chart(
    request: Request,
    date: Optional[date] = DayParam,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_distribution_chart(date)

@router.get("/charts/over-time")
@limiter.limit("50/minute")
async def get_over_time_chart(
    request: Request,
    days: int = Query(14, ge=2, le=90),
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_over_time_chart(days)

@router.get("/latest-scan")
@limiter.limit("50/minute")
async def get_latest_scan(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_latest_scan()

@router.get("/assets-os")
@limiter.limit("50/minute")
async def get_assets_by_os(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_assets_by_os()

@router.get("/recent-vulnerabilities")
@limiter.limit("50/minute")
async def get_recent_vulnerabilities(
    request: Request,
    date: Optional[date] = DayParam,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_recent_vulnerabilities(date)


@router.get("/scans-of-day")
@limiter.limit("50/minute")
async def get_scans_of_day(
    request: Request,
    date: date = Query(..., description="Jour local (AAAA-MM-JJ)"),
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_scans_of_day(date)

@router.get("/scheduled-scans")
@limiter.limit("50/minute")
async def get_scheduled_scans(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_scheduled_scans()
