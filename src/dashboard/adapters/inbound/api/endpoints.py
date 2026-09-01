from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from src.core.database import get_db
from src.auth.adapters.inbound.api.dependencies import require_permissions
from src.auth.domain.entities import Permission
from src.core.rate_limit import limiter
from src.dashboard.adapters.outbound.repository import DashboardRepository

router = APIRouter()

def get_dashboard_repository(db: Session = Depends(get_db)) -> DashboardRepository:
    return DashboardRepository(db)

@router.get("/kpis")
@limiter.limit("50/minute")
async def get_kpis(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_kpis()

@router.get("/charts/distribution")
@limiter.limit("50/minute")
async def get_distribution_chart(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_distribution_chart()

@router.get("/charts/over-time")
@limiter.limit("50/minute")
async def get_over_time_chart(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_over_time_chart()

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
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_recent_vulnerabilities()

@router.get("/scheduled-scans")
@limiter.limit("50/minute")
async def get_scheduled_scans(
    request: Request,
    repo: DashboardRepository = Depends(get_dashboard_repository),
    current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))
):
    return repo.get_scheduled_scans()
