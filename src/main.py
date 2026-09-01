from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from fastapi import Depends
from src.core.config import settings
from src.core.exceptions import KimiaException, kimia_exception_handler
from src.core.rate_limit import limiter
from src.assets.adapters.inbound.api.endpoints import router as assets_router
from src.secrets.adapters.inbound.api.endpoints import router as secrets_router
from src.auth.adapters.inbound.api.endpoints import router as auth_router
from src.auth.adapters.inbound.api.admin_endpoints import router as admin_router
from src.auth.adapters.inbound.api.dependencies import get_current_user, require_role, require_permissions
from src.auth.domain.entities import Permission
from src.audit.adapters.inbound.api.endpoints import router as audit_router
from src.scans.adapters.inbound.api.endpoints import router as scans_router
from src.dashboard.adapters.inbound.api.endpoints import router as dashboard_router
from src.notifications.adapters.inbound.api.endpoints import router as notifications_router
from src.reporting.adapters.inbound.api.endpoints import router as reporting_router
from src.vulnerabilities.adapters.inbound.api.endpoints import router as vulnerabilities_router
from src.policies.adapters.inbound.api.endpoints import router as policies_router
from src.scheduling.adapters.inbound.api.endpoints import router as scheduling_router
from contextlib import asynccontextmanager
from src.core.database import engine, Base
from src.companies.domain.entities import CompanyEntity
from src.scans.domain.entities import ScanEntity
from src.policies.domain.entities import PolicyEntity
from src.scheduling.domain.entities import ScheduleEntity
from src.reporting.domain.entities import ReportEntity
from src.assets.domain.entities import AssetEntity
from src.vulnerabilities.domain.entities import VulnerabilityEntity
from src.audit.domain.models import AuditLog

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Exception handlers
app.add_exception_handler(KimiaException, kimia_exception_handler)

# Register routers
app.include_router(assets_router, prefix=f"{settings.API_V1_STR}/assets", tags=["assets"])
app.include_router(secrets_router, prefix=f"{settings.API_V1_STR}/secrets", tags=["secrets"])
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(admin_router, prefix=f"{settings.API_V1_STR}", tags=["admin"])
app.include_router(audit_router, prefix=f"{settings.API_V1_STR}", tags=["audit"])
app.include_router(scans_router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(dashboard_router, prefix=f"{settings.API_V1_STR}/dashboard", tags=["dashboard"])
app.include_router(notifications_router, prefix=f"{settings.API_V1_STR}/notifications", tags=["notifications"])
app.include_router(reporting_router, prefix=f"{settings.API_V1_STR}/reporting", tags=["reporting"])
app.include_router(vulnerabilities_router, prefix=f"{settings.API_V1_STR}/vulnerabilities", tags=["vulnerabilities"])
app.include_router(policies_router, prefix=f"{settings.API_V1_STR}/policies", tags=["policies"])
app.include_router(scheduling_router, prefix=f"{settings.API_V1_STR}/scheduling", tags=["scheduling"])
@app.get("/health")
@limiter.limit("10/minute")
async def health_check(request: Request):
    return {"status": "healthy"}

@app.get(f"{settings.API_V1_STR}/secure-test")
async def secure_endpoint(current_user: dict = Depends(require_permissions([Permission.ASSET_READ]))):
    return {
        "message": "Authentication successful! You have the correct permissions.", 
        "user_data": current_user
    }
