from fastapi import APIRouter
from app.api.routes_health import router as health_router
from app.api.routes_analysis import router as analysis_router
from app.api.routes_cases import router as cases_router
from app.api.routes_reports import router as reports_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health_router)
api_router.include_router(analysis_router)
api_router.include_router(cases_router)
api_router.include_router(reports_router)

__all__ = ["api_router"]
