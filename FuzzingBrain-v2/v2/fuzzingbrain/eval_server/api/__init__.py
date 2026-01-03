"""API routes for Evaluation Server."""

from fastapi import APIRouter

from .instances import router as instances_router
from .events import router as events_router
from .logs import router as logs_router
from .costs import router as costs_router
from .tasks import router as tasks_router
from .workers import router as workers_router
from .agents import router as agents_router
from .suspicious_points import router as sp_router
from .povs import router as povs_router
from .reports import router as reports_router
from .directions import router as directions_router

# Main API router
api_router = APIRouter(prefix="/api/v1")

# Include sub-routers
api_router.include_router(instances_router, prefix="/instances", tags=["instances"])
api_router.include_router(tasks_router, prefix="/tasks", tags=["tasks"])
api_router.include_router(workers_router, prefix="/workers", tags=["workers"])
api_router.include_router(agents_router, prefix="/agents", tags=["agents"])
api_router.include_router(events_router, prefix="/events", tags=["events"])
api_router.include_router(logs_router, prefix="/logs", tags=["logs"])
api_router.include_router(costs_router, prefix="/costs", tags=["costs"])
api_router.include_router(sp_router, prefix="/suspicious-points", tags=["suspicious-points"])
api_router.include_router(povs_router, prefix="/povs", tags=["povs"])
api_router.include_router(reports_router, prefix="/reports", tags=["reports"])
api_router.include_router(directions_router, prefix="/directions", tags=["directions"])

__all__ = ["api_router"]
