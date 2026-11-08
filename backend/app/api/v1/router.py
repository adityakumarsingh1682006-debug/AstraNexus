from fastapi import APIRouter
from backend.app.api.v1.endpoints import health, scan, message, alerts, reports, registry

api_router = APIRouter()

# Register core endpoints
api_router.include_router(health.router, prefix="", tags=["System Health"])
api_router.include_router(scan.router, prefix="/scan", tags=["URL Investigation"])
api_router.include_router(message.router, prefix="/message", tags=["Message Triage"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Scam Alerts"])
api_router.include_router(reports.router, prefix="/reports", tags=["Community Reports"])
api_router.include_router(registry.router, prefix="/registry", tags=["Threat Registry Notary"])
