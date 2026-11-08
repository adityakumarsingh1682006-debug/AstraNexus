from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime


class ServiceHealth(BaseModel):
    status: str = Field(..., description="Service status: operational, degraded, or offline")
    latency_ms: Optional[float] = Field(None, description="Latency in milliseconds")
    details: Optional[str] = None


class HealthResponse(BaseModel):
    project: str = "AstraNexus"
    status: str = "healthy"
    version: str = "1.0.0"
    timestamp: datetime
    environment: str
    services: Dict[str, ServiceHealth]


class APIErrorResponse(BaseModel):
    error: str
    code: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
