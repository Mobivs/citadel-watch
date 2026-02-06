# PRD: Dashboard - Web API
# Reference: docs/PRD.md v0.2.2, Section: Dashboard - Unified Control Center
#
# FastAPI backend providing REST API and WebSocket endpoints
# for real-time communication with the Dashboard UI.

from .main import app, start_api_server
from .dashboard_ext import (
    DashboardServices,
    EventBroadcaster,
    TTLCache,
    cache,
    services,
    broadcaster,
)

__all__ = [
    "app",
    "start_api_server",
    "DashboardServices",
    "EventBroadcaster",
    "TTLCache",
    "cache",
    "services",
    "broadcaster",
]
