"""
API routes for DDoS Attack Map visualization.

Provides endpoints optimized for frontend Globe/Map visualization.
"""

import asyncio
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AttackEvent, IncidentReport, IPReputation
from config import EVENTS_PER_POLL
from services.briefing import generate_threat_briefing
from agents.threat_investigator import get_agent_status

# Create router with prefix
router = APIRouter(prefix="/api/v1", tags=["attacks"])


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            try:
                self.active_connections.remove(websocket)
            except ValueError:
                pass

    async def broadcast(self, message: dict) -> None:
        async with self._lock:
            connections = list(self.active_connections)

        dead_connections: list[WebSocket] = []
        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception:
                dead_connections.append(websocket)

        if dead_connections:
            async with self._lock:
                for ws in dead_connections:
                    try:
                        self.active_connections.remove(ws)
                    except ValueError:
                        pass


manager = ConnectionManager()


def severity_to_color(severity: float) -> str:
    """
    Convert severity score to hex color for visualization.

    Color gradient:
    - 0-3: Green (low threat)
    - 3-6: Yellow/Orange (medium threat)
    - 6-8: Orange/Red (high threat)
    - 8-10: Red/Magenta (critical threat)
    """
    if severity <= 3:
        # Green to Yellow
        ratio = severity / 3
        r = int(255 * ratio)
        g = 255
        b = 0
    elif severity <= 6:
        # Yellow to Orange
        ratio = (severity - 3) / 3
        r = 255
        g = int(255 * (1 - ratio * 0.5))
        b = 0
    elif severity <= 8:
        # Orange to Red
        ratio = (severity - 6) / 2
        r = 255
        g = int(128 * (1 - ratio))
        b = 0
    else:
        # Red to Magenta
        ratio = (severity - 8) / 2
        r = 255
        g = 0
        b = int(128 * ratio)

    return f"#{r:02x}{g:02x}{b:02x}"


# Response schemas optimized for Globe visualization
class AttackArcResponse(BaseModel):
    """Single attack arc for Globe visualization."""

    id: int
    source_lat: float = Field(..., alias="srcLat")
    source_lon: float = Field(..., alias="srcLon")
    target_lat: float = Field(..., alias="tgtLat")
    target_lon: float = Field(..., alias="tgtLon")
    color: str
    stroke_width: float = Field(..., alias="strokeWidth")
    attack_type: str = Field(..., alias="attackType")
    severity: float
    packet_rate: int = Field(..., alias="packetRate")
    timestamp: datetime
    source_ip: str = Field(..., alias="sourceIp")
    target_ip: str = Field(..., alias="targetIp")

    class Config:
        from_attributes = True
        populate_by_name = True


class LiveAttacksResponse(BaseModel):
    """Response for live attacks endpoint."""

    count: int
    attacks: list[AttackArcResponse]
    last_updated: datetime


def attack_to_arc(event: AttackEvent) -> dict:
    """Convert AttackEvent to arc visualization format."""
    # Stroke width based on packet rate (normalized)
    stroke_width = min(5.0, max(0.5, event.packet_rate / 20000))

    return {
        "id": event.id,
        "srcLat": event.source_lat,
        "srcLon": event.source_lon,
        "tgtLat": event.target_lat,
        "tgtLon": event.target_lon,
        "color": severity_to_color(event.severity_score),
        "strokeWidth": stroke_width,
        "attackType": event.attack_type,
        "severity": event.severity_score,
        "packetRate": event.packet_rate,
        "timestamp": event.timestamp,
        "sourceIp": event.source_ip,
        "targetIp": event.target_ip,
        "isSimulated": event.is_simulated,
    }


@router.get("/agent/status")
async def agent_status():
    return get_agent_status()


@router.get("/attacks/live", response_model=LiveAttacksResponse)
async def get_live_attacks(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=500),
):
    """
    Get the latest attack events for live visualization.

    Returns attack data optimized for Globe/Map rendering with:
    - Source and target coordinates
    - Color based on severity
    - Stroke width based on packet rate

    Args:
        limit: Maximum number of attacks to return (1-500, default 100).

    Returns:
        List of attack arcs ready for Globe visualization.
    """
    query = select(AttackEvent).order_by(AttackEvent.timestamp.desc()).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    attacks = [attack_to_arc(event) for event in events]

    return LiveAttacksResponse(
        count=len(attacks),
        attacks=attacks,
        last_updated=datetime.utcnow(),
    )


@router.get("/attacks/stream")
async def get_attacks_since(
    db: AsyncSession = Depends(get_db),
    since_id: int | None = Query(default=0, description="Get attacks after this ID"),
    limit: int = Query(default=50, ge=1, le=200),
):
    """
    Get new attacks since a given ID (for incremental polling).

    Use this for efficient updates - only fetches new data since last poll.
    Frontend should track the latest_id and pass it on subsequent requests.

    Args:
        since_id: Only return attacks with ID greater than this (default: 0).
        limit: Maximum number of attacks to return (ignored - capped by EVENTS_PER_POLL).

    Returns:
        New attacks since the given ID, sorted chronologically (oldest first),
        with backlog information.
    """
    # Apply rate limiting - use EVENTS_PER_POLL as hard limit
    effective_limit = EVENTS_PER_POLL
    
    query = (
        select(AttackEvent)
        .where(AttackEvent.id > since_id)
        .order_by(AttackEvent.timestamp.asc())  # Chronological order
        .limit(effective_limit)
    )

    result = await db.execute(query)
    events = result.scalars().all()

    attacks = [attack_to_arc(event) for event in events]

    # Get the max ID for next poll
    latest_id = max((a["id"] for a in attacks), default=since_id)

    # Count backlog (remaining events not yet delivered)
    backlog_query = select(func.count(AttackEvent.id)).where(AttackEvent.id > latest_id)
    backlog_result = await db.execute(backlog_query)
    backlog_count = backlog_result.scalar() or 0

    return {
        "count": len(attacks),
        "attacks": attacks,
        "latest_id": latest_id,
        "has_more": len(attacks) == effective_limit,  # Indicates if there might be more data
        "backlog": backlog_count,  # Number of events still waiting to be delivered
    }


@router.get("/attacks/stats")
async def get_attack_statistics(
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated attack statistics for the dashboard.

    Computes windowed metrics (5-minute current vs 5-minute previous),
    top countries, top attack types, severity averages, and peak rate.
    """
    now = datetime.now(UTC)
    t_5m = now - timedelta(minutes=5)
    t_10m = now - timedelta(minutes=10)
    t_1m = now - timedelta(minutes=1)

    # --- Event counts for current and previous 5-min windows ---
    current_count_q = select(func.count(AttackEvent.id)).where(
        AttackEvent.timestamp >= t_5m
    )
    prev_count_q = select(func.count(AttackEvent.id)).where(
        AttackEvent.timestamp >= t_10m,
        AttackEvent.timestamp < t_5m,
    )
    # 1-minute window count for current rate
    current_1m_count_q = select(func.count(AttackEvent.id)).where(
        AttackEvent.timestamp >= t_1m
    )
    current_result, prev_result, current_1m_result = (
        await db.execute(current_count_q),
        await db.execute(prev_count_q),
        await db.execute(current_1m_count_q),
    )
    current_count: int = current_result.scalar() or 0
    prev_count: int = prev_result.scalar() or 0
    current_1m_count: int = current_1m_result.scalar() or 0

    # Trend percentage (guard against division by zero)
    trend_pct: float = 0.0
    if prev_count > 0:
        trend_pct = round(((current_count - prev_count) / prev_count) * 100, 1)

    # Current rate: events in the last 1 minute (most responsive to live activity)
    events_per_min = float(current_1m_count)

    # --- Top 3 countries (join IPReputation on source_ip) ---
    top_countries_q = (
        select(
            IPReputation.country_code,
            func.count(AttackEvent.id).label("cnt"),
        )
        .join(IPReputation, AttackEvent.source_ip == IPReputation.ip)
        .where(AttackEvent.timestamp >= t_5m)
        .group_by(IPReputation.country_code)
        .order_by(desc("cnt"))
        .limit(3)
    )
    top_countries_result = await db.execute(top_countries_q)
    top_countries = [
        {"country": row.country_code or "--", "count": row.cnt}
        for row in top_countries_result
    ]

    # --- Top 3 attack types ---
    top_types_q = (
        select(
            AttackEvent.attack_type,
            func.count(AttackEvent.id).label("cnt"),
            func.avg(AttackEvent.severity_score).label("avg_sev"),
        )
        .where(AttackEvent.timestamp >= t_5m)
        .group_by(AttackEvent.attack_type)
        .order_by(desc("cnt"))
        .limit(3)
    )
    top_types_result = await db.execute(top_types_q)
    top_attack_types = [
        {
            "type": row.attack_type,
            "count": row.cnt,
            "avg_severity": round(float(row.avg_sev or 0), 1),
        }
        for row in top_types_result
    ]

    # --- Average severity for 1-min and 5-min windows ---
    avg_1m_q = select(func.avg(AttackEvent.severity_score)).where(
        AttackEvent.timestamp >= t_1m
    )
    avg_5m_q = select(func.avg(AttackEvent.severity_score)).where(
        AttackEvent.timestamp >= t_5m
    )
    avg_1m_result, avg_5m_result = await db.execute(avg_1m_q), await db.execute(avg_5m_q)
    avg_severity_1m = round(float(avg_1m_result.scalar() or 0), 1)
    avg_severity_5m = round(float(avg_5m_result.scalar() or 0), 1)

    # --- Peak packet rate in 5-min window ---
    peak_q = select(func.max(AttackEvent.packet_rate)).where(
        AttackEvent.timestamp >= t_5m
    )
    peak_result = await db.execute(peak_q)
    peak_packet_rate: int = peak_result.scalar() or 0

    return {
        "window_minutes": 5,
        "current_count": current_count,
        "prev_count": prev_count,
        "trend_pct": trend_pct,
        "events_per_min": events_per_min,
        "top_countries": top_countries,
        "top_attack_types": top_attack_types,
        "avg_severity_1m": avg_severity_1m,
        "avg_severity_5m": avg_severity_5m,
        "peak_packet_rate": peak_packet_rate,
        "generated_at": now.isoformat(),
    }


@router.get("/attacks/{attack_id}")
async def get_attack_detail(
    attack_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed information about a specific attack.

    Args:
        attack_id: The attack event ID.

    Returns:
        Full attack details.
    """
    query = select(AttackEvent).where(AttackEvent.id == attack_id)
    result = await db.execute(query)
    event = result.scalar_one_or_none()

    if not event:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Attack not found")

    return {
        **attack_to_arc(event),
        "source_ip": event.source_ip,
        "target_ip": event.target_ip,
    }


async def _event_with_country(event: AttackEvent, db: AsyncSession) -> dict:
    """Convert an AttackEvent to a dict enriched with country_code from IPReputation."""
    country = None
    rep = await db.get(IPReputation, event.source_ip)
    if rep:
        country = rep.country_code
    return {
        "attack_type": event.attack_type,
        "severity_score": event.severity_score,
        "packet_rate": event.packet_rate,
        "source_country": country or "??",
        "timestamp": event.timestamp.isoformat() if event.timestamp else "",
    }


@router.get("/incidents")
async def get_incident_reports(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=200),
    repeat_only: bool = Query(default=False, description="Return only repeat-attacker incidents"),
    campaign_only: bool = Query(default=False, description="Return only campaign-detected incidents"),
):
    """
    Retrieve AI-generated incident reports ordered most-recent first.

    Args:
        limit: Maximum number of reports to return (1-200, default 50).
        repeat_only: If true, only return incidents where is_repeat_attacker is true.
        campaign_only: If true, only return incidents where campaign_detected is true.

    Returns:
        List of incident reports with all agent findings.
    """
    query = select(IncidentReport).order_by(IncidentReport.generated_at.desc())

    if repeat_only:
        query = query.where(IncidentReport.is_repeat_attacker.is_(True))
    if campaign_only:
        query = query.where(IncidentReport.campaign_detected.is_(True))

    query = query.limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()

    return {
        "count": len(reports),
        "reports": [
            {
                "id": r.id,
                "attack_event_id": r.attack_event_id,
                "source_ip": r.source_ip,
                "attack_type": r.attack_type,
                "severity_score": r.severity_score,
                "ip_reputation_summary": r.ip_reputation_summary,
                "cve_findings": r.cve_findings,
                "trend_context": r.trend_context,
                "threat_level": r.threat_level,
                "summary": r.summary,
                "recommended_action": r.recommended_action,
                "is_repeat_attacker": r.is_repeat_attacker,
                "campaign_detected": r.campaign_detected,
                "pattern_summary": r.pattern_summary,
                "tools_called": r.tools_called,
                "generated_at": r.generated_at.isoformat(),
            }
            for r in reports
        ],
    }


@router.get("/intel/briefing")
async def get_threat_briefing(
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an AI-powered threat intelligence briefing from recent events.

    Returns a concise 3-sentence analysis produced by the Groq LLM, using the
    same 5-minute metrics as the /stats endpoint to ensure consistency.
    """
    now = datetime.now(UTC)
    t_5m = now - timedelta(minutes=5)
    t_1h = now - timedelta(hours=1)

    # Fetch recent events
    query = (
        select(AttackEvent)
        .order_by(AttackEvent.timestamp.desc())
        .limit(20)
    )
    result = await db.execute(query)
    events = result.scalars().all()

    # Compute same 5-min metrics used by /stats
    peak_q = select(func.max(AttackEvent.packet_rate)).where(
        AttackEvent.timestamp >= t_5m
    )
    avg_sev_q = select(func.avg(AttackEvent.severity_score)).where(
        AttackEvent.timestamp >= t_5m
    )
    peak_result, avg_sev_result = await db.execute(peak_q), await db.execute(avg_sev_q)
    peak_packet_rate: int = peak_result.scalar() or 0
    avg_severity: float = round(float(avg_sev_result.scalar() or 0), 1)

    # Fetch last 10 incident reports generated in the past 1 hour
    incidents_q = (
        select(IncidentReport)
        .where(IncidentReport.generated_at >= t_1h)
        .order_by(IncidentReport.generated_at.desc())
        .limit(10)
    )
    incidents_result = await db.execute(incidents_q)
    incidents = incidents_result.scalars().all()

    incident_dicts = [
        {
            "source_ip": r.source_ip,
            "attack_type": r.attack_type,
            "severity_score": r.severity_score,
            "threat_level": r.threat_level,
            "is_repeat_attacker": r.is_repeat_attacker,
            "campaign_detected": r.campaign_detected,
            "pattern_summary": r.pattern_summary,
            "recommended_action": r.recommended_action,
            "generated_at": r.generated_at.isoformat() if r.generated_at else "",
        }
        for r in incidents
    ]

    event_dicts = [await _event_with_country(e, db) for e in events]

    briefing = await generate_threat_briefing(
        event_dicts,
        peak_packet_rate=peak_packet_rate,
        avg_severity=avg_severity,
        recent_incidents=incident_dicts,
    )

    return {
        "briefing": briefing,
        "generated_at": now.isoformat(),
        "event_count": len(event_dicts),
        "peak_packet_rate": peak_packet_rate,
        "avg_severity": avg_severity,
        "incident_count": len(incident_dicts),
        "repeat_attackers": sum(1 for i in incident_dicts if i["is_repeat_attacker"]),
        "campaigns_detected": sum(1 for i in incident_dicts if i["campaign_detected"]),
    }


@router.websocket("/ws/attacks")
async def websocket_attacks(
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db),
) -> None:
    """WebSocket endpoint that streams attack events to connected clients."""
    await manager.connect(websocket)
    try:
        query = (
            select(AttackEvent)
            .order_by(AttackEvent.timestamp.desc())
            .limit(50)
        )
        result = await db.execute(query)
        initial_events = result.scalars().all()

        arcs = [
            {**attack_to_arc(e), "timestamp": e.timestamp.isoformat()}
            for e in reversed(initial_events)
        ]
        await websocket.send_json({"type": "initial", "attacks": arcs, "count": len(arcs)})

        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


def get_connection_manager() -> ConnectionManager:
    return manager
