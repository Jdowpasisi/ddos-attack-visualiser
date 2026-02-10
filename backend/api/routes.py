"""
API routes for DDoS Attack Map visualization.

Provides endpoints optimized for frontend Globe/Map visualization.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AttackEvent

# Create router with prefix
router = APIRouter(prefix="/api/v1", tags=["attacks"])


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


class AttackStatsResponse(BaseModel):
    """Attack statistics response."""

    total_attacks: int
    attacks_by_type: dict[str, int]
    attacks_by_severity: dict[str, int]
    average_severity: float
    average_packet_rate: float
    top_source_countries: list[dict]
    top_target_countries: list[dict]


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
    }


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
        limit: Maximum number of attacks to return.

    Returns:
        New attacks since the given ID, sorted chronologically (oldest first).
    """
    query = (
        select(AttackEvent)
        .where(AttackEvent.id > since_id)
        .order_by(AttackEvent.timestamp.asc())  # Chronological order
        .limit(limit)
    )

    result = await db.execute(query)
    events = result.scalars().all()

    attacks = [attack_to_arc(event) for event in events]

    # Get the max ID for next poll
    latest_id = max((a["id"] for a in attacks), default=since_id)

    return {
        "count": len(attacks),
        "attacks": attacks,
        "latest_id": latest_id,
        "has_more": len(attacks) == limit,  # Indicates if there might be more data
    }


@router.get("/attacks/stats", response_model=AttackStatsResponse)
async def get_attack_statistics(
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated attack statistics.

    Returns:
        Summary statistics for dashboard display.
    """
    # Total count
    total_query = select(func.count(AttackEvent.id))
    total_result = await db.execute(total_query)
    total_count = total_result.scalar() or 0

    # Count by attack type
    type_query = select(
        AttackEvent.attack_type, func.count(AttackEvent.id).label("count")
    ).group_by(AttackEvent.attack_type)
    type_result = await db.execute(type_query)
    attacks_by_type = {row.attack_type: row.count for row in type_result}

    # Count by severity bands
    severity_bands = {"low": 0, "medium": 0, "high": 0, "critical": 0}

    for band, (low, high) in [
        ("low", (0, 3)),
        ("medium", (3, 6)),
        ("high", (6, 8)),
        ("critical", (8, 10)),
    ]:
        band_query = select(func.count(AttackEvent.id)).where(
            AttackEvent.severity_score >= low,
            AttackEvent.severity_score < high
            if band != "critical"
            else AttackEvent.severity_score <= 10,
        )
        band_result = await db.execute(band_query)
        severity_bands[band] = band_result.scalar() or 0

    # Average severity and packet rate
    avg_query = select(func.avg(AttackEvent.severity_score), func.avg(AttackEvent.packet_rate))
    avg_result = await db.execute(avg_query)
    avg_row = avg_result.one()
    avg_severity = float(avg_row[0] or 0)
    avg_packet_rate = float(avg_row[1] or 0)

    return AttackStatsResponse(
        total_attacks=total_count,
        attacks_by_type=attacks_by_type,
        attacks_by_severity=severity_bands,
        average_severity=round(avg_severity, 2),
        average_packet_rate=round(avg_packet_rate, 0),
        top_source_countries=[],  # Would need geo data stored
        top_target_countries=[],
    )


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
