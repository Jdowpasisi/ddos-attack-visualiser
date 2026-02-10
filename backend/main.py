"""
FastAPI application entry point for the DDoS Attack Map.
"""

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager
from datetime import datetime

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.routes import router as api_router
from database import create_tables, get_db
from models import AttackEvent
from services.ingest import ingest_threats

# Load environment variables
load_dotenv()

# Background task control
_ingestion_task: asyncio.Task | None = None
_stop_ingestion = False

# Configuration from environment
INGESTION_INTERVAL_SECONDS = int(os.getenv("INGESTION_INTERVAL_SECONDS", "10"))
INGESTION_BATCH_SIZE = int(os.getenv("INGESTION_BATCH_SIZE", "5"))


async def background_ingestion_loop():
    """
    Background task that continuously ingests threat data.
    Runs every INGESTION_INTERVAL_SECONDS.
    """
    global _stop_ingestion

    print(
        f"Background ingestion started (interval: {INGESTION_INTERVAL_SECONDS}s, batch: {INGESTION_BATCH_SIZE})"
    )

    while not _stop_ingestion:
        try:
            await ingest_threats(count=INGESTION_BATCH_SIZE)
        except Exception as e:
            print(f"Ingestion error: {e}")

        # Wait for next interval
        await asyncio.sleep(INGESTION_INTERVAL_SECONDS)

    print("Background ingestion stopped.")


# Pydantic schemas
class AttackEventBase(BaseModel):
    """Base schema for attack event data."""

    timestamp: datetime
    source_ip: str = Field(..., max_length=45)
    target_ip: str = Field(..., max_length=45)
    source_lat: float = Field(..., ge=-90, le=90)
    source_lon: float = Field(..., ge=-180, le=180)
    target_lat: float = Field(..., ge=-90, le=90)
    target_lon: float = Field(..., ge=-180, le=180)
    attack_type: str = Field(..., max_length=50)
    packet_rate: int = Field(..., ge=0)
    severity_score: float = Field(..., ge=0.0, le=10.0)


class AttackEventCreate(AttackEventBase):
    """Schema for creating a new attack event."""

    pass


class AttackEventResponse(AttackEventBase):
    """Schema for attack event response."""

    id: int

    class Config:
        from_attributes = True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Creates database tables on startup and starts background ingestion.
    """
    global _ingestion_task, _stop_ingestion

    # Startup: Create tables
    await create_tables()
    print("Database tables created successfully.")

    # Start background ingestion task
    _stop_ingestion = False
    _ingestion_task = asyncio.create_task(background_ingestion_loop())

    yield

    # Shutdown: Stop background ingestion
    print("Stopping background ingestion...")
    _stop_ingestion = True
    if _ingestion_task:
        _ingestion_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await _ingestion_task

    print("Application shutting down.")


# Initialize FastAPI app
app = FastAPI(
    title="DDoS Attack Map API",
    description="API for visualizing DDoS attack data on a world map",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API router
app.include_router(api_router)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "ok",
        "message": "DDoS Attack Map API is running",
        "ingestion_active": not _stop_ingestion,
    }


@app.get("/attacks", response_model=list[AttackEventResponse])
async def get_attacks(
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    attack_type: str | None = Query(default=None),
):
    """
    Retrieve attack events with optional filtering.

    Args:
        limit: Maximum number of records to return (1-1000).
        offset: Number of records to skip.
        attack_type: Filter by attack type.

    Returns:
        List of attack events.
    """
    query = select(AttackEvent).order_by(AttackEvent.timestamp.desc())

    if attack_type:
        query = query.where(AttackEvent.attack_type == attack_type)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    attacks = result.scalars().all()

    return attacks


@app.get("/attacks/{attack_id}", response_model=AttackEventResponse)
async def get_attack(attack_id: int, db: AsyncSession = Depends(get_db)):
    """
    Retrieve a specific attack event by ID.

    Args:
        attack_id: The ID of the attack event.

    Returns:
        The attack event if found.

    Raises:
        HTTPException: If the attack event is not found.
    """
    query = select(AttackEvent).where(AttackEvent.id == attack_id)
    result = await db.execute(query)
    attack = result.scalar_one_or_none()

    if not attack:
        raise HTTPException(status_code=404, detail="Attack event not found")

    return attack


@app.post("/attacks", response_model=AttackEventResponse, status_code=201)
async def create_attack(
    attack_data: AttackEventCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new attack event.

    Args:
        attack_data: The attack event data.

    Returns:
        The created attack event.
    """
    attack = AttackEvent(**attack_data.model_dump())
    db.add(attack)
    await db.flush()
    await db.refresh(attack)

    return attack


@app.get("/attacks/stats/summary")
async def get_attack_stats(db: AsyncSession = Depends(get_db)):
    """
    Get summary statistics of attack events.

    Returns:
        Dictionary with attack statistics.
    """
    from sqlalchemy import func

    # Total count
    total_query = select(func.count(AttackEvent.id))
    total_result = await db.execute(total_query)
    total_count = total_result.scalar()

    # Count by attack type
    type_query = select(
        AttackEvent.attack_type, func.count(AttackEvent.id).label("count")
    ).group_by(AttackEvent.attack_type)
    type_result = await db.execute(type_query)
    attacks_by_type = {row.attack_type: row.count for row in type_result}

    # Average severity
    avg_query = select(func.avg(AttackEvent.severity_score))
    avg_result = await db.execute(avg_query)
    avg_severity = avg_result.scalar()

    return {
        "total_attacks": total_count,
        "attacks_by_type": attacks_by_type,
        "average_severity": round(avg_severity, 2) if avg_severity else 0.0,
    }


@app.post("/ingestion/trigger")
async def trigger_ingestion(count: int = Query(default=10, ge=1, le=100)):
    """
    Manually trigger threat ingestion.

    Args:
        count: Number of threats to ingest.

    Returns:
        Number of events ingested.
    """
    try:
        events = await ingest_threats(count=count)
        return {"status": "ok", "ingested": len(events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ingestion/status")
async def ingestion_status():
    """Get background ingestion status."""
    return {
        "active": not _stop_ingestion,
        "interval_seconds": INGESTION_INTERVAL_SECONDS,
        "batch_size": INGESTION_BATCH_SIZE,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
