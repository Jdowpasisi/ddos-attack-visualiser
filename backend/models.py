"""
SQLAlchemy models for the DDoS Attack Map application.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class AttackEvent(Base):
    """
    Model representing a DDoS attack event.
    
    Attributes:
        id: Primary key, auto-incremented.
        timestamp: UTC timestamp of when the attack was detected.
        source_ip: IP address of the attack source.
        target_ip: IP address of the attack target.
        source_lat: Latitude of the source location.
        source_lon: Longitude of the source location.
        target_lat: Latitude of the target location.
        target_lon: Longitude of the target location.
        attack_type: Type of DDoS attack (e.g., SYN flood, UDP flood, HTTP flood).
        packet_rate: Number of packets per second.
        severity_score: Severity score of the attack (0.0 - 10.0).
    """
    __tablename__ = "attack_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_lat: Mapped[float] = mapped_column(Float, nullable=False)
    source_lon: Mapped[float] = mapped_column(Float, nullable=False)
    target_lat: Mapped[float] = mapped_column(Float, nullable=False)
    target_lon: Mapped[float] = mapped_column(Float, nullable=False)
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    packet_rate: Mapped[int] = mapped_column(Integer, nullable=False)
    severity_score: Mapped[float] = mapped_column(Float, nullable=False)

    def __repr__(self) -> str:
        return (
            f"<AttackEvent(id={self.id}, "
            f"source_ip='{self.source_ip}', "
            f"target_ip='{self.target_ip}', "
            f"attack_type='{self.attack_type}', "
            f"severity_score={self.severity_score})>"
        )
