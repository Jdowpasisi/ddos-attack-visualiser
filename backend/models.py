"""
SQLAlchemy models for the DDoS Attack Map application.
"""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
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
    is_simulated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )

    def __repr__(self) -> str:
        return (
            f"<AttackEvent(id={self.id}, "
            f"source_ip='{self.source_ip}', "
            f"target_ip='{self.target_ip}', "
            f"attack_type='{self.attack_type}', "
            f"severity_score={self.severity_score})>"
        )


class IPReputation(Base):
    """
    Persistent cache for IP reputation data from AbuseIPDB (or mock source).

    Attributes:
        ip: IPv4/IPv6 address (primary key).
        abuse_score: AbuseIPDB confidence-of-abuse score (0-100).
        country_code: Two-letter ISO country code.
        isp: Internet service provider name.
        domain: Domain associated with the IP.
        total_reports: Number of abuse reports on record.
        source: Data origin ('abuseipdb' or 'mock').
        last_fetched: UTC timestamp of when the record was last refreshed.
    """

    __tablename__ = "ip_reputation"

    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    abuse_score: Mapped[int] = mapped_column(Integer, nullable=False)
    country_code: Mapped[str] = mapped_column(String(10), nullable=True)
    isp: Mapped[str] = mapped_column(String(200), nullable=True)
    domain: Mapped[str] = mapped_column(String(200), nullable=True)
    total_reports: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(50), nullable=False)  # 'abuseipdb'|'mock'
    last_fetched: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    def is_fresh(self, max_age_days: int = 7) -> bool:
        """Checks if the record is fresh enough to trust."""
        if self.last_fetched.tzinfo is None:
            # Handle naive datetimes if necessary, though we prefer aware
            age = datetime.now(UTC) - self.last_fetched.replace(tzinfo=UTC)
        else:
            age = datetime.now(UTC) - self.last_fetched
        return age.days < max_age_days

    def __repr__(self) -> str:
        return (
            f"<IPReputation(ip='{self.ip}', "
            f"abuse_score={self.abuse_score}, "
            f"source='{self.source}')>"
        )


class IncidentReport(Base):
    """
    AI-generated incident report synthesised from attack event data and tool outputs.

    Attributes:
        id: Primary key, auto-incremented.
        attack_event_id: Foreign key referencing the originating AttackEvent.
        source_ip: IP address of the attack source (denormalised for fast access).
        attack_type: Type of DDoS attack at time of report generation.
        severity_score: Severity score recorded at time of report generation (0.0 - 10.0).
        ip_reputation_summary: Raw output from the IP-reputation tool.
        cve_findings: Raw output from the CVE / vulnerability-lookup tool.
        trend_context: Raw output from the threat-trend context tool.
        threat_level: Agent-assigned threat level (e.g. 'low', 'medium', 'high', 'critical').
        summary: Narrative summary produced by the agent.
        recommended_action: Actionable recommendation produced by the agent.
        tools_called: Comma-separated list of tool names invoked during synthesis.
        generated_at: UTC timestamp of when this report was created.
    """

    __tablename__ = "incident_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    attack_event_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("attack_events.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Denormalised attack context
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Tool outputs
    ip_reputation_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_findings: Mapped[str | None] = mapped_column(Text, nullable=True)
    trend_context: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Agent synthesis
    threat_level: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    is_repeat_attacker: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    campaign_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pattern_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Metadata
    tools_called: Mapped[str | None] = mapped_column(String(500), nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentReport(id={self.id}, "
            f"attack_event_id={self.attack_event_id}, "
            f"threat_level='{self.threat_level}', "
            f"generated_at='{self.generated_at}')>"
        )
