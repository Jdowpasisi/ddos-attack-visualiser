"""
Ingestion service for DDoS attack data.

Fetches or generates threat data, enriches it with geo-location,
scores it using the ML model, and persists to the database.
"""

import asyncio
import json
import logging
import os
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession

# Add backend to path for imports (must be before local imports)
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

from agents.threat_investigator import investigate_threat  # noqa: E402
from api.routes import attack_to_arc, get_connection_manager  # noqa: E402
from database import async_session_maker  # noqa: E402
from ml.predictor import Protocol, score_threat  # noqa: E402
from models import AttackEvent, IncidentReport  # noqa: E402

try:
    from groq import RateLimitError as GroqRateLimitError
    from groq import AuthenticationError as GroqAuthError
    from groq import APIConnectionError as GroqConnectionError
except ImportError:  # pragma: no cover
    GroqRateLimitError = Exception  # type: ignore[assignment,misc]
    GroqAuthError = Exception       # type: ignore[assignment,misc]
    GroqConnectionError = Exception # type: ignore[assignment,misc]
from services.feeds import (  # noqa: E402
    ThreatIndicator,
    fetch_abuseipdb_threats,
    fetch_cloudflare_targets,
    get_feed_service,
    get_real_threat_ips,
)
from services.geo import (  # noqa: E402
    GeoService,
    get_geo_service,
)

# Thread pool for CPU-bound ML inference (prevents blocking async event loop)
_ml_thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ml_inference")

# Severity threshold above which an autonomous investigation is triggered
INVESTIGATION_THRESHOLD: float = float(os.getenv("INVESTIGATION_THRESHOLD", "8.0"))

# Minimum seconds between consecutive investigations (rate-limit guard)
INVESTIGATION_COOLDOWN_SECONDS: float = float(os.getenv("INVESTIGATION_COOLDOWN_SECONDS", "60"))
_last_investigation_at: float = 0.0  # module-level timestamp


def classify_severity(score: float, is_repeat: bool) -> str:
    """Fallback programmatic classification if LLM fails to provide a valid threat_level."""
    if score >= 8:   base = 'CRITICAL'
    elif score >= 6: base = 'HIGH'
    elif score >= 4: base = 'MEDIUM'
    else:            base = 'LOW'

    if not is_repeat:
        return base

    # Apply escalation for repeat attackers
    tier = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    return tier[min(tier.index(base) + 1, 3)]


async def _run_and_store_investigation(event_id: int, event_data: dict) -> None:
    """
    Background task: run the threat investigator agent and persist the result
    as an IncidentReport row.

    Designed to be launched with asyncio.create_task so it never blocks the
    ingestion pipeline.
    """
    try:
        report = await investigate_threat(event_data)
    except GroqRateLimitError as exc:
        logger.warning(
            "Groq rate limit hit for event %d — storing placeholder report. %s",
            event_id, exc,
        )
        report = {
            "threat_level": "high",
            "summary": (
                f"Investigation rate-limited by Groq API. "
                f"Attack: {event_data.get('attack_type')} from "
                f"{event_data.get('source_ip')} "
                f"(severity {event_data.get('severity_score', '?')}). "
                "Manual review recommended."
            ),
            "recommended_action": "Review manually — AI analysis unavailable due to API quota.",
            "tools_called": None,
        }
    except GroqAuthError as exc:
        logger.error(
            "Groq authentication failed for event %d — check GROQ_API_KEY. %s",
            event_id, exc,
        )
        report = {
            "threat_level": "unknown",
            "summary": (
                f"Investigation failed: Groq API key invalid or unauthorised. "
                f"Attack: {event_data.get('attack_type')} from "
                f"{event_data.get('source_ip')}. Verify GROQ_API_KEY in .env."
            ),
            "recommended_action": "Check GROQ_API_KEY is valid and not expired.",
            "tools_called": None,
        }
    except GroqConnectionError as exc:
        logger.error(
            "Groq connection error for event %d: %s", event_id, exc,
        )
        report = {
            "threat_level": "unknown",
            "summary": (
                f"Investigation failed: cannot reach Groq API. "
                f"Attack: {event_data.get('attack_type')} from "
                f"{event_data.get('source_ip')}."
            ),
            "recommended_action": "Check network connectivity and Groq API status.",
            "tools_called": None,
        }
    except Exception as exc:
        logger.error(
            "Threat investigation failed for event %d: %s", event_id, exc, exc_info=True
        )
        return

    # Safely extract and validate the threat level
    raw_threat_level = report.get("threat_level", "UNKNOWN").upper()
    is_repeat = report.get("is_repeat_attacker", False)

    if raw_threat_level not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        print(f"[Investigator] Invalid or missing threat level '{raw_threat_level}', applying fallback classification.")
        validated_threat_level = classify_severity(event_data["severity_score"], is_repeat)
    else:
        validated_threat_level = raw_threat_level

    try:
        async with async_session_maker() as session:
            incident = IncidentReport(
                attack_event_id=event_id,
                source_ip=event_data["source_ip"],
                attack_type=event_data["attack_type"],
                severity_score=event_data["severity_score"],
                ip_reputation_summary=json.dumps(report.get("ip_reputation_summary"))
                if report.get("ip_reputation_summary") is not None
                else None,
                cve_findings=json.dumps(report.get("cve_findings"))
                if report.get("cve_findings") is not None
                else None,
                trend_context=json.dumps(report.get("trend_context"))
                if report.get("trend_context") is not None
                else None,
                threat_level=validated_threat_level,
                summary=report.get("summary", ""),
                recommended_action=report.get("recommended_action", ""),
                is_repeat_attacker=bool(report.get("is_repeat_attacker", False)),
                campaign_detected=bool(report.get("campaign_detected", False)),
                pattern_summary=report.get("pattern_summary") or None,
                tools_called=report.get("tools_called"),
            )
            session.add(incident)
            await session.commit()
            logger.info(
                "IncidentReport created for AttackEvent %d (threat_level=%s)",
                event_id,
                incident.threat_level,
            )
    except Exception as exc:
        logger.error(
            "Failed to persist IncidentReport for event %d: %s", event_id, exc, exc_info=True
        )


# Attack type definitions with associated protocols
ATTACK_TYPES = {
    "syn_flood": {"protocol": Protocol.TCP, "name": "SYN Flood"},
    "udp_flood": {"protocol": Protocol.UDP, "name": "UDP Flood"},
    "icmp_flood": {"protocol": Protocol.ICMP, "name": "ICMP Flood"},
    "http_flood": {"protocol": Protocol.HTTP, "name": "HTTP Flood"},
    "https_flood": {"protocol": Protocol.HTTPS, "name": "HTTPS Flood"},
    "dns_amplification": {"protocol": Protocol.DNS, "name": "DNS Amplification"},
    "ntp_amplification": {"protocol": Protocol.UDP, "name": "NTP Amplification"},
    "memcached_amplification": {"protocol": Protocol.UDP, "name": "Memcached Amplification"},
    "slowloris": {"protocol": Protocol.HTTP, "name": "Slowloris"},
    "ssdp_amplification": {"protocol": Protocol.UDP, "name": "SSDP Amplification"},
}

# Use real threat data by default (falls back to mock if feed unavailable)
USE_REAL_FEEDS = True

# AbuseIPDB API key (set via environment variable)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Common source IP prefixes for mock data (global botnet distribution)
SOURCE_IP_PREFIXES = [
    "1.",
    "27.",
    "36.",
    "49.",
    "61.",  # Asia
    "77.",
    "89.",
    "5.",
    "31.",  # Europe/Russia
    "138.",
    "179.",
    "152.",  # South America
    "41.",
    "102.",
    "196.",  # Africa
]

# Target IP prefixes (typically data centers, cloud providers)
TARGET_IP_PREFIXES = [
    "8.",
    "12.",
    "17.",
    "32.",
    "44.",  # US data centers
    "46.",
    "5.",
    "31.",  # EU data centers
    "103.",
    "14.",
    "101.",  # APAC data centers
]

# Country code to IP prefix mapping for weighted target selection
COUNTRY_IP_PREFIXES: dict[str, list[str]] = {
    "US": ["8.", "12.", "17.", "32.", "44."],
    "CN": ["1.", "36.", "58.", "60.", "106."],
    "DE": ["5.", "46.", "78.", "91."],
    "GB": ["46.", "81.", "82.", "86."],
    "FR": ["2.", "5.", "80.", "90."],
    "JP": ["14.", "27.", "59.", "126."],
    "KR": ["1.", "14.", "59.", "121."],
    "RU": ["5.", "77.", "78.", "89."],
    "BR": ["138.", "143.", "152.", "177.", "179."],
    "IN": ["14.", "27.", "49.", "59."],
    "NL": ["31.", "37.", "77.", "82."],
    "SG": ["1.", "27.", "103.", "118."],
    "AU": ["1.", "27.", "49.", "101.", "103."],
    "CA": ["24.", "65.", "67.", "70.", "99."],
    "IT": ["2.", "5.", "79.", "80."],
    "ES": ["2.", "5.", "79.", "81."],
    "PL": ["5.", "31.", "46.", "77."],
    "UA": ["5.", "31.", "37.", "46."],
    "ID": ["27.", "36.", "103.", "114."],
    "VN": ["1.", "14.", "27.", "42."],
}

# Cached Cloudflare targets for synchronous access
_cloudflare_targets_cache: list[tuple[str, float]] = []
_cloudflare_targets_initialized = False


def generate_random_ip(prefixes: list[str]) -> str:
    """Generate a random IP address with given prefix."""
    prefix = random.choice(prefixes)
    # Complete the IP based on prefix format
    parts_needed = 4 - prefix.count(".")
    remaining = ".".join(str(random.randint(1, 254)) for _ in range(parts_needed))
    return f"{prefix}{remaining}"


def weighted_random_choice(choices: list[tuple[str, float]]) -> str:
    """
    Select a random item based on weights.

    Args:
        choices: List of (item, weight) tuples. Weights should sum to ~1.0.

    Returns:
        Selected item string.
    """
    if not choices:
        return "US"  # Default fallback

    items = [c[0] for c in choices]
    weights = [c[1] for c in choices]

    return random.choices(items, weights=weights, k=1)[0]


def generate_weighted_target_ip(target_weights: list[tuple[str, float]] = None) -> tuple[str, str]:
    """
    Generate a target IP based on Cloudflare Radar attack distribution.

    Args:
        target_weights: Optional list of (country_code, weight) tuples.
                       If None, uses random selection from TARGET_IP_PREFIXES.

    Returns:
        Tuple of (target_ip, country_code).
    """
    global _cloudflare_targets_cache

    # Use provided weights, cached weights, or fall back to random
    weights = target_weights or _cloudflare_targets_cache

    if weights:
        # Select country based on weights
        country_code = weighted_random_choice(weights)

        # Get IP prefixes for this country (or use defaults)
        prefixes = COUNTRY_IP_PREFIXES.get(country_code, TARGET_IP_PREFIXES)
        target_ip = generate_random_ip(prefixes)

        return target_ip, country_code
    else:
        # Fallback to random selection
        target_ip = generate_random_ip(TARGET_IP_PREFIXES)
        return target_ip, "US"  # Default assumption


# Malware family to attack type mapping
MALWARE_ATTACK_MAPPING = {
    "Dridex": {
        "attack_type": "HTTP Flood",
        "protocol": Protocol.HTTPS,
        "rate_range": (5000, 30000),
    },
    "Emotet": {
        "attack_type": "HTTP Flood",
        "protocol": Protocol.HTTP,
        "rate_range": (10000, 50000),
    },
    "QakBot": {
        "attack_type": "HTTPS Flood",
        "protocol": Protocol.HTTPS,
        "rate_range": (8000, 40000),
    },
    "Pikabot": {"attack_type": "SYN Flood", "protocol": Protocol.TCP, "rate_range": (20000, 80000)},
    "BumbleBee": {
        "attack_type": "UDP Flood",
        "protocol": Protocol.UDP,
        "rate_range": (30000, 100000),
    },
    "IcedID": {
        "attack_type": "DNS Amplification",
        "protocol": Protocol.DNS,
        "rate_range": (50000, 200000),
    },
    "TrickBot": {
        "attack_type": "SYN Flood",
        "protocol": Protocol.TCP,
        "rate_range": (15000, 60000),
    },
    "Unknown": {"attack_type": "UDP Flood", "protocol": Protocol.UDP, "rate_range": (10000, 50000)},
    # AbuseIPDB attack types
    "UDP Flood": {
        "attack_type": "UDP Flood",
        "protocol": Protocol.UDP,
        "rate_range": (30000, 100000),
    },
    "SSH Brute Force": {
        "attack_type": "SSH Brute Force",
        "protocol": Protocol.TCP,
        "rate_range": (1000, 5000),
    },
    "Port Scanning": {
        "attack_type": "Port Scanning",
        "protocol": Protocol.TCP,
        "rate_range": (500, 2000),
    },
    "Malicious Traffic": {
        "attack_type": "Malicious Traffic",
        "protocol": Protocol.TCP,
        "rate_range": (5000, 20000),
    },
}


def generate_mock_threat(target_weights: list[tuple[str, float]] = None) -> dict:
    """
    Generate a single mock threat event.

    Args:
        target_weights: Optional weighted country distribution for targets.

    Returns:
        Dictionary with threat data.
    """
    # Pick attack type
    attack_key = random.choice(list(ATTACK_TYPES.keys()))
    attack_info = ATTACK_TYPES[attack_key]

    # Generate IPs
    source_ip = generate_random_ip(SOURCE_IP_PREFIXES)
    target_ip, target_country = generate_weighted_target_ip(target_weights)

    # Generate packet rate based on attack type
    # Different attacks have different typical rates
    if attack_key in ["dns_amplification", "ntp_amplification", "memcached_amplification"]:
        # Amplification attacks: very high rates
        packet_rate = random.randint(50000, 500000)
    elif attack_key in ["syn_flood", "udp_flood", "icmp_flood"]:
        # Volumetric attacks: high rates
        packet_rate = random.randint(10000, 100000)
    elif attack_key == "slowloris":
        # Slowloris: low packet rate, but persistent
        packet_rate = random.randint(50, 500)
    else:
        # Other attacks: moderate rates
        packet_rate = random.randint(5000, 50000)

    return {
        "timestamp": datetime.now(UTC),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_country": target_country,
        "attack_type": attack_info["name"],
        "protocol_id": attack_info["protocol"],
        "packet_rate": packet_rate,
    }


def generate_threat_from_indicator(
    indicator: ThreatIndicator, target_weights: list[tuple[str, float]] = None
) -> dict:
    """
    Generate a threat event from a real threat indicator.

    Uses the malware family to determine attack characteristics.

    Args:
        indicator: ThreatIndicator from the feed service.
        target_weights: Optional weighted country distribution for targets.

    Returns:
        Dictionary with threat data.
    """
    # Get attack characteristics based on malware family
    malware = indicator.malware_family or "Unknown"
    attack_config = MALWARE_ATTACK_MAPPING.get(malware, MALWARE_ATTACK_MAPPING["Unknown"])

    # Generate packet rate within the malware's typical range
    rate_min, rate_max = attack_config["rate_range"]
    packet_rate = random.randint(rate_min, rate_max)

    # Generate a weighted target IP based on Cloudflare data
    target_ip, target_country = generate_weighted_target_ip(target_weights)

    return {
        "timestamp": datetime.now(UTC),
        "source_ip": indicator.ip,
        "target_ip": target_ip,
        "target_country": target_country,
        "attack_type": attack_config["attack_type"],
        "protocol_id": attack_config["protocol"],
        "packet_rate": packet_rate,
        "malware_family": malware,
        "source_port": indicator.port,
        "is_real_threat": True,
    }


async def fetch_live_threats(count: int = 10, use_real_feeds: bool = None) -> list[dict]:
    """
    Fetch live threat data from real feeds or generate mock data.

    Connects to multiple threat intelligence sources:
    - Feodo Tracker (abuse.ch) for botnet C2 IPs
    - AbuseIPDB for high-confidence malicious IPs (if API key configured)
    - Cloudflare Radar for weighted target country distribution

    Falls back to mock data if feeds are unavailable.

    Args:
        count: Number of threat events to generate.
        use_real_feeds: Override global USE_REAL_FEEDS setting.

    Returns:
        List of threat event dictionaries.
    """
    global _cloudflare_targets_cache, _cloudflare_targets_initialized

    should_use_real = use_real_feeds if use_real_feeds is not None else USE_REAL_FEEDS
    threats = []
    all_indicators: list[ThreatIndicator] = []

    # Fetch Cloudflare target weights (for realistic attack distribution)
    target_weights = []
    try:
        target_weights = await fetch_cloudflare_targets()
        if target_weights:
            _cloudflare_targets_cache = target_weights
            _cloudflare_targets_initialized = True
            print(f"  Cloudflare Radar: {len(target_weights)} target countries loaded")
    except Exception as e:
        print(f"  Cloudflare Radar error: {e}")
        target_weights = _cloudflare_targets_cache  # Use cached data

    if should_use_real:
        # Calculate split between sources
        feodo_count = count // 2 + count % 2  # Give Feodo the majority
        abuseipdb_count = count // 2

        # Fetch from Feodo Tracker
        try:
            feodo_indicators = await get_real_threat_ips(count=feodo_count)
            if feodo_indicators:
                print(f"  Feodo Tracker: {len(feodo_indicators)} indicators")
                all_indicators.extend(feodo_indicators)
        except Exception as e:
            print(f"  Feodo Tracker error: {e}")

        # Fetch from AbuseIPDB (if API key is configured)
        if ABUSEIPDB_API_KEY:
            try:
                abuseipdb_indicators = await fetch_abuseipdb_threats(
                    api_key=ABUSEIPDB_API_KEY, limit=abuseipdb_count
                )
                if abuseipdb_indicators:
                    print(f"  AbuseIPDB: {len(abuseipdb_indicators)} indicators")
                    all_indicators.extend(abuseipdb_indicators)
            except Exception as e:
                print(f"  AbuseIPDB error: {e}")
        else:
            print("  AbuseIPDB: Skipped (no API key configured)")

        # Convert indicators to threats (using weighted targets)
        if all_indicators:
            print(f"  Combined: {len(all_indicators)} total indicators from real feeds")

            # Shuffle to mix sources
            random.shuffle(all_indicators)

            for indicator in all_indicators[:count]:
                threat = generate_threat_from_indicator(indicator, target_weights)
                threats.append(threat)
                await asyncio.sleep(0.01)  # Vary timestamps

            # Check if we need to pad with simulated events
            MIN_REAL_EVENTS_PER_BATCH = int(os.getenv("MIN_REAL_EVENTS_PER_BATCH", "5"))

            if len(threats) < MIN_REAL_EVENTS_PER_BATCH:
                padding_needed = MIN_REAL_EVENTS_PER_BATCH - len(threats)
                print(
                    f"  [HYBRID] {len(threats)} real events this cycle — padding with {padding_needed} simulated to reach minimum batch size."
                )
                for _ in range(padding_needed):
                    mock_threat = generate_mock_threat(target_weights)
                    mock_threat["is_simulated"] = True
                    threats.append(mock_threat)
            else:
                print(f"  [REAL] {len(threats)} live threat events — no padding needed.")

            return threats
        else:
            print("  No real indicators available, falling back to mock data")

    # Fallback to mock data (using weighted targets)
    for _ in range(count):
        threat = generate_mock_threat(target_weights)
        threats.append(threat)
        await asyncio.sleep(0.01)

    return threats


async def enrich_threat_with_geo(threat: dict, geo_service: GeoService) -> dict:
    """
    Enrich threat data with geographic coordinates.

    If the threat dict already contains pre-cached 'source_geo' and 'target_geo'
    keys (from batch caching), those are used directly. Otherwise, falls back
    to geo service resolution.

    Args:
        threat: Raw threat dictionary.
        geo_service: Geo service for IP resolution.

    Returns:
        Enriched threat dictionary with coordinates.
    """
    # Use pre-cached geo data if available (batch optimization)
    if "source_geo" in threat:
        source_geo = threat["source_geo"]
    else:
        # Fallback: resolve source IP
        source_geo = await geo_service.resolve(threat["source_ip"])

    if "target_geo" in threat:
        target_geo = threat["target_geo"]
    else:
        # Fallback: resolve target IP
        target_geo = await geo_service.resolve(threat["target_ip"])

    threat["source_lat"] = source_geo.lat
    threat["source_lon"] = source_geo.lon
    threat["source_country"] = source_geo.country

    threat["target_lat"] = target_geo.lat
    threat["target_lon"] = target_geo.lon
    threat["target_country"] = target_geo.country

    return threat


async def score_threat_async(threat: dict) -> float:
    """
    Async wrapper for ML scoring - runs in thread pool to avoid blocking.

    This prevents CPU-bound scikit-learn/numpy operations from
    blocking the async event loop.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_ml_thread_pool, score_threat, threat)


async def process_and_store_threat(
    threat: dict,
    db_session: AsyncSession,
    geo_service: GeoService,
    pending_investigations: list | None = None,
) -> AttackEvent:
    """
    Process a single threat: enrich, score, and store.

    Enrichment now includes an IP reputation lookup that is cached in the
    ``ip_reputation`` table so that subsequent ingestions for the same
    source IP avoid redundant AbuseIPDB API calls.

    Additionally supports batch-level caching where reputation data is
    pre-fetched and attached to the threat dict as 'reputation' key.

    Args:
        threat: Raw threat dictionary.
        db_session: Database session.
        geo_service: Geo service for IP resolution.

    Returns:
        Created AttackEvent record.
    """
    # Enrich with geo data (uses pre-cached data if available)
    enriched = await enrich_threat_with_geo(threat, geo_service)

    # Look up source-IP reputation from the bulk-cached blacklist database
    reputation: dict | None = None
    
    # Use pre-cached reputation if available (batch optimization)
    if "reputation" in threat:
        reputation = threat["reputation"]
    else:
        # Fallback: fetch reputation data
        try:
            feed_service = get_feed_service()
            reputation = await feed_service.get_ip_reputation(
                ip=enriched["source_ip"],
                db=db_session,
                api_key=ABUSEIPDB_API_KEY or None,
            )
            
            if reputation is None:
                # IP not found in blacklist database - treat as neutral/unknown
                # This is normal for IPs that haven't been reported to AbuseIPDB
                pass  # Continue with base ML/geo scoring only
            
        except Exception as exc:
            # Never let a reputation lookup failure break the pipeline
            print(f"  Reputation lookup error for {enriched['source_ip']}: {exc}")
            reputation = None  # Treat as neutral on error

    # Score the threat using ML model (runs in thread pool to avoid blocking)
    severity_score = await score_threat_async(enriched)

    # Apply reputation bonus if IP is confirmed high-risk in AbuseIPDB
    if reputation is not None:
        abuse_score = reputation.get("abuse_score", 0)
        if abuse_score >= 75:
            # High-confidence malicious IP: boost severity by up to +2.0
            abuse_bonus = min(2.0, abuse_score / 100 * 2)
            severity_score = min(10.0, round(severity_score + abuse_bonus, 2))
        # IPs with abuse_score < 75 get no bonus (treated as neutral)

    # Create database record
    attack_event = AttackEvent(
        timestamp=enriched["timestamp"],
        source_ip=enriched["source_ip"],
        target_ip=enriched["target_ip"],
        source_lat=enriched["source_lat"],
        source_lon=enriched["source_lon"],
        target_lat=enriched["target_lat"],
        target_lon=enriched["target_lon"],
        attack_type=enriched["attack_type"],
        packet_rate=enriched["packet_rate"],
        severity_score=severity_score,
        is_simulated=threat.get("is_simulated", False),
    )

    db_session.add(attack_event)
    await db_session.flush()  # Populate attack_event.id without committing

    try:
        arc_data = attack_to_arc(attack_event)
        manager = get_connection_manager()
        asyncio.create_task(manager.broadcast({"type": "attack", "attack": arc_data, "backlog": 0}))
    except Exception as _ws_exc:
        logger.debug("WebSocket broadcast skipped: %s", _ws_exc)

    if attack_event.severity_score >= INVESTIGATION_THRESHOLD:
        if pending_investigations is not None:
            # Collect candidate; the batch loop will pick the worst one later.
            pending_investigations.append((attack_event.id, {
                "source_ip": attack_event.source_ip,
                "target_ip": attack_event.target_ip,
                "attack_type": attack_event.attack_type,
                "severity_score": attack_event.severity_score,
                "packet_rate": attack_event.packet_rate,
                "timestamp": attack_event.timestamp.isoformat(),
            }))
        else:
            import time as _time
            global _last_investigation_at
            now_ts = _time.monotonic()
            if now_ts - _last_investigation_at >= INVESTIGATION_COOLDOWN_SECONDS:
                _last_investigation_at = now_ts
                event_data = {
                    "source_ip": attack_event.source_ip,
                    "target_ip": attack_event.target_ip,
                    "attack_type": attack_event.attack_type,
                    "severity_score": attack_event.severity_score,
                    "packet_rate": attack_event.packet_rate,
                    "timestamp": attack_event.timestamp.isoformat(),
                }
                asyncio.create_task(
                    _run_and_store_investigation(attack_event.id, event_data)
                )
                logger.info(
                    "Investigation queued for AttackEvent %d (severity=%.2f)",
                    attack_event.id,
                    attack_event.severity_score,
                )

    return attack_event


async def ingest_threats(count: int = 10, use_real_feeds: bool = None) -> list[AttackEvent]:
    """
    Main ingestion pipeline: fetch, enrich, score, and store threats.

    Implements batch-level caching to avoid duplicate lookups for the same
    IP address within a single batch (e.g., if 3 threats come from the same
    source IP, only 1 reputation/geo lookup is performed).

    Args:
        count: Number of threats to ingest.
        use_real_feeds: Whether to use real threat feeds (None = use global default).

    Returns:
        List of created AttackEvent records.
    """
    # Use ip-api backend for real feeds (with rate limiting and fallbacks)
    # Use mock backend for mock data (faster, no API calls)
    should_use_real = use_real_feeds if use_real_feeds is not None else USE_REAL_FEEDS
    geo_backend = "ip-api" if should_use_real else "mock"
    geo_service = get_geo_service(backend=geo_backend, enable_db_lookup=True)

    # Fetch raw threat data
    feed_type = "real feeds" if should_use_real else "mock data"
    print(f"Fetching {count} threat events ({feed_type}, geo: {geo_backend})...")
    threats = await fetch_live_threats(count=count, use_real_feeds=use_real_feeds)

    # --- BATCH-LEVEL CACHING: Pre-fetch data for unique IPs ---
    # Extract unique IPs from the batch
    unique_source_ips = set(t["source_ip"] for t in threats)
    unique_target_ips = set(t["target_ip"] for t in threats)
    all_unique_ips = unique_source_ips | unique_target_ips

    # Initialize batch caches
    _batch_reputation_cache: dict[str, dict | None] = {}
    _batch_geo_cache: dict[str, object] = {}

    print(f"  Batch: {len(threats)} threats, {len(all_unique_ips)} unique IPs")

    # Process and store each threat
    created_events = []

    async with async_session_maker() as session:
        # Pre-fetch reputation data for all unique source IPs
        feed_service = get_feed_service()
        for source_ip in unique_source_ips:
            if source_ip not in _batch_reputation_cache:
                try:
                    reputation = await feed_service.get_ip_reputation(
                        ip=source_ip,
                        db=session,
                        api_key=ABUSEIPDB_API_KEY or None,
                    )
                    _batch_reputation_cache[source_ip] = reputation
                except Exception as exc:
                    print(f"  Batch reputation lookup error for {source_ip}: {exc}")
                    _batch_reputation_cache[source_ip] = None

        # Pre-fetch geo data for all unique IPs
        for ip in all_unique_ips:
            if ip not in _batch_geo_cache:
                try:
                    geo_data = await geo_service.resolve(ip)
                    _batch_geo_cache[ip] = geo_data
                except Exception as exc:
                    print(f"  Batch geo lookup error for {ip}: {exc}")
                    _batch_geo_cache[ip] = None

        # Attach cached data to threats
        for threat in threats:
            # Attach pre-fetched reputation
            threat["reputation"] = _batch_reputation_cache.get(threat["source_ip"])
            
            # Attach pre-fetched geo data
            threat["source_geo"] = _batch_geo_cache.get(threat["source_ip"])
            threat["target_geo"] = _batch_geo_cache.get(threat["target_ip"])

        # Process each threat (using cached data)
        pending_investigations: list[tuple[int, dict]] = []
        for threat in threats:
            try:
                event = await process_and_store_threat(
                    threat=threat,
                    db_session=session,
                    geo_service=geo_service,
                    pending_investigations=pending_investigations,
                )
                created_events.append(event)

                print(
                    f"  [{event.attack_type}] {event.source_ip} -> {event.target_ip} | "
                    f"Rate: {event.packet_rate:,} pps | Severity: {event.severity_score}"
                )

            except Exception as e:
                print(f"  Error processing threat: {e}")

        # Commit all events — attack_events rows now exist in the DB
        await session.commit()

        # Refresh to get IDs
        for event in created_events:
            await session.refresh(event)

    # Fire investigation tasks only after commit so the FK is satisfied.
    # Pick only the single highest-severity event from this batch to avoid
    # flooding the Groq API and ensure the agent sees the worst offender.
    if pending_investigations:
        import time as _time
        global _last_investigation_at
        now_ts = _time.monotonic()
        if now_ts - _last_investigation_at >= INVESTIGATION_COOLDOWN_SECONDS:
            _last_investigation_at = now_ts
            best_id, best_data = max(
                pending_investigations,
                key=lambda t: t[1]["severity_score"],
            )
            asyncio.create_task(_run_and_store_investigation(best_id, best_data))
            logger.info(
                "Investigation queued for AttackEvent %d (severity=%.2f, batch candidates=%d)",
                best_id, best_data["severity_score"], len(pending_investigations),
            )
        else:
            remaining = INVESTIGATION_COOLDOWN_SECONDS - (now_ts - _last_investigation_at)
            logger.debug(
                "Investigation skipped for entire batch — cooldown active (%.0fs remaining)",
                remaining,
            )

    print(f"\nIngested {len(created_events)} attack events.")
    if pending_investigations:
        print(f"  Queued {len(pending_investigations)} investigation task(s).")


    return created_events


async def run_continuous_ingestion(
    interval_seconds: float = 5.0, batch_size: int = 5, use_real_feeds: bool = None
):
    """
    Run continuous ingestion in a loop.

    Args:
        interval_seconds: Seconds between ingestion batches.
        batch_size: Number of events per batch.
        use_real_feeds: Whether to use real threat feeds.
    """
    feed_type = (
        "real feeds"
        if (use_real_feeds if use_real_feeds is not None else USE_REAL_FEEDS)
        else "mock data"
    )
    print(
        f"Starting continuous ingestion (interval: {interval_seconds}s, batch: {batch_size}, source: {feed_type})"
    )
    print("Press Ctrl+C to stop.\n")

    # Pre-warm the feed cache if using real feeds
    if use_real_feeds or (use_real_feeds is None and USE_REAL_FEEDS):
        print("Pre-warming threat feed cache...")
        feed_service = get_feed_service()
        await feed_service.refresh_cache()
        stats = feed_service.cache_stats
        print(f"  Loaded {stats['total_indicators']} threat indicators\n")

    try:
        while True:
            await ingest_threats(count=batch_size, use_real_feeds=use_real_feeds)
            await asyncio.sleep(interval_seconds)
    except KeyboardInterrupt:
        print("\nIngestion stopped.")
        # Clean up feed service
        if use_real_feeds or (use_real_feeds is None and USE_REAL_FEEDS):
            await get_feed_service().close()


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DDoS threat ingestion service")
    parser.add_argument(
        "--count", "-c", type=int, default=10, help="Number of threats to ingest (default: 10)"
    )
    parser.add_argument("--continuous", action="store_true", help="Run continuous ingestion")
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Interval between batches in continuous mode (default: 5s)",
    )
    parser.add_argument(
        "--mock", action="store_true", help="Use mock data instead of real threat feeds"
    )
    parser.add_argument("--real", action="store_true", help="Force use of real threat feeds")

    args = parser.parse_args()

    # Determine feed source
    use_real = None  # Use global default
    if args.mock:
        use_real = False
    elif args.real:
        use_real = True

    if args.continuous:
        asyncio.run(
            run_continuous_ingestion(
                interval_seconds=args.interval, batch_size=args.count, use_real_feeds=use_real
            )
        )
    else:
        asyncio.run(ingest_threats(count=args.count, use_real_feeds=use_real))
