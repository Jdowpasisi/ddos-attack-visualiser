"""
Ingestion service for DDoS attack data.

Fetches or generates threat data, enriches it with geo-location,
scores it using the ML model, and persists to the database.
"""

import asyncio
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

from database import async_session_maker  # noqa: E402
from ml.predictor import Protocol, predict_threat  # noqa: E402
from models import AttackEvent  # noqa: E402
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

            # HYBRID FALLBACK: Pad with mock data if real feeds are limited
            MIN_THREATS_FOR_DEMO = 20
            if len(threats) < MIN_THREATS_FOR_DEMO:
                padding_needed = MIN_THREATS_FOR_DEMO - len(threats)
                print(
                    f"  [HYBRID] Feed limit reached. Padding with {padding_needed} simulated events for demo."
                )
                for _ in range(padding_needed):
                    mock_threat = generate_mock_threat(target_weights)
                    mock_threat["is_simulated"] = True  # Mark as simulated
                    threats.append(mock_threat)
                    await asyncio.sleep(0.01)

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

    Args:
        threat: Raw threat dictionary.
        geo_service: Geo service for IP resolution.

    Returns:
        Enriched threat dictionary with coordinates.
    """
    # Resolve source and target IPs to coordinates
    source_geo = await geo_service.resolve(threat["source_ip"])
    target_geo = await geo_service.resolve(threat["target_ip"])

    threat["source_lat"] = source_geo.lat
    threat["source_lon"] = source_geo.lon
    threat["source_country"] = source_geo.country

    threat["target_lat"] = target_geo.lat
    threat["target_lon"] = target_geo.lon
    threat["target_country"] = target_geo.country

    return threat


def score_threat(threat: dict) -> float:
    """
    Score the threat using the ML model (synchronous, CPU-bound).

    Args:
        threat: Threat dictionary with packet_rate and protocol_id.

    Returns:
        Severity score between 0 and 10.
    """
    # Get probability from ML model (0-1)
    probability = predict_threat(
        packet_rate=threat["packet_rate"], protocol_id=threat["protocol_id"]
    )

    # Calculate rate bonus based on packet rate
    packet_rate = threat["packet_rate"]
    if packet_rate > 100000:
        rate_bonus = min(2.0, (packet_rate - 100000) / 200000 * 2)
    elif packet_rate > 50000:
        rate_bonus = 1.0
    elif packet_rate > 20000:
        rate_bonus = 0.5
    else:
        rate_bonus = 0.0

    # Convert to severity score (0-10)
    base_score = probability * 8.0  # Base score up to 8
    severity_score = min(10.0, base_score + rate_bonus)

    return round(severity_score, 2)


async def score_threat_async(threat: dict) -> float:
    """
    Async wrapper for ML scoring - runs in thread pool to avoid blocking.

    This prevents CPU-bound scikit-learn/numpy operations from
    blocking the async event loop.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_ml_thread_pool, score_threat, threat)


async def process_and_store_threat(
    threat: dict, db_session: AsyncSession, geo_service: GeoService
) -> AttackEvent:
    """
    Process a single threat: enrich, score, and store.

    Args:
        threat: Raw threat dictionary.
        db_session: Database session.
        geo_service: Geo service for IP resolution.

    Returns:
        Created AttackEvent record.
    """
    # Enrich with geo data
    enriched = await enrich_threat_with_geo(threat, geo_service)

    # Score the threat (runs in thread pool to avoid blocking)
    severity_score = await score_threat_async(enriched)

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
    )

    db_session.add(attack_event)

    return attack_event


async def ingest_threats(count: int = 10, use_real_feeds: bool = None) -> list[AttackEvent]:
    """
    Main ingestion pipeline: fetch, enrich, score, and store threats.

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

    # Process and store each threat
    created_events = []

    async with async_session_maker() as session:
        for threat in threats:
            try:
                event = await process_and_store_threat(
                    threat=threat, db_session=session, geo_service=geo_service
                )
                created_events.append(event)

                print(
                    f"  [{event.attack_type}] {event.source_ip} -> {event.target_ip} | "
                    f"Rate: {event.packet_rate:,} pps | Severity: {event.severity_score}"
                )

            except Exception as e:
                print(f"  Error processing threat: {e}")

        # Commit all events
        await session.commit()

        # Refresh to get IDs
        for event in created_events:
            await session.refresh(event)

    print(f"\nIngested {len(created_events)} attack events.")

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
