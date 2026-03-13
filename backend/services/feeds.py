"""
Threat Intelligence Feed Service.

Fetches and caches real threat data from public intelligence feeds.
Currently supports:
- Feodo Tracker Botnet C2 IP Blocklist (abuse.ch)

Implements a 'Cache & Diff' strategy:
- First run: downloads and caches the full feed
- Subsequent runs: returns random samples from cache
- Periodic refresh: updates cache every CACHE_TTL_SECONDS
"""

import asyncio
import csv
import io
import logging
import os
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from dotenv import load_dotenv
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import async_session_maker
from models import IPReputation

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Feed configuration
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CLOUDFLARE_RADAR_L3_URL = (
    "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target"
)

# Free blocklist URLs (no API key required)
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
EMERGING_THREATS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
CINS_ARMY_URL = "http://cinsscore.com/list/ci-badguys.txt"

CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
CACHE_TTL_SECONDS = 300  # Refresh cache every 5 minutes
CLOUDFLARE_CACHE_TTL_SECONDS = 3600  # Cache Cloudflare data for 1 hour
ABUSEIPDB_CACHE_TTL_SECONDS = 1800  # Cache AbuseIPDB data for 30 minutes (rate limit protection)
ABUSEIPDB_FETCH_SIZE = 500        # Always fetch this many from AbuseIPDB to build a rich cache pool
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2.0

# AbuseIPDB category to attack type mapping
ABUSEIPDB_CATEGORY_MAPPING = {
    4: "UDP Flood",  # DDoS Attack
    18: "SSH Brute Force",  # Brute-Force
    15: "Port Scanning",  # Hacking
}
DEFAULT_ABUSEIPDB_ATTACK_TYPE = "Malicious Traffic"


# Cloudflare Radar target cache
@dataclass
class CloudflareTargetCache:
    """Cache for Cloudflare Radar L3 attack target data."""

    targets: list[tuple[str, float]] = field(default_factory=list)  # (country_code, weight)
    last_updated: datetime | None = None

    @property
    def is_valid(self) -> bool:
        if not self.targets or self.last_updated is None:
            return False
        age = (datetime.now(UTC) - self.last_updated).total_seconds()
        return age < CLOUDFLARE_CACHE_TTL_SECONDS


_cloudflare_cache = CloudflareTargetCache()
_cloudflare_lock = asyncio.Lock()


# AbuseIPDB cache
@dataclass
class AbuseIPDBCache:
    """Cache for AbuseIPDB threat data to avoid rate limits."""

    indicators: list = field(default_factory=list)
    last_updated: datetime | None = None

    @property
    def is_valid(self) -> bool:
        if not self.indicators or self.last_updated is None:
            return False
        age = (datetime.now(UTC) - self.last_updated).total_seconds()
        return age < ABUSEIPDB_CACHE_TTL_SECONDS


_abuseipdb_cache = AbuseIPDBCache()
_abuseipdb_lock = asyncio.Lock()


@dataclass
class ThreatIndicator:
    """Represents a single threat indicator from a feed."""

    ip: str
    port: int | None = None
    malware_family: str | None = None
    first_seen: datetime | None = None
    last_online: datetime | None = None
    source_feed: str = "feodo_tracker"

    def __hash__(self):
        return hash((self.ip, self.port, self.source_feed))

    def __eq__(self, other):
        if not isinstance(other, ThreatIndicator):
            return False
        return self.ip == other.ip and self.port == other.port


@dataclass
class FeedCache:
    """Cache container for threat feed data."""

    indicators: list[ThreatIndicator] = field(default_factory=list)
    last_updated: datetime | None = None
    etag: str | None = None
    is_stale: bool = True

    @property
    def is_valid(self) -> bool:
        """Check if cache is valid (not stale and has data)."""
        if not self.indicators or self.is_stale:
            return False
        if self.last_updated is None:
            return False
        age = (datetime.now(UTC) - self.last_updated).total_seconds()
        return age < CACHE_TTL_SECONDS

    @property
    def count(self) -> int:
        """Number of indicators in cache."""
        return len(self.indicators)


class ThreatFeedService:
    """
    Service for fetching and managing threat intelligence feeds.

    Implements caching to avoid hammering external APIs and provides
    random sampling for simulating 'live' traffic detection.
    """

    def __init__(self):
        self._cache = FeedCache()
        self._lock = asyncio.Lock()
        self._http_client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with proper configuration."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
                follow_redirects=True,
                headers={"User-Agent": "DDoS-Visualizer/1.0 (Threat Intelligence Consumer)"},
            )
        return self._http_client

    async def close(self):
        """Close the HTTP client."""
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    def _parse_feodo_csv(self, content: str) -> list[ThreatIndicator]:
        """
        Parse Feodo Tracker CSV format.

        CSV format (after comment lines starting with #):
        first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware

        Example:
        2024-01-15 10:30:00,192.168.1.1,443,online,2024-01-15,Dridex
        """
        indicators = []

        # Filter out comment lines
        lines = [line for line in content.splitlines() if line and not line.startswith("#")]

        if not lines:
            logger.warning("No data lines found in Feodo feed")
            return indicators

        # Parse CSV
        reader = csv.DictReader(io.StringIO("\n".join(lines)))

        for row in reader:
            try:
                # Extract fields with fallbacks
                ip = row.get("dst_ip", "").strip()
                if not ip:
                    continue

                # Parse port
                port_str = row.get("dst_port", "").strip()
                port = int(port_str) if port_str.isdigit() else None

                # Parse malware family
                malware = row.get("malware", "").strip() or "Unknown"

                # Parse first_seen
                first_seen = None
                first_seen_str = row.get("first_seen_utc", "").strip()
                if first_seen_str:
                    try:
                        first_seen = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                        first_seen = first_seen.replace(tzinfo=UTC)
                    except ValueError:
                        pass

                # Parse last_online
                last_online = None
                last_online_str = row.get("last_online", "").strip()
                if last_online_str:
                    try:
                        last_online = datetime.strptime(last_online_str, "%Y-%m-%d")
                        last_online = last_online.replace(tzinfo=UTC)
                    except ValueError:
                        pass

                indicator = ThreatIndicator(
                    ip=ip,
                    port=port,
                    malware_family=malware,
                    first_seen=first_seen,
                    last_online=last_online,
                    source_feed="feodo_tracker",
                )
                indicators.append(indicator)

            except Exception as e:
                logger.debug(f"Error parsing row: {row}, error: {e}")
                continue

        return indicators

    async def _fetch_feodo_feed(self) -> list[ThreatIndicator] | None:
        """
        Fetch Feodo Tracker feed with retry logic.

        Returns:
            List of ThreatIndicators or None if fetch failed.
        """
        client = await self._get_client()

        for attempt in range(MAX_RETRIES):
            try:
                logger.info(f"Fetching Feodo feed (attempt {attempt + 1}/{MAX_RETRIES})...")

                # Build headers for conditional request
                headers = {}
                if self._cache.etag:
                    headers["If-None-Match"] = self._cache.etag

                response = await client.get(FEODO_TRACKER_URL, headers=headers)

                # Handle 304 Not Modified
                if response.status_code == 304:
                    logger.info("Feed not modified since last fetch")
                    self._cache.is_stale = False
                    self._cache.last_updated = datetime.now(UTC)
                    return self._cache.indicators

                response.raise_for_status()

                # Store ETag for future conditional requests
                new_etag = response.headers.get("ETag")
                if new_etag:
                    self._cache.etag = new_etag

                # Parse the feed
                indicators = self._parse_feodo_csv(response.text)
                logger.info(f"Parsed {len(indicators)} threat indicators from Feodo feed")

                return indicators

            except httpx.TimeoutException:
                logger.warning(f"Timeout fetching Feodo feed (attempt {attempt + 1})")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error fetching Feodo feed: {e.response.status_code}")
                if e.response.status_code >= 500:
                    # Server error, retry
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                else:
                    # Client error, don't retry
                    break

            except httpx.RequestError as e:
                logger.error(f"Request error fetching Feodo feed: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

        logger.error("Failed to fetch Feodo feed after all retries")
        return None

    async def refresh_cache(self, force: bool = False) -> bool:
        """
        Refresh the threat indicator cache.

        Args:
            force: Force refresh even if cache is valid.

        Returns:
            True if cache was updated, False otherwise.
        """
        async with self._lock:
            # Check if refresh is needed
            if not force and self._cache.is_valid:
                logger.debug("Cache is still valid, skipping refresh")
                return False

            # Mark cache as stale before fetching
            self._cache.is_stale = True

            # Fetch fresh data
            indicators = await self._fetch_feodo_feed()

            if indicators is not None:
                # Check for changes (diff logic)
                old_ips = {i.ip for i in self._cache.indicators}
                new_ips = {i.ip for i in indicators}

                added = new_ips - old_ips
                removed = old_ips - new_ips

                if added or removed:
                    logger.info(f"Feed diff: +{len(added)} new, -{len(removed)} removed")

                # Update cache
                self._cache.indicators = indicators
                self._cache.last_updated = datetime.now(UTC)
                self._cache.is_stale = False

                return True
            else:
                # Fetch failed, keep old data if available
                if self._cache.indicators:
                    logger.warning("Using stale cache data due to fetch failure")
                    self._cache.is_stale = True
                return False

    async def get_indicators(self, count: int = 10) -> list[ThreatIndicator]:
        """
        Get random threat indicators from the cache.

        This simulates 'live' traffic detection by sampling from
        the cached threat feed.

        Args:
            count: Number of indicators to return.

        Returns:
            List of randomly sampled ThreatIndicators.
        """
        # Ensure cache is populated
        if not self._cache.indicators:
            await self.refresh_cache()

        # If still empty, return empty list
        if not self._cache.indicators:
            logger.warning("No indicators available in cache")
            return []

        # Sample random indicators
        sample_size = min(count, len(self._cache.indicators))
        return random.sample(self._cache.indicators, sample_size)

    async def _fetch_abuseipdb_single(self, ip: str, api_key: str) -> dict | None:
        """
        Fetch reputation data for a single IP from the AbuseIPDB check endpoint.

        Args:
            ip: The IP address to look up.
            api_key: AbuseIPDB API key.

        Returns:
            Dict with reputation fields, or None on failure.
        """
        client = await self._get_client()

        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        for attempt in range(MAX_RETRIES):
            try:
                response = await client.get(
                    ABUSEIPDB_CHECK_URL, headers=headers, params=params
                )
                response.raise_for_status()
                data = response.json().get("data", {})

                return {
                    "ip": data.get("ipAddress", ip),
                    "abuse_score": int(data.get("abuseConfidenceScore", 0)),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "total_reports": int(data.get("totalReports", 0)),
                    "source": "abuseipdb",
                }

            except httpx.TimeoutException:
                logger.warning(
                    f"Timeout fetching AbuseIPDB check for {ip} (attempt {attempt + 1})"
                )
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

            except httpx.HTTPStatusError as e:
                logger.error(
                    f"HTTP {e.response.status_code} from AbuseIPDB check for {ip}"
                )
                if e.response.status_code in (401, 429):
                    break  # Don't retry auth / rate-limit errors
                if e.response.status_code >= 500 and attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                else:
                    break

            except httpx.RequestError as e:
                logger.error(f"Request error checking AbuseIPDB for {ip}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

        return None

    async def get_ip_reputation(
        self, ip: str, db: AsyncSession, api_key: str | None = None
    ) -> dict | None:
        """
        Look up IP reputation using a "DB-only" strategy.

        Queries the ip_reputation table for a cached record. Does NOT make
        individual API calls to AbuseIPDB — use refresh_abuseipdb_blacklist()
        to bulk-populate the cache instead.

        The caller is responsible for committing the session.

        Args:
            ip: IP address to look up.
            db: An async SQLAlchemy session.
            api_key: Ignored (kept for API compatibility).

        Returns:
            Dict with reputation fields, or None if not in DB.
        """
        # Query the database cache
        result = await db.execute(select(IPReputation).where(IPReputation.ip == ip))
        cached: IPReputation | None = result.scalar_one_or_none()

        if cached is not None:
            # Return cached data regardless of freshness
            # (Bulk refresh handles keeping data current)
            is_fresh = cached.is_fresh(7)
            logger.debug(
                f"IP reputation {'HIT' if is_fresh else 'HIT (stale)'} for {ip} "
                f"(score={cached.abuse_score})"
            )
            return {
                "ip": cached.ip,
                "abuse_score": cached.abuse_score,
                "country_code": cached.country_code,
                "isp": cached.isp,
                "domain": cached.domain,
                "total_reports": cached.total_reports,
                "source": cached.source,
                "last_fetched": cached.last_fetched.isoformat(),
                "from_cache": True,
                "stale": not is_fresh,
            }

        # No record in DB — do not make individual API call
        logger.debug(f"IP reputation MISS for {ip} (not in bulk cache)")
        return None

    @property
    def cache_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "total_indicators": self._cache.count,
            "last_updated": self._cache.last_updated.isoformat()
            if self._cache.last_updated
            else None,
            "is_valid": self._cache.is_valid,
            "is_stale": self._cache.is_stale,
        }


# Global service instance (singleton)
_feed_service: ThreatFeedService | None = None


def get_feed_service() -> ThreatFeedService:
    """Get or create the global feed service instance."""
    global _feed_service
    if _feed_service is None:
        _feed_service = ThreatFeedService()
    return _feed_service


async def get_real_threat_ips(count: int = 10) -> list[ThreatIndicator]:
    """
    Convenience function to get real threat indicators.

    Args:
        count: Number of indicators to fetch.

    Returns:
        List of ThreatIndicators from real threat feeds.
    """
    service = get_feed_service()

    # Refresh cache if needed (non-blocking check)
    if not service._cache.is_valid:
        await service.refresh_cache()

    return await service.get_indicators(count=count)


async def refresh_abuseipdb_blacklist() -> int:
    """
    Bulk fetch high-confidence malicious IPs from AbuseIPDB blacklist.

    This function downloads up to 10,000 IPs with confidence >= 90 and
    upserts them into the ip_reputation table. This bulk approach saves
    API credits compared to individual lookups during ingestion.

    Returns:
        Number of IP reputation records upserted to the database.
    """
    if not ABUSEIPDB_API_KEY:
        logger.warning("ABUSEIPDB_API_KEY not set, skipping blacklist refresh")
        return 0

    logger.info("Fetching AbuseIPDB blacklist (bulk)...")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": 90,
        "limit": 10000,
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(
                ABUSEIPDB_BLACKLIST_URL,
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            ip_list = data.get("data", [])

            if not ip_list:
                logger.warning("AbuseIPDB blacklist returned no data")
                return 0

            logger.info(f"Received {len(ip_list)} IPs from AbuseIPDB blacklist")

            # Upsert records into the database
            count = 0
            async with async_session_maker() as session:
                for entry in ip_list:
                    ip = entry.get("ipAddress", "").strip()
                    if not ip:
                        continue

                    reputation = IPReputation(
                        ip=ip,
                        abuse_score=int(entry.get("abuseConfidenceScore", 0)),
                        country_code=entry.get("countryCode"),
                        isp=entry.get("isp"),
                        domain=entry.get("domain"),
                        total_reports=int(entry.get("totalReports", 0)),
                        source="abuseipdb",
                        last_fetched=datetime.now(UTC),
                    )
                    await session.merge(reputation)
                    count += 1

                await session.commit()
                logger.info(f"Upserted {count} IPs to ip_reputation table")

            return count

    except httpx.TimeoutException:
        logger.error("Timeout fetching AbuseIPDB blacklist")
        return 0
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP {e.response.status_code} from AbuseIPDB blacklist")
        if e.response.status_code == 429:
            logger.warning("AbuseIPDB rate limit exceeded")
        return 0
    except httpx.RequestError as e:
        logger.error(f"Request error fetching AbuseIPDB blacklist: {e}")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error fetching AbuseIPDB blacklist: {e}")
        return 0


async def fetch_free_blocklists() -> set[str]:
    """
    Fetch IPs from multiple free, high-quality blocklists.

    Sources:
    - Spamhaus DROP/EDROP (known malicious netblocks)
    - Emerging Threats compromised IPs
    - CINS Army bad guys list

    Returns:
        Set of unique IP addresses (deduplicated).
    """
    ips: set[str] = set()

    blocklists = [
        ("Spamhaus DROP", SPAMHAUS_DROP_URL),
        ("Spamhaus EDROP", SPAMHAUS_EDROP_URL),
        ("Emerging Threats", EMERGING_THREATS_URL),
        ("CINS Army", CINS_ARMY_URL),
    ]

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        for list_name, url in blocklists:
            try:
                logger.info(f"Fetching {list_name} blocklist...")
                response = await client.get(url)
                response.raise_for_status()
                content = response.text

                list_ips = set()
                for line in content.splitlines():
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue

                    # Extract IP address:
                    # - Handle CIDR notation (192.168.1.0/24) -> take base IP
                    # - Handle inline comments (192.168.1.1 ; comment)
                    # - Split on whitespace, /, or ;
                    parts = line.split()
                    if not parts:
                        continue

                    ip_candidate = parts[0]  # First token is usually the IP

                    # Remove CIDR suffix if present
                    if "/" in ip_candidate:
                        ip_candidate = ip_candidate.split("/")[0]

                    # Remove inline comment separator if present
                    if ";" in ip_candidate:
                        ip_candidate = ip_candidate.split(";")[0]

                    ip_candidate = ip_candidate.strip()

                    # Basic validation: check if it looks like an IP
                    if ip_candidate and "." in ip_candidate:
                        # Simple check: has dots and no alphabetic chars
                        if not any(c.isalpha() for c in ip_candidate):
                            list_ips.add(ip_candidate)

                logger.info(f"{list_name}: fetched {len(list_ips)} unique IPs")
                ips.update(list_ips)

            except httpx.TimeoutException:
                logger.warning(f"Timeout fetching {list_name} blocklist")
            except httpx.HTTPStatusError as e:
                logger.warning(
                    f"HTTP {e.response.status_code} from {list_name} blocklist"
                )
            except httpx.RequestError as e:
                logger.warning(f"Request error fetching {list_name}: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error fetching {list_name}: {e}")

    logger.info(f"Total unique IPs from free blocklists: {len(ips)}")
    return ips


async def refresh_free_blocklists() -> int:
    """
    Fetch IPs from free blocklists and save them to the database.

    This function aggregates IPs from multiple free, high-quality threat
    intelligence sources and upserts them into the ip_reputation table.
    These lists are high-confidence (abuse_score=95) and require no API key.

    Returns:
        Number of IP reputation records upserted to the database.
    """
    logger.info("Refreshing free blocklists...")

    try:
        # Fetch IPs from all free blocklists
        ips = await fetch_free_blocklists()

        if not ips:
            logger.warning("No IPs fetched from free blocklists")
            return 0

        # Upsert records into the database
        count = 0
        async with async_session_maker() as session:
            for ip in ips:
                reputation = IPReputation(
                    ip=ip,
                    abuse_score=95,  # High-confidence lists
                    country_code=None,  # Free lists don't provide geo data
                    isp=None,
                    domain=None,
                    total_reports=0,  # Free lists don't provide report counts
                    source="free_blocklist",
                    last_fetched=datetime.now(UTC),
                )
                await session.merge(reputation)
                count += 1

            await session.commit()
            logger.info(f"Upserted {count} IPs from free blocklists to ip_reputation table")

        return count

    except Exception as e:
        logger.error(f"Unexpected error refreshing free blocklists: {e}")
        return 0


async def fetch_cloudflare_targets() -> list[tuple[str, float]]:
    """
    Fetch L3 attack target country rankings from Cloudflare Radar.

    Returns weighted list of countries being attacked, based on real-world
    attack trends. Data is cached for 1 hour.

    Returns:
        List of (country_code, weight) tuples. Weights are normalized percentages.
        Example: [("CN", 0.20), ("US", 0.15), ("DE", 0.10), ...]
    """
    global _cloudflare_cache

    async with _cloudflare_lock:
        # Return cached data if valid
        if _cloudflare_cache.is_valid:
            logger.debug(
                f"Using cached Cloudflare data ({len(_cloudflare_cache.targets)} countries)"
            )
            return _cloudflare_cache.targets

        logger.info("Fetching Cloudflare Radar L3 attack targets...")

        targets = []

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            for attempt in range(MAX_RETRIES):
                try:
                    # Build headers with optional auth
                    headers = {"Accept": "application/json", "User-Agent": "DDoS-Visualizer/1.0"}
                    if CLOUDFLARE_API_TOKEN:
                        headers["Authorization"] = f"Bearer {CLOUDFLARE_API_TOKEN}"

                    response = await client.get(CLOUDFLARE_RADAR_L3_URL, headers=headers)
                    response.raise_for_status()

                    data = response.json()

                    # Parse Cloudflare response structure
                    # Expected: {"result": {"top_0": [{"clientCountryName": "China", "clientCountryAlpha2": "CN", "value": "25.5"}, ...]}}
                    result = data.get("result", {})
                    top_locations = result.get("top_0", [])

                    if not top_locations:
                        logger.warning("No target locations in Cloudflare response")
                        break

                    # Extract country codes and weights
                    total_value = 0.0
                    raw_targets = []

                    for loc in top_locations:
                        country_code = loc.get("clientCountryAlpha2", "").strip().upper()
                        value_str = loc.get("value", "0")

                        try:
                            value = float(value_str)
                        except ValueError:
                            value = 0.0

                        if country_code and value > 0:
                            raw_targets.append((country_code, value))
                            total_value += value

                    # Normalize weights to sum to 1.0
                    if total_value > 0:
                        targets = [(cc, v / total_value) for cc, v in raw_targets]

                    logger.info(f"Fetched {len(targets)} target countries from Cloudflare Radar")
                    break

                except httpx.TimeoutException:
                    logger.warning(f"Timeout fetching Cloudflare Radar (attempt {attempt + 1})")
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

                except httpx.HTTPStatusError as e:
                    logger.error(f"HTTP error from Cloudflare Radar: {e.response.status_code}")
                    # Don't retry client errors
                    if e.response.status_code < 500:
                        break
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

                except Exception as e:
                    logger.error(f"Error fetching Cloudflare Radar: {e}")
                    break

        # Update cache even if empty (to avoid repeated failed fetches)
        if targets:
            _cloudflare_cache.targets = targets
            _cloudflare_cache.last_updated = datetime.now(UTC)
        elif not _cloudflare_cache.targets:
            # Fallback to default distribution if no data and no cache
            targets = _get_default_target_distribution()
            _cloudflare_cache.targets = targets
            _cloudflare_cache.last_updated = datetime.now(UTC)
            logger.info("Using default target distribution")

        return _cloudflare_cache.targets


def _get_default_target_distribution() -> list[tuple[str, float]]:
    """
    Default target distribution based on typical DDoS patterns.
    Used as fallback when Cloudflare Radar is unavailable.
    """
    return [
        ("CN", 0.18),  # China
        ("US", 0.15),  # United States
        ("DE", 0.08),  # Germany
        ("GB", 0.06),  # United Kingdom
        ("FR", 0.05),  # France
        ("JP", 0.05),  # Japan
        ("KR", 0.05),  # South Korea
        ("RU", 0.05),  # Russia
        ("BR", 0.04),  # Brazil
        ("IN", 0.04),  # India
        ("NL", 0.04),  # Netherlands
        ("SG", 0.03),  # Singapore
        ("AU", 0.03),  # Australia
        ("CA", 0.03),  # Canada
        ("IT", 0.02),  # Italy
        ("ES", 0.02),  # Spain
        ("PL", 0.02),  # Poland
        ("UA", 0.02),  # Ukraine
        ("ID", 0.02),  # Indonesia
        ("VN", 0.02),  # Vietnam
    ]


async def fetch_abuseipdb_threats(api_key: str, limit: int = 50) -> list[ThreatIndicator]:
    """
    Fetch high-confidence threat indicators from AbuseIPDB.

    Priority order to minimise API credit consumption:
    1. In-memory cache (valid for 30 min, reset on restart)
    2. DB-backed ip_reputation table (persistent across restarts)
    3. Live AbuseIPDB blacklist API call (last resort, populates both caches)

    Args:
        api_key: AbuseIPDB API key.
        limit: Number of indicators to return.

    Returns:
        List of ThreatIndicators from AbuseIPDB.
    """
    global _abuseipdb_cache

    # --- 1. In-memory cache (fast path) ---
    async with _abuseipdb_lock:
        if _abuseipdb_cache.is_valid:
            logger.info(
                f"Using cached AbuseIPDB data ({len(_abuseipdb_cache.indicators)} indicators)"
            )
            cached = _abuseipdb_cache.indicators[:]
            random.shuffle(cached)
            return cached[:limit]

    # --- 2. DB-backed cache (survives container restarts) ---
    try:
        async with async_session_maker() as session:
            result = await session.execute(
                select(IPReputation.ip)
                .where(IPReputation.source == "abuseipdb")
                .limit(ABUSEIPDB_FETCH_SIZE)
            )
            db_ips = [row[0] for row in result.fetchall()]

        if db_ips:
            logger.info(f"Using {len(db_ips)} AbuseIPDB IPs from DB cache")
            sampled = random.sample(db_ips, min(limit, len(db_ips)))
            indicators = [
                ThreatIndicator(
                    ip=ip,
                    port=None,
                    malware_family=DEFAULT_ABUSEIPDB_ATTACK_TYPE,
                    source_feed="abuseipdb",
                )
                for ip in sampled
            ]
            # Warm the in-memory cache so future calls skip the DB too
            all_indicators = [
                ThreatIndicator(ip=ip, port=None,
                                malware_family=DEFAULT_ABUSEIPDB_ATTACK_TYPE,
                                source_feed="abuseipdb")
                for ip in db_ips
            ]
            async with _abuseipdb_lock:
                _abuseipdb_cache.indicators = all_indicators
                _abuseipdb_cache.last_updated = datetime.now(UTC)
            return indicators
    except Exception as e:
        logger.warning(f"DB cache read failed, falling back to API: {e}")

    # --- 3. Live API call (last resort — only when DB is empty) ---
    indicators = []

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "confidenceMinimum": 90,
        "limit": min(ABUSEIPDB_FETCH_SIZE, 10000),
    }

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        for attempt in range(MAX_RETRIES):
            try:
                logger.info(
                    f"Fetching AbuseIPDB blacklist from API (attempt {attempt + 1}/{MAX_RETRIES})..."
                )

                response = await client.get(
                    ABUSEIPDB_BLACKLIST_URL,
                    headers=headers,
                    params=params,
                )
                response.raise_for_status()

                data = response.json()
                ip_list = data.get("data", [])

                logger.info(f"Received {len(ip_list)} IPs from AbuseIPDB API")

                for entry in ip_list:
                    ip = entry.get("ipAddress", "").strip()
                    if not ip:
                        continue

                    categories = entry.get("abuseCategories", []) or []
                    attack_type = DEFAULT_ABUSEIPDB_ATTACK_TYPE
                    for cat_id in categories:
                        if cat_id in ABUSEIPDB_CATEGORY_MAPPING:
                            attack_type = ABUSEIPDB_CATEGORY_MAPPING[cat_id]
                            break

                    indicators.append(ThreatIndicator(
                        ip=ip,
                        port=None,
                        malware_family=attack_type,
                        first_seen=None,
                        last_online=None,
                        source_feed="abuseipdb",
                    ))

                # Populate in-memory cache
                async with _abuseipdb_lock:
                    _abuseipdb_cache.indicators = indicators[:]
                    _abuseipdb_cache.last_updated = datetime.now(UTC)
                    logger.info(f"Cached {len(indicators)} AbuseIPDB indicators (TTL: 30min)")

                return random.sample(indicators, min(limit, len(indicators))) if indicators else []

            except httpx.TimeoutException:
                logger.warning(f"Timeout fetching AbuseIPDB (attempt {attempt + 1})")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error from AbuseIPDB: {e.response.status_code}")
                if e.response.status_code == 401:
                    logger.error("Invalid AbuseIPDB API key")
                    break
                elif e.response.status_code == 429:
                    logger.warning("AbuseIPDB rate limit exceeded — will retry from DB next cycle")
                    break
                elif e.response.status_code >= 500 and attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                else:
                    break

            except httpx.RequestError as e:
                logger.error(f"Request error fetching AbuseIPDB: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))

            except Exception as e:
                logger.error(f"Unexpected error fetching AbuseIPDB: {e}")
                break

    logger.error("Failed to fetch AbuseIPDB data from all sources")
    return indicators


# CLI for testing
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Threat Feed Service CLI")
    parser.add_argument("--refresh", action="store_true", help="Force refresh cache")
    parser.add_argument("--sample", type=int, default=5, help="Number of indicators to sample")
    parser.add_argument("--stats", action="store_true", help="Show cache stats")

    args = parser.parse_args()

    async def main():
        service = get_feed_service()

        try:
            if args.refresh:
                print("Forcing cache refresh...")
                await service.refresh_cache(force=True)

            if args.stats:
                stats = service.cache_stats
                print("\nCache Statistics:")
                print(f"  Total indicators: {stats['total_indicators']}")
                print(f"  Last updated: {stats['last_updated']}")
                print(f"  Cache valid: {stats['is_valid']}")
                print(f"  Cache stale: {stats['is_stale']}")

            print(f"\nSampling {args.sample} indicators:")
            indicators = await service.get_indicators(count=args.sample)

            for i, ind in enumerate(indicators, 1):
                print(f"  {i}. {ind.ip}:{ind.port or 'N/A'} - {ind.malware_family}")

        finally:
            await service.close()

    asyncio.run(main())
