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
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
import httpx

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# Feed configuration
FEODO_TRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
CLOUDFLARE_RADAR_L3_URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target"
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN", "")
CACHE_TTL_SECONDS = 300  # Refresh cache every 5 minutes
CLOUDFLARE_CACHE_TTL_SECONDS = 3600  # Cache Cloudflare data for 1 hour
ABUSEIPDB_CACHE_TTL_SECONDS = 1800  # Cache AbuseIPDB data for 30 minutes (rate limit protection)
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2.0

# AbuseIPDB category to attack type mapping
ABUSEIPDB_CATEGORY_MAPPING = {
    4: "UDP Flood",           # DDoS Attack
    18: "SSH Brute Force",    # Brute-Force
    15: "Port Scanning",      # Hacking
}
DEFAULT_ABUSEIPDB_ATTACK_TYPE = "Malicious Traffic"


# Cloudflare Radar target cache
@dataclass
class CloudflareTargetCache:
    """Cache for Cloudflare Radar L3 attack target data."""
    targets: list[tuple[str, float]] = field(default_factory=list)  # (country_code, weight)
    last_updated: Optional[datetime] = None
    
    @property
    def is_valid(self) -> bool:
        if not self.targets or self.last_updated is None:
            return False
        age = (datetime.now(timezone.utc) - self.last_updated).total_seconds()
        return age < CLOUDFLARE_CACHE_TTL_SECONDS


_cloudflare_cache = CloudflareTargetCache()
_cloudflare_lock = asyncio.Lock()


# AbuseIPDB cache
@dataclass
class AbuseIPDBCache:
    """Cache for AbuseIPDB threat data to avoid rate limits."""
    indicators: list = field(default_factory=list)
    last_updated: Optional[datetime] = None
    
    @property
    def is_valid(self) -> bool:
        if not self.indicators or self.last_updated is None:
            return False
        age = (datetime.now(timezone.utc) - self.last_updated).total_seconds()
        return age < ABUSEIPDB_CACHE_TTL_SECONDS


_abuseipdb_cache = AbuseIPDBCache()
_abuseipdb_lock = asyncio.Lock()


@dataclass
class ThreatIndicator:
    """Represents a single threat indicator from a feed."""
    ip: str
    port: Optional[int] = None
    malware_family: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_online: Optional[datetime] = None
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
    last_updated: Optional[datetime] = None
    etag: Optional[str] = None
    is_stale: bool = True
    
    @property
    def is_valid(self) -> bool:
        """Check if cache is valid (not stale and has data)."""
        if not self.indicators or self.is_stale:
            return False
        if self.last_updated is None:
            return False
        age = (datetime.now(timezone.utc) - self.last_updated).total_seconds()
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
        self._http_client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with proper configuration."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
                follow_redirects=True,
                headers={
                    "User-Agent": "DDoS-Visualizer/1.0 (Threat Intelligence Consumer)"
                }
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
                        first_seen = first_seen.replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
                
                # Parse last_online
                last_online = None
                last_online_str = row.get("last_online", "").strip()
                if last_online_str:
                    try:
                        last_online = datetime.strptime(last_online_str, "%Y-%m-%d")
                        last_online = last_online.replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
                
                indicator = ThreatIndicator(
                    ip=ip,
                    port=port,
                    malware_family=malware,
                    first_seen=first_seen,
                    last_online=last_online,
                    source_feed="feodo_tracker"
                )
                indicators.append(indicator)
                
            except Exception as e:
                logger.debug(f"Error parsing row: {row}, error: {e}")
                continue
        
        return indicators
    
    async def _fetch_feodo_feed(self) -> Optional[list[ThreatIndicator]]:
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
                    self._cache.last_updated = datetime.now(timezone.utc)
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
                self._cache.last_updated = datetime.now(timezone.utc)
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
    
    @property
    def cache_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "total_indicators": self._cache.count,
            "last_updated": self._cache.last_updated.isoformat() if self._cache.last_updated else None,
            "is_valid": self._cache.is_valid,
            "is_stale": self._cache.is_stale,
        }


# Global service instance (singleton)
_feed_service: Optional[ThreatFeedService] = None


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
            logger.debug(f"Using cached Cloudflare data ({len(_cloudflare_cache.targets)} countries)")
            return _cloudflare_cache.targets
        
        logger.info("Fetching Cloudflare Radar L3 attack targets...")
        
        targets = []
        
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            for attempt in range(MAX_RETRIES):
                try:
                    # Build headers with optional auth
                    headers = {
                        "Accept": "application/json",
                        "User-Agent": "DDoS-Visualizer/1.0"
                    }
                    if CLOUDFLARE_API_TOKEN:
                        headers["Authorization"] = f"Bearer {CLOUDFLARE_API_TOKEN}"
                    
                    response = await client.get(
                        CLOUDFLARE_RADAR_L3_URL,
                        headers=headers
                    )
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
            _cloudflare_cache.last_updated = datetime.now(timezone.utc)
        elif not _cloudflare_cache.targets:
            # Fallback to default distribution if no data and no cache
            targets = _get_default_target_distribution()
            _cloudflare_cache.targets = targets
            _cloudflare_cache.last_updated = datetime.now(timezone.utc)
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
    Fetch high-confidence threat indicators from AbuseIPDB with caching.
    
    Uses the blacklist endpoint to get IPs with confidenceMinimum=90.
    Cache TTL: 30 minutes to avoid rate limit (1000 requests/day free tier).
    
    Args:
        api_key: AbuseIPDB API key.
        limit: Maximum number of IPs to fetch (max 10000).
    
    Returns:
        List of ThreatIndicators from AbuseIPDB.
    """
    global _abuseipdb_cache
    
    # Check cache first
    async with _abuseipdb_lock:
        if _abuseipdb_cache.is_valid:
            logger.info(f"Using cached AbuseIPDB data ({len(_abuseipdb_cache.indicators)} indicators)")
            # Return random sample from cache
            import random
            cached = _abuseipdb_cache.indicators[:]
            random.shuffle(cached)
            return cached[:limit]
    
    indicators = []
    
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    
    params = {
        "confidenceMinimum": 90,
        "limit": min(limit, 10000),
    }
    
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        for attempt in range(MAX_RETRIES):
            try:
                logger.info(f"Fetching AbuseIPDB blacklist (attempt {attempt + 1}/{MAX_RETRIES})...")
                
                response = await client.get(
                    ABUSEIPDB_BLACKLIST_URL,
                    headers=headers,
                    params=params,
                )
                response.raise_for_status()
                
                data = response.json()
                ip_list = data.get("data", [])
                
                logger.info(f"Received {len(ip_list)} IPs from AbuseIPDB")
                
                for entry in ip_list:
                    ip = entry.get("ipAddress", "").strip()
                    if not ip:
                        continue
                    
                    # Map categories to attack type
                    categories = entry.get("abuseCategories", []) or []
                    attack_type = DEFAULT_ABUSEIPDB_ATTACK_TYPE
                    
                    for cat_id in categories:
                        if cat_id in ABUSEIPDB_CATEGORY_MAPPING:
                            attack_type = ABUSEIPDB_CATEGORY_MAPPING[cat_id]
                            break
                    
                    indicator = ThreatIndicator(
                        ip=ip,
                        port=None,
                        malware_family=attack_type,  # Store attack type in malware_family
                        first_seen=None,
                        last_online=None,
                        source_feed="abuseipdb",
                    )
                    indicators.append(indicator)
                
                # Update cache with fresh data
                async with _abuseipdb_lock:
                    _abuseipdb_cache.indicators = indicators[:]
                    _abuseipdb_cache.last_updated = datetime.now(timezone.utc)
                    logger.info(f"Cached {len(indicators)} AbuseIPDB indicators (TTL: 30min)")
                
                return indicators
                
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
                    logger.warning("AbuseIPDB rate limit exceeded")
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
    
    logger.error("Failed to fetch AbuseIPDB data")
    return indicators


# CLI for testing
if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    
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
                print(f"\nCache Statistics:")
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
