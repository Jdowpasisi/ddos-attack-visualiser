"""
Geo-location service for IP address to coordinates mapping.

Supports multiple backends with intelligent fallback:
1. In-memory LRU cache (fastest)
2. Database lookup for recent resolutions (24h)
3. ip-api.com API (rate-limited: 45 req/min)
4. Country center coordinates with jitter (fallback)

Ensures the demo never crashes due to API rate limits or bans.
"""

import asyncio
import logging
import random
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Add backend to path for database imports
backend_dir = Path(__file__).parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

try:
    import httpx  # type: ignore[import-not-found]
except ImportError:
    httpx: Any = None

logger = logging.getLogger(__name__)


@dataclass
class GeoLocation:
    """Geographic location data for an IP address."""

    ip: str
    country: str
    country_code: str
    city: str
    lat: float
    lon: float
    isp: str | None = None
    source: str = "unknown"  # Track where the data came from


@dataclass
class CachedGeoLocation:
    """Cached geo location with timestamp for TTL expiration."""

    location: GeoLocation
    cached_at: float  # Unix timestamp


# Country center coordinates for fallback (with jitter radius in degrees)
COUNTRY_CENTER_COORDS: dict[str, dict] = {
    # North America
    "US": {"lat": 39.8283, "lon": -98.5795, "jitter": 5.0, "name": "United States"},
    "CA": {"lat": 56.1304, "lon": -106.3468, "jitter": 5.0, "name": "Canada"},
    "MX": {"lat": 23.6345, "lon": -102.5528, "jitter": 3.0, "name": "Mexico"},
    # Europe
    "GB": {"lat": 55.3781, "lon": -3.4360, "jitter": 2.0, "name": "United Kingdom"},
    "DE": {"lat": 51.1657, "lon": 10.4515, "jitter": 2.0, "name": "Germany"},
    "FR": {"lat": 46.2276, "lon": 2.2137, "jitter": 2.5, "name": "France"},
    "NL": {"lat": 52.1326, "lon": 5.2913, "jitter": 0.5, "name": "Netherlands"},
    "RU": {"lat": 61.5240, "lon": 105.3188, "jitter": 10.0, "name": "Russia"},
    "UA": {"lat": 48.3794, "lon": 31.1656, "jitter": 3.0, "name": "Ukraine"},
    "PL": {"lat": 51.9194, "lon": 19.1451, "jitter": 2.0, "name": "Poland"},
    "IT": {"lat": 41.8719, "lon": 12.5674, "jitter": 2.0, "name": "Italy"},
    "ES": {"lat": 40.4637, "lon": -3.7492, "jitter": 2.5, "name": "Spain"},
    # Asia
    "CN": {"lat": 35.8617, "lon": 104.1954, "jitter": 8.0, "name": "China"},
    "JP": {"lat": 36.2048, "lon": 138.2529, "jitter": 2.0, "name": "Japan"},
    "KR": {"lat": 35.9078, "lon": 127.7669, "jitter": 1.0, "name": "South Korea"},
    "IN": {"lat": 20.5937, "lon": 78.9629, "jitter": 5.0, "name": "India"},
    "SG": {"lat": 1.3521, "lon": 103.8198, "jitter": 0.1, "name": "Singapore"},
    "TW": {"lat": 23.6978, "lon": 120.9605, "jitter": 0.5, "name": "Taiwan"},
    "ID": {"lat": -0.7893, "lon": 113.9213, "jitter": 5.0, "name": "Indonesia"},
    "VN": {"lat": 14.0583, "lon": 108.2772, "jitter": 3.0, "name": "Vietnam"},
    "TH": {"lat": 15.8700, "lon": 100.9925, "jitter": 2.0, "name": "Thailand"},
    "PH": {"lat": 12.8797, "lon": 121.7740, "jitter": 2.0, "name": "Philippines"},
    # South America
    "BR": {"lat": -14.2350, "lon": -51.9253, "jitter": 8.0, "name": "Brazil"},
    "AR": {"lat": -38.4161, "lon": -63.6167, "jitter": 5.0, "name": "Argentina"},
    "CL": {"lat": -35.6751, "lon": -71.5430, "jitter": 4.0, "name": "Chile"},
    "CO": {"lat": 4.5709, "lon": -74.2973, "jitter": 3.0, "name": "Colombia"},
    # Africa
    "ZA": {"lat": -30.5595, "lon": 22.9375, "jitter": 3.0, "name": "South Africa"},
    "NG": {"lat": 9.0820, "lon": 8.6753, "jitter": 3.0, "name": "Nigeria"},
    "EG": {"lat": 26.8206, "lon": 30.8025, "jitter": 3.0, "name": "Egypt"},
    "KE": {"lat": -0.0236, "lon": 37.9062, "jitter": 2.0, "name": "Kenya"},
    # Oceania
    "AU": {"lat": -25.2744, "lon": 133.7751, "jitter": 8.0, "name": "Australia"},
    "NZ": {"lat": -40.9006, "lon": 174.8860, "jitter": 2.0, "name": "New Zealand"},
    # Middle East
    "AE": {"lat": 23.4241, "lon": 53.8478, "jitter": 1.0, "name": "UAE"},
    "SA": {"lat": 23.8859, "lon": 45.0792, "jitter": 4.0, "name": "Saudi Arabia"},
    "IL": {"lat": 31.0461, "lon": 34.8516, "jitter": 0.5, "name": "Israel"},
    "IR": {"lat": 32.4279, "lon": 53.6880, "jitter": 4.0, "name": "Iran"},
    # Default/Unknown
    "XX": {"lat": 0.0, "lon": 0.0, "jitter": 30.0, "name": "Unknown"},
}


# Mock database of IP ranges to locations
# Structure: IP prefix -> GeoLocation data
MOCK_GEO_DATABASE: dict[str, dict] = {
    # United States
    "8.": {
        "country": "United States",
        "country_code": "US",
        "city": "Los Angeles",
        "lat": 34.0522,
        "lon": -118.2437,
    },
    "12.": {
        "country": "United States",
        "country_code": "US",
        "city": "New York",
        "lat": 40.7128,
        "lon": -74.0060,
    },
    "17.": {
        "country": "United States",
        "country_code": "US",
        "city": "Cupertino",
        "lat": 37.3230,
        "lon": -122.0322,
    },
    "32.": {
        "country": "United States",
        "country_code": "US",
        "city": "Chicago",
        "lat": 41.8781,
        "lon": -87.6298,
    },
    "44.": {
        "country": "United States",
        "country_code": "US",
        "city": "Seattle",
        "lat": 47.6062,
        "lon": -122.3321,
    },
    # Europe
    "2.": {
        "country": "France",
        "country_code": "FR",
        "city": "Paris",
        "lat": 48.8566,
        "lon": 2.3522,
    },
    "5.": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
    },
    "31.": {
        "country": "Netherlands",
        "country_code": "NL",
        "city": "Amsterdam",
        "lat": 52.3676,
        "lon": 4.9041,
    },
    "46.": {
        "country": "United Kingdom",
        "country_code": "GB",
        "city": "London",
        "lat": 51.5074,
        "lon": -0.1278,
    },
    "77.": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "lat": 55.7558,
        "lon": 37.6173,
    },
    "89.": {
        "country": "Russia",
        "country_code": "RU",
        "city": "St. Petersburg",
        "lat": 59.9311,
        "lon": 30.3609,
    },
    # Asia
    "1.": {
        "country": "China",
        "country_code": "CN",
        "city": "Beijing",
        "lat": 39.9042,
        "lon": 116.4074,
    },
    "14.": {
        "country": "Japan",
        "country_code": "JP",
        "city": "Tokyo",
        "lat": 35.6762,
        "lon": 139.6503,
    },
    "27.": {
        "country": "China",
        "country_code": "CN",
        "city": "Shanghai",
        "lat": 31.2304,
        "lon": 121.4737,
    },
    "36.": {
        "country": "China",
        "country_code": "CN",
        "city": "Shenzhen",
        "lat": 22.5431,
        "lon": 114.0579,
    },
    "49.": {
        "country": "South Korea",
        "country_code": "KR",
        "city": "Seoul",
        "lat": 37.5665,
        "lon": 126.9780,
    },
    "61.": {
        "country": "India",
        "country_code": "IN",
        "city": "Mumbai",
        "lat": 19.0760,
        "lon": 72.8777,
    },
    "103.": {
        "country": "Singapore",
        "country_code": "SG",
        "city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
    },
    "110.": {
        "country": "Taiwan",
        "country_code": "TW",
        "city": "Taipei",
        "lat": 25.0330,
        "lon": 121.5654,
    },
    "118.": {
        "country": "Indonesia",
        "country_code": "ID",
        "city": "Jakarta",
        "lat": -6.2088,
        "lon": 106.8456,
    },
    # South America
    "138.": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "São Paulo",
        "lat": -23.5505,
        "lon": -46.6333,
    },
    "152.": {
        "country": "Argentina",
        "country_code": "AR",
        "city": "Buenos Aires",
        "lat": -34.6037,
        "lon": -58.3816,
    },
    "179.": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "Rio de Janeiro",
        "lat": -22.9068,
        "lon": -43.1729,
    },
    # Africa
    "41.": {
        "country": "South Africa",
        "country_code": "ZA",
        "city": "Johannesburg",
        "lat": -26.2041,
        "lon": 28.0473,
    },
    "102.": {
        "country": "Nigeria",
        "country_code": "NG",
        "city": "Lagos",
        "lat": 6.5244,
        "lon": 3.3792,
    },
    "196.": {
        "country": "Egypt",
        "country_code": "EG",
        "city": "Cairo",
        "lat": 30.0444,
        "lon": 31.2357,
    },
    # Oceania
    "101.": {
        "country": "Australia",
        "country_code": "AU",
        "city": "Sydney",
        "lat": -33.8688,
        "lon": 151.2093,
    },
    "203.": {
        "country": "Australia",
        "country_code": "AU",
        "city": "Melbourne",
        "lat": -37.8136,
        "lon": 144.9631,
    },
}

# Default fallback locations when IP prefix isn't found
FALLBACK_LOCATIONS = [
    {
        "country": "United States",
        "country_code": "US",
        "city": "Ashburn",
        "lat": 39.0438,
        "lon": -77.4874,
    },
    {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
    },
    {
        "country": "Singapore",
        "country_code": "SG",
        "city": "Singapore",
        "lat": 1.3521,
        "lon": 103.8198,
    },
]


class LRUCache:
    """
    Simple LRU Cache implementation using OrderedDict.

    Thread-safe for single-threaded async usage.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CachedGeoLocation] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> GeoLocation | None:
        """Get item from cache, returns None if not found or expired."""
        if key not in self._cache:
            self._misses += 1
            return None

        entry = self._cache[key]
        now = time.time()

        # Check expiration
        if (now - entry.cached_at) > self.ttl_seconds:
            del self._cache[key]
            self._misses += 1
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key)
        self._hits += 1
        return entry.location

    def put(self, key: str, location: GeoLocation) -> None:
        """Store item in cache, evicting oldest if full."""
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self.max_size:
                # Remove oldest (first) item
                self._cache.popitem(last=False)

        self._cache[key] = CachedGeoLocation(location=location, cached_at=time.time())

    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @property
    def stats(self) -> dict:
        """Get cache statistics."""
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_percent": round(hit_rate, 2),
        }


class RateLimiter:
    """
    Token bucket rate limiter for API calls.

    Configured for ip-api.com: 45 requests per minute.
    """

    def __init__(self, requests_per_minute: int = 45):
        self.max_tokens = requests_per_minute
        self.tokens = float(requests_per_minute)
        self.refill_rate = requests_per_minute / 60.0  # tokens per second
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self, timeout: float = 5.0) -> bool:
        """
        Acquire a token for an API request.

        Args:
            timeout: Maximum seconds to wait for a token.

        Returns:
            True if token acquired, False if timed out.
        """
        start = time.time()

        while True:
            async with self._lock:
                self._refill()

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True

            # Check timeout
            if time.time() - start >= timeout:
                return False

            # Wait a bit before retrying
            await asyncio.sleep(0.1)

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    @property
    def available_tokens(self) -> float:
        """Get current available tokens (approximate)."""
        self._refill()
        return self.tokens


class GeoService:
    """
    Service for resolving IP addresses to geographic locations.

    Resolution order (with fallbacks):
    1. In-memory LRU cache (instant)
    2. Database lookup for IPs resolved in last 24 hours
    3. ip-api.com API (rate-limited: 45 req/min)
    4. Mock database (IP prefix matching)
    5. Country center coordinates with jitter (ultimate fallback)

    Ensures the demo never crashes due to API rate limits or bans.
    """

    # Cache settings
    CACHE_TTL_SECONDS: int = 3600  # 1 hour
    MAX_CACHE_SIZE: int = 10000

    # Database lookup settings
    DB_LOOKUP_MAX_AGE_HOURS: int = 24

    # Rate limit settings (ip-api.com free tier)
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 45

    def __init__(self, backend: str = "mock", enable_db_lookup: bool = True):
        """
        Initialize the geo service.

        Args:
            backend: Backend to use ('mock' or 'ip-api')
            enable_db_lookup: Whether to check database for recent lookups
        """
        self.backend = backend
        self.enable_db_lookup = enable_db_lookup
        self._http_client = None
        self._cache = LRUCache(max_size=self.MAX_CACHE_SIZE, ttl_seconds=self.CACHE_TTL_SECONDS)
        self._rate_limiter = RateLimiter(requests_per_minute=self.RATE_LIMIT_REQUESTS_PER_MINUTE)
        self._api_failures = 0
        self._api_successes = 0
        self._db_hits = 0
        self._fallback_used = 0

    async def _get_http_client(self):
        """Get or create HTTP client for API calls."""
        if httpx is None:
            raise ImportError(
                "httpx is required for ip-api backend. Install with: pip install httpx"
            )
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0), headers={"User-Agent": "DDoS-Visualizer/1.0"}
            )
        return self._http_client

    async def close(self):
        """Close HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def _apply_jitter(self, location: GeoLocation) -> GeoLocation:
        """
        Apply random jitter to coordinates for visual diversity.

        Prevents multiple attacks to the same data center from appearing
        as a single thick line on the globe. Creates a 'swarm' effect.

        Args:
            location: Original GeoLocation.

        Returns:
            New GeoLocation with jittered coordinates.
        """
        jitter_lat = random.uniform(-0.5, 0.5)
        jitter_lon = random.uniform(-0.5, 0.5)

        return GeoLocation(
            ip=location.ip,
            country=location.country,
            country_code=location.country_code,
            city=location.city,
            lat=location.lat + jitter_lat,
            lon=location.lon + jitter_lon,
            isp=location.isp,
            source=location.source,
        )

    def _get_country_fallback(self, country_code: str = "XX") -> GeoLocation:
        """
        Get fallback coordinates for a country with random jitter.

        Args:
            country_code: Two-letter country code.

        Returns:
            GeoLocation with jittered country center coordinates.
        """
        self._fallback_used += 1

        coords = COUNTRY_CENTER_COORDS.get(country_code, COUNTRY_CENTER_COORDS["XX"])
        jitter = coords["jitter"]

        return GeoLocation(
            ip="0.0.0.0",
            country=coords["name"],
            country_code=country_code,
            city="Unknown",
            lat=coords["lat"] + random.uniform(-jitter, jitter),
            lon=coords["lon"] + random.uniform(-jitter, jitter),
            source="country_fallback",
        )

    def _resolve_mock(self, ip: str) -> GeoLocation:
        """
        Resolve IP using mock database.

        Args:
            ip: IP address to resolve.

        Returns:
            GeoLocation with coordinates.
        """
        # Try to match IP prefix
        for prefix, data in MOCK_GEO_DATABASE.items():
            if ip.startswith(prefix):
                return GeoLocation(
                    ip=ip,
                    country=data["country"],
                    country_code=data["country_code"],
                    city=data["city"],
                    lat=data["lat"] + random.uniform(-0.5, 0.5),
                    lon=data["lon"] + random.uniform(-0.5, 0.5),
                    source="mock",
                )

        # Fallback to random location from fallback list
        fallback = random.choice(FALLBACK_LOCATIONS)
        return GeoLocation(
            ip=ip,
            country=fallback["country"],
            country_code=fallback["country_code"],
            city=fallback["city"],
            lat=fallback["lat"] + random.uniform(-1, 1),
            lon=fallback["lon"] + random.uniform(-1, 1),
            source="mock_fallback",
        )

    async def _lookup_from_database(self, ip: str) -> GeoLocation | None:
        """
        Look up IP in database from recent attack events.

        Checks if this IP was resolved in the last 24 hours.

        Args:
            ip: IP address to look up.

        Returns:
            GeoLocation if found in recent records, None otherwise.
        """
        if not self.enable_db_lookup:
            return None

        try:
            from sqlalchemy import or_, select

            from database import async_session_maker
            from models import AttackEvent

            cutoff = datetime.now(UTC) - timedelta(hours=self.DB_LOOKUP_MAX_AGE_HOURS)

            async with async_session_maker() as session:
                # Look for this IP as source or target in recent events
                stmt = (
                    select(AttackEvent)
                    .where(
                        AttackEvent.timestamp >= cutoff,
                        or_(AttackEvent.source_ip == ip, AttackEvent.target_ip == ip),
                    )
                    .order_by(AttackEvent.timestamp.desc())
                    .limit(1)
                )

                result = await session.execute(stmt)
                event = result.scalar_one_or_none()

                if event:
                    self._db_hits += 1

                    # Determine if this IP was source or target
                    if event.source_ip == ip:
                        return GeoLocation(
                            ip=ip,
                            country="Database",
                            country_code="XX",
                            city="Cached",
                            lat=event.source_lat,
                            lon=event.source_lon,
                            source="database",
                        )
                    else:
                        return GeoLocation(
                            ip=ip,
                            country="Database",
                            country_code="XX",
                            city="Cached",
                            lat=event.target_lat,
                            lon=event.target_lon,
                            source="database",
                        )

        except Exception as e:
            logger.debug(f"Database lookup failed for {ip}: {e}")

        return None

    async def _resolve_ip_api(self, ip: str) -> GeoLocation | None:
        """
        Resolve IP using ip-api.com with rate limiting.

        Rate limit: 45 requests/minute for free tier.

        Args:
            ip: IP address to resolve.

        Returns:
            GeoLocation if successful, None if rate limited or failed.
        """
        # Check rate limit first
        if not await self._rate_limiter.acquire(timeout=2.0):
            logger.warning(f"Rate limit hit for ip-api.com, skipping API call for {ip}")
            return None

        try:
            client = await self._get_http_client()

            response = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,city,lat,lon,isp"},
            )

            # Handle rate limit response
            if response.status_code == 429:
                logger.warning("ip-api.com returned 429 Too Many Requests")
                self._api_failures += 1
                return None

            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                self._api_successes += 1
                return GeoLocation(
                    ip=ip,
                    country=data.get("country", "Unknown"),
                    country_code=data.get("countryCode", "XX"),
                    city=data.get("city", "Unknown"),
                    lat=data.get("lat", 0.0),
                    lon=data.get("lon", 0.0),
                    isp=data.get("isp"),
                    source="ip-api",
                )
            else:
                logger.debug(f"ip-api.com returned failure for {ip}: {data.get('message')}")
                self._api_failures += 1
                return None

        except httpx.TimeoutException:
            logger.warning(f"Timeout calling ip-api.com for {ip}")
            self._api_failures += 1
            return None

        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error from ip-api.com for {ip}: {e.response.status_code}")
            self._api_failures += 1
            return None

        except Exception as e:
            logger.warning(f"Error calling ip-api.com for {ip}: {e}")
            self._api_failures += 1
            return None

    async def resolve(self, ip: str) -> GeoLocation:
        """
        Resolve IP address to geographic location.

        Resolution order (with fallbacks):
        1. In-memory LRU cache (instant)
        2. Database lookup for IPs resolved in last 24 hours
        3. ip-api.com API (rate-limited: 45 req/min)
        4. Mock database (IP prefix matching)
        5. Country center coordinates with jitter (ultimate fallback)

        Args:
            ip: IP address to resolve.

        Returns:
            GeoLocation with country, city, and coordinates.
        """
        # 1. Check LRU cache first
        cached = self._cache.get(ip)
        if cached is not None:
            # Apply jitter even to cached results for visual diversity
            return self._apply_jitter(cached)

        location = None

        # 2. Check database for recent lookups
        if self.enable_db_lookup:
            location = await self._lookup_from_database(ip)

        # 3. Try ip-api.com if using that backend
        if location is None and self.backend == "ip-api":
            location = await self._resolve_ip_api(ip)

        # 4. Fall back to mock database
        if location is None:
            location = self._resolve_mock(ip)

        # Store in cache (without jitter - jitter applied on retrieval)
        self._cache.put(ip, location)

        # Apply jitter for visual diversity (prevents overlapping attack lines)
        return self._apply_jitter(location)

    def clear_cache(self) -> None:
        """Clear the entire geo cache."""
        self._cache.clear()

    def get_cache_stats(self) -> dict:
        """
        Get comprehensive service statistics.

        Returns:
            Dict with cache, API, and database stats.
        """
        return {
            "cache": self._cache.stats,
            "api": {
                "successes": self._api_successes,
                "failures": self._api_failures,
                "rate_limit_tokens": round(self._rate_limiter.available_tokens, 1),
            },
            "database_hits": self._db_hits,
            "fallback_used": self._fallback_used,
            "backend": self.backend,
        }

    async def resolve_batch(self, ips: list[str]) -> list[GeoLocation]:
        """
        Resolve multiple IP addresses.

        Args:
            ips: List of IP addresses.

        Returns:
            List of GeoLocation objects.
        """
        results = []
        for ip in ips:
            results.append(await self.resolve(ip))
        return results


# Default service instance (using mock)
_geo_service: GeoService | None = None


def get_geo_service(backend: str = "mock", enable_db_lookup: bool = True) -> GeoService:
    """
    Get or create the geo service instance.

    If the requested backend differs from the existing service,
    the service will be recreated with the new backend.

    Args:
        backend: Backend to use ('mock' or 'ip-api')
        enable_db_lookup: Whether to check database for recent lookups

    Returns:
        GeoService instance.
    """
    global _geo_service

    # Check if we need to create or recreate the service
    if _geo_service is None or _geo_service.backend != backend:
        _geo_service = GeoService(backend=backend, enable_db_lookup=enable_db_lookup)

    return _geo_service


def reset_geo_service() -> None:
    """Reset the global geo service instance (for testing)."""
    global _geo_service
    _geo_service = None


# Convenience function
async def resolve_ip(ip: str, backend: str = "mock") -> GeoLocation:
    """
    Resolve a single IP to location using default service.

    Args:
        ip: IP address to resolve.
        backend: Backend to use ('mock' or 'ip-api')

    Returns:
        GeoLocation with coordinates.
    """
    service = get_geo_service(backend=backend)
    return await service.resolve(ip)


# CLI for testing
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    parser = argparse.ArgumentParser(description="Geo-location Service CLI")
    parser.add_argument("--ip", type=str, help="IP address to resolve")
    parser.add_argument(
        "--backend", choices=["mock", "ip-api"], default="mock", help="Backend to use"
    )
    parser.add_argument("--stats", action="store_true", help="Show service stats")
    parser.add_argument("--test-batch", type=int, help="Resolve N random IPs for testing")

    args = parser.parse_args()

    async def main():
        service = get_geo_service(backend=args.backend)

        try:
            if args.ip:
                print(f"\nResolving {args.ip} using {args.backend} backend...")
                location = await service.resolve(args.ip)
                print(f"  Country: {location.country} ({location.country_code})")
                print(f"  City: {location.city}")
                print(f"  Coordinates: {location.lat:.4f}, {location.lon:.4f}")
                print(f"  Source: {location.source}")
                if location.isp:
                    print(f"  ISP: {location.isp}")

            if args.test_batch:
                print(f"\nResolving {args.test_batch} random IPs...")
                test_ips = [
                    f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    for _ in range(args.test_batch)
                ]
                for ip in test_ips:
                    location = await service.resolve(ip)
                    print(
                        f"  {ip} -> {location.country} ({location.lat:.2f}, {location.lon:.2f}) [{location.source}]"
                    )

            if args.stats or args.ip or args.test_batch:
                print("\nService Statistics:")
                stats = service.get_cache_stats()
                print(f"  Backend: {stats['backend']}")
                print(f"  Cache size: {stats['cache']['size']}/{stats['cache']['max_size']}")
                print(f"  Cache hit rate: {stats['cache']['hit_rate_percent']}%")
                print(f"  API successes: {stats['api']['successes']}")
                print(f"  API failures: {stats['api']['failures']}")
                print(f"  Rate limit tokens: {stats['api']['rate_limit_tokens']}")
                print(f"  Database hits: {stats['database_hits']}")
                print(f"  Fallback used: {stats['fallback_used']}")

        finally:
            await service.close()

    asyncio.run(main())
