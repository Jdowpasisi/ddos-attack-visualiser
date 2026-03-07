"""
Configuration constants for the DDoS Attack Map backend.
"""

import os

# Background ingestion configuration
INGESTION_INTERVAL_SECONDS = int(os.getenv("INGESTION_INTERVAL_SECONDS", "10"))
INGESTION_BATCH_SIZE = int(os.getenv("INGESTION_BATCH_SIZE", "5"))
BLACKLIST_REFRESH_HOURS = 24  # Refresh AbuseIPDB blacklist every 24 hours

# Display rate limiting configuration
DISPLAY_RATE_PER_SECOND = float(os.getenv("DISPLAY_RATE_PER_SECOND", "3.0"))
FRONTEND_POLL_INTERVAL_SECONDS = 5

# Maximum events to return in one /stream request
EVENTS_PER_POLL = max(1, int(DISPLAY_RATE_PER_SECOND * FRONTEND_POLL_INTERVAL_SECONDS))
