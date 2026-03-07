"""
AI-powered threat briefing service using Groq LLM.

Generates concise threat intelligence summaries from recent DDoS event data.
"""

import json
import os
from datetime import UTC, datetime

from groq import Groq

# ── Groq client ──
_groq_client: Groq | None = None


def _get_client() -> Groq:
    global _groq_client
    if _groq_client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        _groq_client = Groq(api_key=api_key)
    return _groq_client


# ── Cache ──
BRIEFING_CACHE_SECONDS = 60
_cached_briefing: str = "Awaiting first threat analysis cycle."
_last_generated: datetime = datetime(2000, 1, 1, tzinfo=UTC)

# ── System prompt ──
SYSTEM_PROMPT = (
    "You are a Senior Threat Intelligence Analyst. "
    "Analyze the provided JSON array of recent DDoS attack events. "
    "Respond with exactly 3 sentences: "
    "1) Pattern – the dominant attack pattern observed. "
    "2) Trend – whether activity is escalating, stable, or declining. "
    "3) Anomaly – any outlier or unusual characteristic worth noting. "
    "Be technical and precise. No preamble. Maximum 80 words."
)

_DEFAULT_MSG = "No recent events to analyze. System nominal."


async def generate_threat_briefing(recent_events: list[dict]) -> str:
    """Generate a 3-sentence threat briefing from recent attack events.

    Results are cached for BRIEFING_CACHE_SECONDS to avoid excessive API calls.
    """
    global _cached_briefing, _last_generated

    # Return cache if still fresh
    age = (datetime.now(UTC) - _last_generated).total_seconds()
    if age < BRIEFING_CACHE_SECONDS:
        return _cached_briefing

    if not recent_events:
        _cached_briefing = _DEFAULT_MSG
        _last_generated = datetime.now(UTC)
        return _cached_briefing

    # Summarise to essential fields, cap at 20 events
    summary = [
        {
            "attack_type": e.get("attack_type", "unknown"),
            "severity_score": e.get("severity_score", 0),
            "packet_rate_kpps": round(e.get("packet_rate", 0) / 1000, 1),
            "source_country": e.get("source_country", "??"),
            "timestamp": e.get("timestamp", ""),
        }
        for e in recent_events[:20]
    ]

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(summary)},
            ],
            temperature=0.4,
            max_tokens=200,
        )

        text = response.choices[0].message.content or _DEFAULT_MSG
        _cached_briefing = text.strip()
        _last_generated = datetime.now(UTC)
        return _cached_briefing

    except Exception as exc:
        # On API/network failure, return stale cache or error message
        if _cached_briefing and _cached_briefing != _DEFAULT_MSG:
            return _cached_briefing
        return f"Briefing unavailable: {exc}"
