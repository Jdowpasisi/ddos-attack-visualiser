"""
AI-powered threat briefing service using Groq LLM.

Generates concise threat intelligence summaries from recent DDoS event data.
"""

import json
import logging
import os
from collections import Counter
from datetime import UTC, datetime

from groq import AsyncGroq

logger = logging.getLogger(__name__)

# ── Groq client ──
_groq_client: AsyncGroq | None = None


def _get_client() -> AsyncGroq:
    global _groq_client
    if _groq_client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        _groq_client = AsyncGroq(api_key=api_key)
    return _groq_client


# ── Cache ──
BRIEFING_CACHE_SECONDS = 60
_cached_briefing: str = "Awaiting first threat analysis cycle."
_last_generated: datetime = datetime(2000, 1, 1, tzinfo=UTC)

# ── System prompt ──
SYSTEM_PROMPT = (
    "You are a Senior Threat Intelligence Analyst. "
    "You have access to both raw DDoS telemetry and structured findings from an autonomous "
    "investigation agent. Prioritize the agent findings over raw event data. "
    "If repeat attackers or coordinated campaigns are present, lead with them. "
    "When 'Verified 5-minute window metrics' are supplied, you MUST use those exact "
    "figures verbatim — never contradict them. "
    "Respond with exactly 3 sentences: "
    "1) Dominant threat pattern (draw on agent findings first, raw events second). "
    "2) Severity and persistence assessment (escalating, sustained, or declining). "
    "3) Actionable intelligence — reference agent recommendations where available. "
    "Be technical and precise. No preamble. Maximum 90 words."
)

_DEFAULT_MSG = "No recent events to analyze. System nominal."


def _build_agent_context(recent_incidents: list[dict]) -> str:
    """Build a structured text summary of agent investigation findings.

    Args:
        recent_incidents: List of serialized IncidentReport dicts.

    Returns:
        Multi-line string to prepend to the LLM user message, or empty string
        if no incidents were provided.
    """
    if not recent_incidents:
        return ""

    total = len(recent_incidents)
    repeat_attackers = [i for i in recent_incidents if i.get("is_repeat_attacker")]
    campaigns = [i for i in recent_incidents if i.get("campaign_detected")]
    critical = [
        i for i in recent_incidents
        if (i.get("severity_score") or 0) >= 8 or (i.get("threat_level") or "").lower() == "critical"
    ]

    lines: list[str] = [
        "=== AUTONOMOUS AGENT INVESTIGATION FINDINGS ===",
        f"Total recent incidents: {total} | "
        f"Repeat attackers: {len(repeat_attackers)} | "
        f"Campaigns detected: {len(campaigns)}",
    ]

    # Top 3 repeat attackers
    if repeat_attackers:
        lines.append("\nTop repeat attackers:")
        for inc in repeat_attackers[:3]:
            pattern = inc.get("pattern_summary") or "N/A"
            lines.append(
                f"  - IP {inc.get('source_ip', '?')} | "
                f"Type: {inc.get('attack_type', '?')} | "
                f"Threat: {inc.get('threat_level', '?')} | "
                f"Pattern: {pattern}"
            )

    # Critical incidents (up to 3)
    if critical:
        lines.append("\nCritical-severity incidents:")
        for inc in critical[:3]:
            lines.append(
                f"  - IP {inc.get('source_ip', '?')} | "
                f"Type: {inc.get('attack_type', '?')} | "
                f"Severity: {inc.get('severity_score', '?')} | "
                f"Threat: {inc.get('threat_level', '?')}"
            )

    # Most common recommended action
    actions = [i.get("recommended_action") for i in recent_incidents if i.get("recommended_action")]
    if actions:
        most_common_action, _ = Counter(actions).most_common(1)[0]
        lines.append(f"\nMost common agent recommendation: {most_common_action}")

    lines.append("=" * 47)
    return "\n".join(lines)


async def generate_threat_briefing(
    recent_events: list[dict],
    peak_packet_rate: int = 0,
    avg_severity: float = 0.0,
    recent_incidents: list[dict] | None = None,
) -> str:
    """Generate a 3-sentence threat briefing from recent attack events.

    Args:
        recent_events: List of recent attack event dicts.
        peak_packet_rate: Peak packet rate (pps) observed in the last 5 minutes.
        avg_severity: Average severity score in the last 5 minutes.
        recent_incidents: Optional list of serialized IncidentReport dicts from
            the autonomous investigation agent.

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

    kpps = round(peak_packet_rate / 1000, 1)
    verified_context = (
        f"Verified 5-minute window metrics (use these exact numbers): "
        f"Peak packet rate: {kpps}k pps, Average severity: {avg_severity}/10"
    )

    agent_context = _build_agent_context(recent_incidents or [])
    n_incidents = len(recent_incidents) if recent_incidents else 0

    parts: list[str] = []
    if agent_context:
        parts.append(agent_context)
    parts.append(verified_context)
    parts.append(json.dumps({"events": summary}))
    user_message = "\n\n".join(parts)

    try:
        client = _get_client()
        response = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.4,
            max_tokens=200,
        )

        text = response.choices[0].message.content or _DEFAULT_MSG
        _cached_briefing = text.strip()
        _last_generated = datetime.now(UTC)
        logger.info("[Briefing] Generated from: raw events, %d agent reports.", n_incidents)
        return _cached_briefing

    except Exception as exc:
        # On API/network failure, return stale cache or error message
        if _cached_briefing and _cached_briefing != _DEFAULT_MSG:
            return _cached_briefing
        return f"Briefing unavailable: {exc}"
