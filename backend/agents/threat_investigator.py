"""
Autonomous Threat Investigator Agent.

Uses Groq (llama-3.3-70b-versatile) with function-calling to investigate
DDoS attack events, gather threat intelligence, and produce structured
incident reports.
"""

import asyncio
import json
import logging
import os
import re
import sys
from pathlib import Path

import httpx
from datetime import UTC, datetime, timedelta
from groq import AsyncGroq, BadRequestError
from sqlalchemy import or_, select

# Ensure the backend directory is on the path when this module is imported
# directly (e.g. during testing outside of uvicorn).
_backend_dir = Path(__file__).parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from database import async_session_maker  # noqa: E402
from models import IncidentReport, IPReputation  # noqa: E402

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global agent status — updated throughout investigate_threat so the API can
# surface real-time progress to the frontend.
# ---------------------------------------------------------------------------

_agent_status: dict = {
    "is_active": False,
    "current_tool": None,
    "event_id": None,
    "attack_type": None,
    "source_ip": None,
    "tools_completed": [],
    "started_at": None,
}


def get_agent_status() -> dict:
    return _agent_status.copy()


# ---------------------------------------------------------------------------
# Groq client (lazy — instantiated on first use so GROQ_API_KEY is always set)
# ---------------------------------------------------------------------------

_groq_client: AsyncGroq | None = None


def _get_client() -> AsyncGroq:
    global _groq_client
    if _groq_client is None:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        _groq_client = AsyncGroq(api_key=api_key)
    return _groq_client

# ---------------------------------------------------------------------------
# Tool definitions — JSON Schema for Groq function-calling
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "find_related_incidents",
            "description": (
                "Search the incident database for prior investigations involving this source IP or attack type. "
                "ALWAYS call this first before any other tool. The result determines which other tools to call "
                "and whether to escalate threat level."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "The source IP address of the current attack event.",
                    },
                    "attack_type": {
                        "type": "string",
                        "description": "The DDoS attack type of the current event.",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "How many hours of history to search. Defaults to 24.",
                    },
                },
                "required": ["source_ip", "attack_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_ip_reputation",
            "description": (
                "Look up reputation data for an IP address from the local database. "
                "Returns abuse score, ISP, country, total abuse reports, and data freshness."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IPv4 or IPv6 address to look up.",
                    }
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_cve_data",
            "description": (
                "Search the NVD (National Vulnerability Database) for CVEs related to a "
                "keyword such as an attack type or protocol. Returns up to 3 recent CVEs."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": (
                            "Search keyword, e.g. 'SYN flood', 'DNS amplification', 'NTP reflection'."
                        ),
                    }
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_attack_trend",
            "description": (
                "Retrieve trend data and contextual threat analysis for a given DDoS attack type."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "description": "The DDoS attack type, e.g. 'SYN Flood', 'UDP Flood', 'HTTP Flood'.",
                    }
                },
                "required": ["attack_type"],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


async def find_related_incidents(
    source_ip: str,
    attack_type: str,
    hours_back: int = 24,
) -> dict:
    """Search IncidentReport history for the same source IP or attack type."""
    cutoff = datetime.now(UTC) - timedelta(hours=hours_back)

    async with async_session_maker() as session:
        result = await session.execute(
            select(IncidentReport)
            .where(
                IncidentReport.generated_at >= cutoff,
                or_(
                    IncidentReport.source_ip == source_ip,
                    IncidentReport.attack_type == attack_type,
                ),
            )
            .order_by(IncidentReport.generated_at.asc())
            .limit(10)
        )
        rows = result.scalars().all()

    ip_matches = [r for r in rows if r.source_ip == source_ip]
    type_matches = [r for r in rows if r.attack_type == attack_type]

    is_repeat_attacker = len(ip_matches) >= 2
    is_campaign = (not is_repeat_attacker) and len(type_matches) >= 4

    severity_trend: str | None = None
    if len(ip_matches) >= 2:
        first_score = ip_matches[0].severity_score
        last_score = ip_matches[-1].severity_score
        if last_score > first_score:
            severity_trend = "escalating"
        elif last_score < first_score:
            severity_trend = "declining"
        else:
            severity_trend = "stable"

    if is_repeat_attacker and severity_trend == "escalating":
        recommended_focus = (
            "Repeat attacker with escalating severity. Skip trend analysis; "
            "focus on CVEs and consider immediate IP block."
        )
    elif is_repeat_attacker:
        recommended_focus = (
            "Known repeat attacker. Confirm reputation via lookup_ip_reputation "
            "and fetch CVE data for the attack type."
        )
    elif is_campaign:
        recommended_focus = (
            "Coordinated campaign detected (4+ incidents of this type). "
            "Call get_attack_trend to assess scope; cross-reference CVEs."
        )
    elif rows:
        recommended_focus = (
            "Some prior activity found. Proceed with all three remaining tools "
            "for a complete assessment."
        )
    else:
        recommended_focus = (
            "No prior incidents found. Proceed with lookup_ip_reputation, "
            "fetch_cve_data, and get_attack_trend for a baseline assessment."
        )

    return {
        "source_ip": source_ip,
        "attack_type": attack_type,
        "hours_back": hours_back,
        "total_related": len(rows),
        "ip_match_count": len(ip_matches),
        "type_match_count": len(type_matches),
        "is_repeat_attacker": is_repeat_attacker,
        "is_campaign": is_campaign,
        "severity_trend": severity_trend,
        "recommended_focus": recommended_focus,
    }


async def lookup_ip_reputation(ip: str) -> dict:
    """Query the IPReputation table for the given IP address."""
    async with async_session_maker() as session:
        result = await session.execute(
            select(IPReputation).where(IPReputation.ip == ip)
        )
        record = result.scalar_one_or_none()

    if record is None:
        return {
            "ip": ip,
            "found": False,
            "message": "No reputation data on record for this IP.",
        }
    return {
        "ip": record.ip,
        "found": True,
        "abuse_score": record.abuse_score,
        "country_code": record.country_code,
        "isp": record.isp,
        "domain": record.domain,
        "total_reports": record.total_reports,
        "source": record.source,
        "is_fresh": record.is_fresh(),
    }


async def fetch_cve_data(keyword: str) -> dict:
    """Search the NVD CVE API for CVEs matching the keyword (top 3 results)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": 3}
    try:
        async with httpx.AsyncClient(timeout=15.0) as http:
            response = await http.get(url, params=params)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning("NVD CVE lookup failed for keyword '%s': %s", keyword, exc)
        return {"keyword": keyword, "error": str(exc), "cves": []}

    cves: list[dict] = []
    for item in data.get("vulnerabilities", [])[:3]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )
        # Try CVSS v3.1, then v3.0, then v2 for a base score
        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                break
        cves.append({"id": cve_id, "description": description, "cvss_score": cvss_score})

    return {
        "keyword": keyword,
        "total_found": data.get("totalResults", 0),
        "cves": cves,
    }


# Static trend knowledge-base keyed on lowercase substrings of attack_type
_TREND_DATA: dict[str, dict] = {
    "syn": {
        "trend": "increasing",
        "context": (
            "SYN flood attacks rose ~34 % over the past quarter, frequently deployed "
            "in multi-vector volumetric campaigns targeting ISPs and hosting providers."
        ),
    },
    "udp": {
        "trend": "stable",
        "context": (
            "UDP amplification attacks remain a persistent threat; DNS and NTP "
            "reflectors continue to be the most exploited vectors."
        ),
    },
    "http": {
        "trend": "increasing",
        "context": (
            "HTTP flood and application-layer attacks have surged, targeting REST APIs, "
            "login pages, and CDN origins with high-frequency low-bandwidth requests."
        ),
    },
    "icmp": {
        "trend": "decreasing",
        "context": (
            "ICMP flood attacks have declined following widespread BCP 38 adoption; "
            "still observed from misconfigured legacy networks."
        ),
    },
    "dns": {
        "trend": "increasing",
        "context": (
            "DNS amplification remains one of the highest-bandwidth DDoS vectors, "
            "with open resolvers still widely abused despite years of mitigation guidance."
        ),
    },
    "ntp": {
        "trend": "stable",
        "context": (
            "NTP reflection volumes are steady; most major ISPs now filter MONLIST "
            "requests, limiting amplification potential."
        ),
    },
    "slowloris": {
        "trend": "stable",
        "context": (
            "Slow HTTP / Slowloris attacks persist against under-tuned web servers "
            "that lack connection-timeout and max-connection policies."
        ),
    },
}


async def get_attack_trend(attack_type: str) -> dict:
    """Return mocked trend data and contextual analysis for the given attack type."""
    at = attack_type.lower()
    for key, data in _TREND_DATA.items():
        if key in at:
            return {"attack_type": attack_type, **data}
    return {
        "attack_type": attack_type,
        "trend": "stable",
        "context": (
            f"No specific trend data available for '{attack_type}'. "
            "Monitor baseline traffic and cross-reference with threat intelligence feeds."
        ),
    }


# ---------------------------------------------------------------------------
# Tool dispatch map
# ---------------------------------------------------------------------------

TOOL_MAP: dict = {
    "find_related_incidents": find_related_incidents,
    "lookup_ip_reputation": lookup_ip_reputation,
    "fetch_cve_data": fetch_cve_data,
    "get_attack_trend": get_attack_trend,
}

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "You are a DDoS threat analyst. Follow this Investigation Protocol exactly:\n\n"
    "STEP 1 — ALWAYS call find_related_incidents first (source_ip, attack_type).\n"
    "  Inspect the result carefully before proceeding.\n\n"
    "STEP 2 — ALWAYS call lookup_ip_reputation for the source IP.\n\n"
    "STEP 3 — Branch based on find_related_incidents output:\n"
    "  • is_repeat_attacker = true  → call fetch_cve_data ONLY. "
    "Skip get_attack_trend (redundant for known attackers). "
    "Escalate threat_level by at least one tier above what reputation data suggests.\n"
    "  • is_campaign = true         → call BOTH get_attack_trend AND fetch_cve_data. "
    "Treat as coordinated infrastructure-level threat.\n"
    "  • Neither flag set (new/isolated event) → call get_attack_trend. "
    "Call fetch_cve_data only if the attack type maps to a known CVE vector "
    "(e.g. DNS amplification, NTP reflection, HTTP/2 rapid reset); otherwise skip it.\n\n"
    "THREAT LEVEL ASSESSMENT PROTOCOL:\n\n"
    "Step 1: Establish BASELINE THREAT LEVEL based strictly on the provided severity score:\n"
    "  - Severity 0.0 to 3.9  -> LOW\n"
    "  - Severity 4.0 to 5.9  -> MEDIUM\n"
    "  - Severity 6.0 to 7.9  -> HIGH\n"
    "  - Severity 8.0 to 10.0 -> CRITICAL\n\n"
    "Step 2: Apply ESCALATION RULES (only if applicable):\n"
    "  - If is_repeat_attacker = true: Escalate exactly ONE tier above the baseline. \n"
    "    (e.g., LOW becomes MEDIUM. MEDIUM becomes HIGH. HIGH becomes CRITICAL).\n"
    "  - NEVER escalate a LOW or MEDIUM baseline directly to CRITICAL in a single step.\n"
    "  - If severity_trend = \"escalating\": Note this explicitly in the summary, but do not jump additional tiers.\n"
    "  - Never downgrade a threat level based on prior incidents.\n\n"
    "After all required tool calls are complete, respond with ONLY a JSON object — "
    "no prose, no markdown, no code fences — with exactly these keys:\n"
    '{"threat_level": "low|medium|high|critical", '
    '"summary": "2-3 sentence synthesis of all findings", '
    '"recommended_action": "one concrete, actionable mitigation step", '
    '"is_repeat_attacker": true|false, '
    '"campaign_detected": true|false, '
    '"pattern_summary": "description of the attack pattern found, or null if no prior history"}'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_report_content(content: str) -> dict:
    """Strip markdown fences and JSON-parse an agent response."""
    content = content.strip()
    content = re.sub(r"^```(?:json)?\s*\n?", "", content)
    content = re.sub(r"\n?\s*```$", "", content.strip()).strip()
    try:
        report = json.loads(content)
    except json.JSONDecodeError:
        report = {}
    report.setdefault("threat_level", "unknown")
    report.setdefault("summary", content[:500] if content else "No summary provided.")
    report.setdefault("recommended_action", "Manual review required.")
    return report


async def _direct_completion(messages: list[dict]) -> dict:
    """
    Ask the model for a plain JSON report without any tools.

    Used as a fallback when the model generates a malformed tool call that
    Groq rejects with a ``tool_use_failed`` 400 error.
    """
    try:
        response = await _get_client().chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
        )
        content = response.choices[0].message.content or ""
        return _parse_report_content(content)
    except Exception as exc:
        logger.error("Fallback direct completion also failed: %s", exc)
        return {
            "threat_level": "unknown",
            "summary": "Agent failed to produce a report (tool-call error + fallback failure).",
            "recommended_action": "Manual review required.",
        }


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


async def investigate_threat(event: dict) -> dict:
    """
    Autonomously investigate a DDoS attack event using Groq tool-calling.

    The agent loops up to 6 times, executing tool calls as needed, then returns
    a structured report dict with at minimum: threat_level, summary,
    recommended_action.

    Args:
        event: A dict containing at minimum source_ip, attack_type, and
               severity_score (mirrors the AttackEvent model fields).

    Returns:
        A dict with keys threat_level, summary, recommended_action, plus any
        additional fields the model includes.
    """
    global _agent_status

    _agent_status = {
        "is_active": True,
        "current_tool": None,
        "event_id": event.get("id"),
        "attack_type": event.get("attack_type"),
        "source_ip": event.get("source_ip"),
        "tools_completed": [],
        "started_at": datetime.now(UTC).isoformat(),
    }

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Investigate the following DDoS attack event:\n\n"
                f"{json.dumps(event, indent=2)}"
            ),
        },
    ]

    tools_called: list[str] = []

    try:
        for iteration in range(6):
            logger.debug("Agent loop iteration %d/6", iteration + 1)

            try:
                response = await _get_client().chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    max_tokens=1000,
                )
            except BadRequestError as exc:
                # Groq rejects malformed tool-call generations (e.g. the model
                # emits `<function=...>` XML instead of structured JSON).  Fall
                # back to a tool-free completion so we still get a report.
                body = getattr(exc, "body", {}) or {}
                code = body.get("error", {}).get("code", "")
                if code == "tool_use_failed":
                    logger.warning(
                        "Iteration %d: model generated malformed tool call (%s); "
                        "retrying without tools.",
                        iteration + 1,
                        body.get("error", {}).get("failed_generation", "")[:120],
                    )
                    return await _direct_completion(messages)
                raise

            message = response.choices[0].message

            # Build a serialisable assistant turn before appending
            assistant_turn: dict = {"role": "assistant"}
            if message.content:
                assistant_turn["content"] = message.content
            if message.tool_calls:
                assistant_turn["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in message.tool_calls
                ]
            messages.append(assistant_turn)

            # --- Tool-call branch ---
            if message.tool_calls:
                for tool_call in message.tool_calls:
                    fn_name = tool_call.function.name
                    try:
                        fn_args = json.loads(tool_call.function.arguments)
                    except json.JSONDecodeError:
                        fn_args = {}

                    _agent_status["current_tool"] = fn_name
                    fn = TOOL_MAP.get(fn_name)
                    if fn is not None:
                        try:
                            result = await fn(**fn_args)
                        except Exception as exc:
                            logger.warning("Tool '%s' raised an exception: %s", fn_name, exc)
                            result = {"error": str(exc)}
                    else:
                        logger.warning("Unknown tool requested by agent: %s", fn_name)
                        result = {"error": f"Unknown tool: {fn_name}"}

                    tools_called.append(fn_name)
                    _agent_status["tools_completed"] = list(tools_called)
                    _agent_status["current_tool"] = None

                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": json.dumps(result),
                        }
                    )
                # Continue the loop with tool results now in context
                continue

            # --- Final report branch ---
            if message.content:
                _agent_status["current_tool"] = "complete"
                report = _parse_report_content(message.content)
                report["tools_called"] = ", ".join(tools_called) if tools_called else None
                return report

            # Neither tool calls nor content — unexpected model response
            logger.warning(
                "Agent loop iteration %d produced neither content nor tool calls.",
                iteration + 1,
            )
            break

        # Loop exhausted or broke without a final report
        return {
            "threat_level": "unknown",
            "summary": "Agent loop exhausted without producing a final report.",
            "recommended_action": "Manual review required.",
        }

    finally:
        await asyncio.sleep(2)
        _agent_status.update({
            "is_active": False,
            "current_tool": None,
            "event_id": None,
            "attack_type": None,
            "source_ip": None,
            "tools_completed": [],
            "started_at": None,
        })
