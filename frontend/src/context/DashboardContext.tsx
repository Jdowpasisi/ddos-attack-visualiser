/**
 * DashboardContext – single heartbeat that drives all dashboard data.
 *
 * All four API endpoints (stream, stats, briefing, incidents) are polled
 * together via Promise.allSettled so a failure in one never blocks the others.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react';

import type { AttackStats } from '../components/CyberDashboard';
import { FETCH_INTERVAL_MS } from '../constants';

const API_BASE_URL =
  import.meta.env.VITE_API_URL ??
  import.meta.env.VITE_API_BASE_URL ??
  'http://localhost:8000';

const WS_BASE_URL = import.meta.env.VITE_WS_URL ?? 'ws://localhost:8000';
const WS_INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;
const BACKOFF_MULTIPLIER = 2;
const MAX_ARCS = 100;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface StreamAttack {
  id: number;
  srcLat: number;
  srcLon: number;
  tgtLat: number;
  tgtLon: number;
  color: string;
  strokeWidth: number;
  attackType: string;
  severity: number;
  packetRate: number;
  timestamp: string;
  sourceIp: string;
  targetIp: string;
}

export interface IncidentReport {
  id: number;
  attack_event_id: number | null;
  source_ip: string;
  attack_type: string;
  severity_score: number;
  ip_reputation_summary: string | null;
  cve_findings: string | null;
  trend_context: string | null;
  threat_level: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  summary: string;
  recommended_action: string;
  is_repeat_attacker: boolean;
  campaign_detected: boolean;
  pattern_summary: string | null;
  tools_called: string | null;
  generated_at: string;
}

export interface DashboardSnapshot {
  /** New attacks from the stream endpoint since last poll. */
  attacks: StreamAttack[];
  /** Highest attack ID seen so far – used as cursor for incremental polling. */
  latestId: number;
  /** Number of events still queued on the server not yet delivered. */
  backlog: number;
  /** Aggregated stats for the last 5-minute window. */
  stats: AttackStats | null;
  /** Latest AI threat briefing text. */
  briefing: string;
  /** Number of events the briefing was generated from. */
  briefingEventCount: number;
  /** Number of agent incident reports included in the briefing. */
  briefingIncidentCount: number;
  /** Number of repeat attackers identified in the briefing window. */
  repeatAttackers: number;
  /** Number of campaigns detected in the briefing window. */
  campaignsDetected: number;
  /** Most recent incident reports from the AI investigator agent. */
  incidents: IncidentReport[];
  /** Unix ms timestamp when this snapshot was assembled. */
  snapshotAt: number;
}

interface DashboardContextValue {
  snapshot: DashboardSnapshot;
  isPaused: boolean;
  setIsPaused: (paused: boolean) => void;
  togglePause: () => void;
  wsStatus: 'connecting' | 'connected' | 'disconnected';
}

// ── Defaults ──────────────────────────────────────────────────────────────────

const DEFAULT_SNAPSHOT: DashboardSnapshot = {
  attacks: [],
  latestId: 0,
  backlog: 0,
  stats: null,
  briefing: 'Awaiting threat data…',
  briefingEventCount: 0,
  briefingIncidentCount: 0,
  repeatAttackers: 0,
  campaignsDetected: 0,
  incidents: [],
  snapshotAt: 0,
};

// ── Context ───────────────────────────────────────────────────────────────────

const DashboardContext = createContext<DashboardContextValue>({
  snapshot: DEFAULT_SNAPSHOT,
  isPaused: false,
  setIsPaused: () => undefined,
  togglePause: () => undefined,
  wsStatus: 'disconnected',
});

// ── Provider ──────────────────────────────────────────────────────────────────

export const DashboardProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(DEFAULT_SNAPSHOT);
  const [isPaused, setIsPaused] = useState(false);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected');
  const [attacks, setAttacks] = useState<StreamAttack[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef<number>(WS_INITIAL_BACKOFF_MS);
  const isPausedRef = useRef<boolean>(false);

  // Keep isPausedRef in sync with state on every render.
  isPausedRef.current = isPaused;

  // ── HTTP polling: stats / briefing / incidents ───────────────────────────

  const fetchAll = useCallback(async () => {
    const [statsResult, briefingResult, incidentsResult] =
      await Promise.allSettled([
        fetch(`${API_BASE_URL}/api/v1/attacks/stats`).then((r) => {
          if (!r.ok) throw new Error(`stats ${r.status}`);
          return r.json();
        }),
        fetch(`${API_BASE_URL}/api/v1/intel/briefing`, {
          // Briefing calls Groq; cap at 15 s so a slow/failing LLM response
          // never blocks Promise.allSettled and freezes stats + incidents.
          signal: AbortSignal.timeout(15000),
        }).then((r) => {
          if (!r.ok) throw new Error(`briefing ${r.status}`);
          return r.json();
        }),
        fetch(`${API_BASE_URL}/api/v1/incidents?limit=50`).then((r) => {
          if (!r.ok) throw new Error(`incidents ${r.status}`);
          return r.json();
        }),
      ]);

    setSnapshot((prev) => {
      const stats: AttackStats | null =
        statsResult.status === 'fulfilled'
          ? (statsResult.value as AttackStats)
          : prev.stats;

      const briefing: string =
        briefingResult.status === 'fulfilled'
          ? (briefingResult.value.briefing ?? prev.briefing)
          : prev.briefing;

      const briefingEventCount: number =
        briefingResult.status === 'fulfilled'
          ? (briefingResult.value.event_count ?? prev.briefingEventCount)
          : prev.briefingEventCount;

      const briefingIncidentCount: number =
        briefingResult.status === 'fulfilled'
          ? (briefingResult.value.incident_count ?? 0)
          : prev.briefingIncidentCount;

      const repeatAttackers: number =
        briefingResult.status === 'fulfilled'
          ? (briefingResult.value.repeat_attackers ?? 0)
          : prev.repeatAttackers;

      const campaignsDetected: number =
        briefingResult.status === 'fulfilled'
          ? (briefingResult.value.campaigns_detected ?? 0)
          : prev.campaignsDetected;

      const incidents: IncidentReport[] =
        incidentsResult.status === 'fulfilled'
          ? (incidentsResult.value.reports ?? prev.incidents)
          : prev.incidents;

      return {
        ...prev,
        stats,
        briefing,
        briefingEventCount,
        briefingIncidentCount,
        repeatAttackers,
        campaignsDetected,
        incidents,
        snapshotAt: Date.now(),
      };
    });
  }, []);

  // Kick off an immediate fetch then poll on the heartbeat interval.
  useEffect(() => {
    if (!isPaused) {
      fetchAll();
    }

    const id = setInterval(() => {
      if (!isPaused) {
        fetchAll();
      }
    }, FETCH_INTERVAL_MS);

    return () => clearInterval(id);
  }, [isPaused, fetchAll]);

  // ── WebSocket connection ─────────────────────────────────────────────────

  const connectWebSocket = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(`${WS_BASE_URL}/api/v1/ws/attacks`);
    wsRef.current = ws;
    setWsStatus('connecting');

    ws.onopen = () => {
      setWsStatus('connected');
      backoffRef.current = WS_INITIAL_BACKOFF_MS;
    };

    ws.onmessage = (event) => {
      if (isPausedRef.current) return;
      try {
        const msg = JSON.parse(event.data as string) as {
          type: string;
          attacks?: StreamAttack[];
          attack?: StreamAttack;
        };
        if (msg.type === 'ping') return;
        if (msg.type === 'initial') {
          setAttacks(msg.attacks ?? []);
          return;
        }
        if (msg.type === 'attack' && msg.attack) {
          // Add this diagnostic log
          console.log('[WS] Attack received:', msg.attack?.attackType, new Date().toISOString());

          setAttacks((prev) => {
            const updated = [...prev, msg.attack!];
            return updated.slice(-MAX_ARCS);
          });
        }
      } catch (e) {
        console.error('[WS] Message parse error:', e);
      }
    };

    ws.onclose = () => {
      setWsStatus('disconnected');
      wsRef.current = null;
      const delay = backoffRef.current;
      backoffRef.current = Math.min(delay * BACKOFF_MULTIPLIER, MAX_BACKOFF_MS);
      setTimeout(() => connectWebSocket(), delay);
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      ws.close();
    };
  }, []);

  useEffect(() => {
    connectWebSocket();
    return () => {
      wsRef.current?.close();
    };
  }, [connectWebSocket]);

  const togglePause = useCallback(
    () => setIsPaused((p) => !p),
    [],
  );

  return (
    <DashboardContext.Provider
      value={{ snapshot: { ...snapshot, attacks }, isPaused, setIsPaused, togglePause, wsStatus }}
    >
      {children}
    </DashboardContext.Provider>
  );
};

// ── Consumer hook ─────────────────────────────────────────────────────────────

export const useDashboard = (): DashboardContextValue =>
  useContext(DashboardContext);
