// CyberDashboard.tsx 
import React, { useMemo, useState, useEffect } from 'react';
import ArcDetailPanel from './ArcDetailPanel';
import AgentStatusWidget from './AgentStatusWidget';
import { ArcLegend } from './ArcLegend';
import BriefingPanel from './BriefingPanel';
import IncidentsPanel from './IncidentsPanel';
import StatsPanel from './StatsPanel';
import { useDashboard } from '../context/DashboardContext';

// ============ Types ============
export interface ThreatEvent {
  id: number;
  sourceIp: string;
  attackType: string;
  severity: number;
  timestamp: string;
  country?: string;
}

export interface StreamEntry {
  key: string;           // Unique ID: "sourceIp|attackType"
  sourceIp: string;
  attackType: string;
  severity: number;
  packetRate: number;
  hitCount: number;      // How many times this specific pattern occurred
  firstSeenAt: number;
  lastSeenAt: number;
  isNew: boolean;        // For animation
}

export interface AttackStats {
  window_minutes: number;
  current_count: number;
  prev_count: number;
  trend_pct: number;
  events_per_min: number;
  top_countries: { country: string; count: number }[];
  top_attack_types: { type: string; count: number; avg_severity: number }[];
  avg_severity_1m: number;
  avg_severity_5m: number;
  peak_packet_rate: number;
  generated_at: string;
}

export interface DashboardProps {
  threats: ThreatEvent[];
  arcs?: import('./AttackGlobe').GlobeArc[];
  stats?: AttackStats | null;
  totalEvents: number;
  arcCount?: number;
  arcMax?: number;
  isLive: boolean;
  error: string | null;
  backlog: number;
  isPaused?: boolean;
  onTogglePause?: () => void;
  selectedArc?: import('./AttackGlobe').GlobeArc | null;
  onDeselectArc?: () => void;
  serverStatus?: { label: string; lat: number; lon: number };
}

// ============ Utility Functions ============
const getSeverityClass = (severity: number): string => {
  if (severity <= 3) return 'threat-low';
  if (severity <= 6) return 'threat-medium';
  if (severity <= 8) return 'threat-high';
  return 'threat-critical';
};

const getSeverityLabel = (severity: number): string => {
  if (severity <= 3) return 'LOW';
  if (severity <= 6) return 'MED';
  if (severity <= 8) return 'HIGH';
  return 'CRIT';
};

const getThreatLevelInfo = (avgSeverity: number): { level: string; color: string; percent: number } => {
  if (avgSeverity <= 2) return { level: 'MINIMAL', color: 'bg-green-500', percent: avgSeverity * 10 };
  if (avgSeverity <= 4) return { level: 'LOW', color: 'bg-green-400', percent: avgSeverity * 10 };
  if (avgSeverity <= 6) return { level: 'MODERATE', color: 'bg-yellow-500', percent: avgSeverity * 10 };
  if (avgSeverity <= 8) return { level: 'HIGH', color: 'bg-orange-500', percent: avgSeverity * 10 };
  return { level: 'CRITICAL', color: 'bg-red-500', percent: Math.min(100, avgSeverity * 10) };
};

const truncateIp = (ip: string): string => {
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.x.${parts[3]}`;
  }
  if (ip.length <= 15) return ip;
  return ip.substring(0, 12) + '...';
};

const formatTimeAgo = (timestamp: number): string => {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
};

type AttackArc = import('./AttackGlobe').GlobeArc;

export const aggregateThreats = (
  prev: StreamEntry[],
  incoming: AttackArc[],
): StreamEntry[] => {
  const map = new Map<string, StreamEntry>();
  for (const entry of prev) {
    map.set(entry.key, { ...entry, isNew: false });
  }

  const now = Date.now();
  for (const attack of incoming) {
    const key = `${attack.data.sourceIp}|${attack.data.attackType}`;
    const existing = map.get(key);
    if (existing) {
      map.set(key, {
        ...existing,
        hitCount: existing.hitCount + 1,
        lastSeenAt: now,
        // KEY FIX: Only keep the highest severity and rate
        severity: Math.max(existing.severity, attack.data.severity),
        packetRate: Math.max(existing.packetRate, attack.data.packetRate),
        isNew: false,
      });
    } else {
      map.set(key, {
        key,
        sourceIp: attack.data.sourceIp,
        attackType: attack.data.attackType,
        severity: attack.data.severity,
        packetRate: attack.data.packetRate,
        hitCount: 1,
        firstSeenAt: attack.lastHitAt || now,
        lastSeenAt: attack.lastHitAt || now,
        isNew: true,
      });
    }
  }

  return Array.from(map.values())
    .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
    .slice(0, 12);
};

// ============ Live Threat Stream Component ============
interface LiveThreatStreamProps {
  entries: StreamEntry[];
}

export const LiveThreatStream: React.FC<LiveThreatStreamProps> = ({ entries }) => {
  // Force a re-render every second so the "time ago" timestamps tick up dynamically
  const [, setTick] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="glass-card cyber-glow p-4 w-72 md:w-80 max-w-[90vw]">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-cyan-500/30">
        <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
        <h3 className="digital-text text-cyan-400 text-sm font-semibold tracking-wider">
          LIVE THREAT STREAM
        </h3>
      </div>

      {/* Threat List */}
      <div className="space-y-1.5 max-h-[420px] overflow-y-auto custom-scrollbar">
        {entries.length === 0 ? (
          <div className="text-gray-500 text-xs mono-text text-center py-4">
            No active threats detected
          </div>
        ) : (
          entries.map((entry) => {
            const heatWidth = Math.min(100, Math.log2(entry.hitCount + 1) * 20);

            return (
              <div
                key={entry.key}
                className={`
                  relative flex items-center justify-between gap-2 p-2 rounded-lg
                  bg-black/40 border border-gray-700/50 overflow-hidden
                  hover:border-cyan-500/30 transition-all duration-200
                  ${entry.isNew ? 'animate-slide-up' : ''}
                `}
              >
                {/* Heat bar background */}
                <div
                  className={`absolute inset-y-0 left-0 ${getSeverityClass(entry.severity)} opacity-10 transition-all duration-500`}
                  style={{ width: `${heatWidth}%` }}
                />

                {/* Left: Severity + IP + Attack Type */}
                <div className="relative flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${getSeverityClass(entry.severity)} bg-current/10`}>
                      {getSeverityLabel(entry.severity)}
                    </span>
                    <span className="mono-text text-xs text-gray-300 truncate">
                      {truncateIp(entry.sourceIp)}
                    </span>
                  </div>
                  <div className="text-xs text-cyan-400 mono-text font-medium mt-0.5 truncate">
                    {entry.attackType.replace(/_/g, ' ')}
                  </div>
                </div>

                {/* Right: Hit count + Time ago */}
                <div className="relative flex flex-col items-end flex-shrink-0">
                  <span className={`text-[11px] mono-text font-bold ${
                    entry.hitCount > 20 ? 'text-red-400' : 'text-cyan-400'
                  }`}>
                    &times;{entry.hitCount}
                  </span>
                  <span className="text-[9px] text-gray-500 mono-text">
                    {formatTimeAgo(entry.lastSeenAt)}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Footer */}
      <div className="mt-3 pt-2 border-t border-gray-700/50 flex justify-between items-center">
        <span className="text-[10px] text-gray-500 mono-text">
          {entries.length} aggregated sources
        </span>
        <div className="flex gap-2 text-[10px]">
          <span className="threat-low">●</span>
          <span className="threat-medium">●</span>
          <span className="threat-high">●</span>
          <span className="threat-critical">●</span>
        </div>
      </div>
    </div>
  );
};

// ============ Total Events Counter Component ============
interface TotalEventsCounterProps {
  count: number;
  isLive: boolean;
}

export const TotalEventsCounter: React.FC<TotalEventsCounterProps> = ({ 
  count, 
  isLive 
}) => {
  const formattedCount = useMemo(() => 
    count.toString().padStart(6, '0'),
    [count]
  );

  return (
    <div className="glass-card cyber-glow p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] text-gray-500 mono-text uppercase tracking-widest">
          Total Events
        </span>
        <div className="flex items-center gap-1.5">
          <div className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
          <span className={`text-[10px] mono-text ${isLive ? 'text-green-400' : 'text-red-400'}`}>
            {isLive ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
      </div>

      {/* Digital Counter */}
      <div className="flex items-center justify-center">
        <div className="digital-text text-3xl md:text-4xl font-bold tracking-widest">
          {formattedCount.split('').map((digit, i) => (
            <span 
              key={i}
              className={`
                inline-block w-6 md:w-8 text-center
                ${digit === '0' && i < formattedCount.length - String(count).length 
                  ? 'text-gray-700' 
                  : 'text-cyan-400'
                }
              `}
            >
              {digit}
            </span>
          ))}
        </div>
      </div>

      {/* Decorative scan line */}
      <div className="relative h-0.5 mt-3 bg-gray-800 rounded overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-500 to-transparent animate-scan-line opacity-50" />
      </div>
    </div>
  );
};

// ============ Global Threat Level Gauge ============
interface ThreatLevelGaugeProps {
  threats: ThreatEvent[];
}

export const ThreatLevelGauge: React.FC<ThreatLevelGaugeProps> = ({ threats }) => {
  const { avgSeverity, threatInfo } = useMemo(() => {
    if (threats.length === 0) {
      return { avgSeverity: 0, threatInfo: getThreatLevelInfo(0) };
    }
    const avg = threats.reduce((sum, t) => sum + t.severity, 0) / threats.length;
    return { avgSeverity: avg, threatInfo: getThreatLevelInfo(avg) };
  }, [threats]);

  return (
    <div className="glass-card cyber-glow p-4 w-64 md:w-72">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" 
          />
        </svg>
        <h3 className="digital-text text-cyan-400 text-sm font-semibold tracking-wider">
          GLOBAL THREAT LEVEL
        </h3>
      </div>

      {/* Threat Level Label */}
      <div className="text-center mb-3">
        <span className={`
          digital-text text-2xl font-bold tracking-widest
          ${threatInfo.level === 'CRITICAL' ? 'text-red-500 animate-threat-pulse' :
            threatInfo.level === 'HIGH' ? 'text-orange-500' :
            threatInfo.level === 'MODERATE' ? 'text-yellow-500' :
            threatInfo.level === 'LOW' ? 'text-green-400' : 'text-green-500'}
        `}>
          {threatInfo.level}
        </span>
        <span className="block text-gray-500 text-[10px] uppercase tracking-widest mt-0.5">
          active arcs · last 30s
        </span>
      </div>

      {/* Progress Bar */}
      <div className="relative h-3 bg-gray-800 rounded-full overflow-hidden mb-2">
        {/* Gradient background segments */}
        <div className="absolute inset-0 flex">
          <div className="flex-1 bg-green-500/20" />
          <div className="flex-1 bg-yellow-500/20" />
          <div className="flex-1 bg-orange-500/20" />
          <div className="flex-1 bg-red-500/20" />
        </div>
        
        {/* Active fill */}
        <div 
          className={`absolute left-0 top-0 h-full ${threatInfo.color} transition-all duration-500 ease-out`}
          style={{ width: `${threatInfo.percent}%` }}
        >
          {/* Glow effect */}
          <div className="absolute right-0 top-0 bottom-0 w-4 bg-gradient-to-r from-transparent to-white/30" />
        </div>

        {/* Tick marks */}
        <div className="absolute inset-0 flex justify-between px-0.5">
          {[...Array(10)].map((_, i) => (
            <div key={i} className="w-px h-full bg-black/50" />
          ))}
        </div>
      </div>

      {/* Scale Labels */}
      <div className="flex justify-between text-[9px] mono-text text-gray-500">
        <span>0</span>
        <span>2.5</span>
        <span>5.0</span>
        <span>7.5</span>
        <span>10</span>
      </div>

      {/* Stats Footer */}
      <div className="mt-3 pt-2 border-t border-gray-700/50 grid grid-cols-2 gap-2 text-center">
        <div>
          <div className="text-lg font-bold digital-text text-cyan-400">
            {avgSeverity.toFixed(1)}
          </div>
          <div className="text-[9px] text-gray-500 mono-text">THREAT INDEX</div>
          <div className="text-[8px] text-gray-600 mono-text">active arc weighted avg</div>
        </div>
        <div>
          <div className="text-lg font-bold digital-text text-cyan-400">
            {threats.length}
          </div>
          <div className="text-[9px] text-gray-500 mono-text">ACTIVE</div>
        </div>
      </div>
    </div>
  );
};

// ============ Server Status Component ============
interface ServerStatusProps {
  label: string;
  lat: number;
  lon: number;
}

export const ServerStatus: React.FC<ServerStatusProps> = ({ label, lat, lon }) => (
  <div className="glass-card p-3 flex items-center gap-3">
    <div className="relative">
      <div className="w-3 h-3 bg-green-500 rounded-full" />
      <div className="absolute inset-0 w-3 h-3 bg-green-500 rounded-full animate-ping opacity-50" />
    </div>
    <div>
      <div className="text-xs mono-text text-green-400 font-medium">
        🖥 {label}
      </div>
      <div className="text-[10px] text-gray-500 mono-text">
        {lat.toFixed(2)}°, {lon.toFixed(2)}°
      </div>
    </div>
  </div>
);

// ============ Error Banner Component ============
interface ErrorBannerProps {
  message: string;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({ message }) => (
  <div className="glass-card border-red-500/50 bg-red-900/20 p-3 max-w-xs">
    <div className="flex items-center gap-2">
      <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
          d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" 
        />
      </svg>
      <span className="text-xs mono-text text-red-400 truncate">{message}</span>
    </div>
  </div>
);

// ============ Backlog Indicator Component ============
interface BacklogIndicatorProps {
  backlog: number;
}

export const BacklogIndicator: React.FC<BacklogIndicatorProps> = ({ backlog }) => {
  // Don't render if no backlog
  if (backlog === 0) return null;

  // Determine severity styling
  const getSeverityStyle = () => {
    if (backlog > 100) {
      return {
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-900/20',
        textColor: 'text-red-400',
        iconColor: 'text-red-500',
        pulseClass: 'animate-pulse',
        label: 'CRITICAL'
      };
    } else if (backlog > 30) {
      return {
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-900/20',
        textColor: 'text-orange-400',
        iconColor: 'text-orange-500',
        pulseClass: '',
        label: 'HIGH'
      };
    } else {
      return {
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-900/20',
        textColor: 'text-yellow-400',
        iconColor: 'text-yellow-500',
        pulseClass: '',
        label: 'MODERATE'
      };
    }
  };

  const style = getSeverityStyle();

  return (
    <div className={`glass-card ${style.borderColor} ${style.bgColor} p-3 max-w-xs ${style.pulseClass}`}>
      <div className="flex items-center gap-2">
        <svg className={`w-4 h-4 ${style.iconColor} flex-shrink-0`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" 
          />
        </svg>
        <div className="flex-1">
          <div className={`text-xs mono-text ${style.textColor} font-medium`}>
            ⚠ {backlog} EVENTS QUEUED
          </div>
          <div className="text-[9px] text-gray-500 mono-text uppercase">
            {style.label} BACKLOG
          </div>
        </div>
      </div>
    </div>
  );
};

// ============ Arc Capacity Indicator Component ============
const ArcCapacityIndicator: React.FC<{ count: number; max: number }> = ({ count, max }) => {
  const pct = max > 0 ? count / max : 0;

  let barColor: string;
  let textColor: string;
  let label: string | null = null;
  let pulse = false;
  let warning: string | null = null;

  if (pct >= 1.0) {
    barColor = 'bg-red-500';
    textColor = 'text-red-400';
    label = 'SATURATED';
    pulse = true;
    warning = 'Oldest arcs cycling off';
  } else if (pct >= 0.75) {
    barColor = 'bg-orange-500';
    textColor = 'text-orange-400';
    label = 'HIGH';
  } else if (pct >= 0.4) {
    barColor = 'bg-cyan-500';
    textColor = 'text-cyan-400';
  } else {
    barColor = 'bg-green-500';
    textColor = 'text-green-400';
  }

  return (
    <div className="glass-card p-3 min-w-[160px]">
      {/* Header */}
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[9px] text-gray-500 mono-text uppercase tracking-widest">Arc Capacity</span>
        {label && (
          <span className={`text-[9px] mono-text font-bold ${textColor} ${pulse ? 'animate-pulse' : ''}`}>
            {label}
          </span>
        )}
      </div>

      {/* Progress bar */}
      <div className="relative h-1.5 bg-gray-800 rounded-full overflow-hidden mb-1.5">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${Math.min(100, pct * 100)}%` }}
        />
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <span className={`text-[10px] mono-text font-bold ${textColor}`}>
          {count} / {max}
        </span>
        {warning && (
          <span className="text-[9px] mono-text text-red-400/80">
            {warning}
          </span>
        )}
      </div>
    </div>
  );
};

// ============ WebSocket Status Indicator Component ============
const WsStatusIndicator: React.FC = () => {
  const { wsStatus } = useDashboard();

  const config = {
    connected: {
      dot: 'bg-green-500 animate-pulse',
      text: 'text-green-400',
      label: 'LIVE',
    },
    connecting: {
      dot: 'bg-yellow-500 animate-pulse',
      text: 'text-yellow-400',
      label: 'CONNECTING',
    },
    disconnected: {
      dot: 'bg-red-500',
      text: 'text-red-400',
      label: 'RECONNECTING',
    },
  }[wsStatus];

  return (
    <div className="glass-card p-2 px-3 flex items-center gap-2">
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${config.dot}`} />
      <span className={`digital-text text-[9px] uppercase tracking-widest ${config.text}`}>
        {config.label}
      </span>
    </div>
  );
};

// ============ Pause Button Component ============
const PauseButton: React.FC<{
  isPaused: boolean;
  onToggle: () => void;
}> = ({ isPaused, onToggle }) => (
  <button
    onClick={onToggle}
    className={`
      mt-2 w-full py-1.5 rounded-lg border backdrop-blur-md
      text-[10px] font-bold tracking-widest uppercase transition-all
      ${
        isPaused
          ? 'border-red-500/50 bg-red-900/40 text-red-400 shadow-[0_0_10px_rgba(239,68,68,0.3)] animate-pulse'
          : 'border-cyan-500/30 bg-black/40 text-cyan-400 hover:bg-cyan-900/20 hover:border-cyan-400/50'
      }
    `}
  >
    {isPaused ? '\u25b6 RESUME SYSTEM' : '\u23f8 PAUSE STREAM'}
  </button>
);

// ============ Main Dashboard Overlay Component ============
export const CyberDashboard: React.FC<DashboardProps> = ({ 
  threats, 
  arcs = [],
  totalEvents,
  arcCount = 0,
  arcMax = 100,
  isLive, 
  error,
  backlog,
  isPaused = false,
  onTogglePause,
  selectedArc = null,
  onDeselectArc,
  serverStatus,
}) => {
  const [streamEntries, setStreamEntries] = useState<StreamEntry[]>([]);

  useEffect(() => {
    if (!isPaused && arcs.length > 0) {
      setStreamEntries(prev => aggregateThreats(prev, arcs));
    }
  }, [arcs, isPaused]);

  return (
    <>
      {/* Top Left: Live Threat Stream */}
      <div className="absolute top-4 left-4 z-10 md:top-6 md:left-6">
        <LiveThreatStream entries={streamEntries} />
        
        {/* Backlog Indicator (below threat stream) */}
        <div className="mt-2">
          <BacklogIndicator backlog={backlog} />
        </div>
      </div>

      {/* Top Right: Total Events & Controls */}
      <div className="absolute top-4 right-4 z-10 md:top-6 md:right-6 flex flex-col gap-2 w-64 md:w-72">
        <TotalEventsCounter count={totalEvents} isLive={isLive && !isPaused} />

        {/* Error Banner */}
        {error && <ErrorBanner message={error} />}

        {/* Pause Button */}
        {onTogglePause && (
          <PauseButton isPaused={!!isPaused} onToggle={onTogglePause} />
        )}

        {/* Arc Capacity */}
        <ArcCapacityIndicator count={arcCount} max={arcMax} />
      </div>

      {/* Bottom Left: Incidents Panel */}
      <div className="absolute bottom-4 left-4 z-20 md:bottom-6 md:left-6 flex flex-col gap-2 items-start">
        <IncidentsPanel />
        {serverStatus && (
          <ServerStatus
            label={serverStatus.label}
            lat={serverStatus.lat}
            lon={serverStatus.lon}
          />
        )}
      </div>

      {/* Bottom Right: Attack Details (when arc selected) + Agent Status + Global Threat Level + Sync */}
      <div className="absolute bottom-4 right-4 z-20 md:bottom-6 md:right-6 flex flex-col gap-2 items-end">
        {selectedArc && onDeselectArc && (
          <ArcDetailPanel arc={selectedArc} onClose={onDeselectArc} />
        )}
        <div className="pointer-events-auto w-64 md:w-72">
          <AgentStatusWidget />
        </div>
        <ArcLegend />
        <ThreatLevelGauge threats={threats} />
        <WsStatusIndicator />
      </div>

      {/* Top Center: AI Briefing */}
      <div className="absolute top-4 left-1/2 -translate-x-1/2 z-10 pointer-events-auto">
        <BriefingPanel />
      </div>

      {/* Bottom Center: Stats Panel */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-10">
        <StatsPanel />
      </div>
    </>
  );
};

export default CyberDashboard;
