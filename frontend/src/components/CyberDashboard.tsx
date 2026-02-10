import React, { useMemo } from 'react';

// ============ Types ============
export interface ThreatEvent {
  id: number;
  sourceIp: string;
  attackType: string;
  severity: number;
  timestamp: string;
  country?: string;
}

export interface DashboardProps {
  threats: ThreatEvent[];
  totalEvents: number;
  isLive: boolean;
  error: string | null;
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

const formatTime = (timestamp: string): string => {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', { 
    hour12: false, 
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit' 
  });
};

const truncateIp = (ip: string): string => {
  if (ip.length <= 15) return ip;
  return ip.substring(0, 12) + '...';
};

// ============ Live Threat Stream Component ============
interface LiveThreatStreamProps {
  threats: ThreatEvent[];
  maxItems?: number;
}

export const LiveThreatStream: React.FC<LiveThreatStreamProps> = ({ 
  threats, 
  maxItems = 5 
}) => {
  const recentThreats = useMemo(() => 
    threats.slice(0, maxItems), 
    [threats, maxItems]
  );

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
      <div className="space-y-2 max-h-48 overflow-y-auto custom-scrollbar">
        {recentThreats.length === 0 ? (
          <div className="text-gray-500 text-xs mono-text text-center py-4">
            No active threats detected
          </div>
        ) : (
          recentThreats.map((threat, index) => (
            <div 
              key={threat.id}
              className={`
                flex items-center justify-between gap-2 p-2 rounded-lg 
                bg-black/40 border border-gray-700/50
                hover:border-cyan-500/30 transition-all duration-200
                animate-slide-up
              `}
              style={{ animationDelay: `${index * 50}ms` }}
            >
              {/* Left: Time + IP */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-gray-500 text-[10px] mono-text">
                    {formatTime(threat.timestamp)}
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${getSeverityClass(threat.severity)} bg-current/10`}>
                    {getSeverityLabel(threat.severity)}
                  </span>
                </div>
                <div className="mono-text text-xs text-gray-300 truncate">
                  {truncateIp(threat.sourceIp)}
                </div>
              </div>

              {/* Right: Attack Type */}
              <div className="text-right">
                <span className="text-xs text-cyan-400 mono-text font-medium">
                  {threat.attackType.replace(/_/g, ' ')}
                </span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="mt-3 pt-2 border-t border-gray-700/50 flex justify-between items-center">
        <span className="text-[10px] text-gray-500 mono-text">
          Showing {recentThreats.length} of {threats.length}
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
          <div className="text-[9px] text-gray-500 mono-text">AVG SEVERITY</div>
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

// ============ Main Dashboard Overlay Component ============
export const CyberDashboard: React.FC<DashboardProps> = ({ 
  threats, 
  totalEvents, 
  isLive, 
  error 
}) => {
  return (
    <>
      {/* Top Left: Live Threat Stream */}
      <div className="absolute top-4 left-4 z-10 md:top-6 md:left-6">
        <LiveThreatStream threats={threats} maxItems={5} />
      </div>

      {/* Top Right: Total Events Counter */}
      <div className="absolute top-4 right-4 z-10 md:top-6 md:right-6">
        <TotalEventsCounter count={totalEvents} isLive={isLive} />
        
        {/* Error Banner (below counter if error exists) */}
        {error && (
          <div className="mt-2">
            <ErrorBanner message={error} />
          </div>
        )}
      </div>

      {/* Bottom Right: Global Threat Level */}
      <div className="absolute bottom-4 right-4 z-10 md:bottom-6 md:right-6">
        <ThreatLevelGauge threats={threats} />
      </div>
    </>
  );
};

export default CyberDashboard;
