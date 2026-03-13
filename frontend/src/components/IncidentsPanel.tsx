import { useEffect, useRef, useState } from 'react';
import { useDashboard } from '../context/DashboardContext';
import type { IncidentReport } from '../context/DashboardContext';

// ── helpers ──────────────────────────────────────────────────────────────────

const threatColor = (level: IncidentReport['threat_level']): string => {
  switch (level) {
    case 'critical': return 'text-red-400';
    case 'high':     return 'text-orange-400';
    case 'medium':   return 'text-yellow-400';
    case 'low':      return 'text-green-400';
    default:         return 'text-gray-400';
  }
};

const threatBorder = (level: IncidentReport['threat_level']): string => {
  switch (level) {
    case 'critical': return 'border-red-500/40';
    case 'high':     return 'border-orange-500/40';
    case 'medium':   return 'border-yellow-500/40';
    case 'low':      return 'border-green-500/40';
    default:         return 'border-gray-600/40';
  }
};

const severityDot = (score: number): string => {
  if (score >= 8) return 'bg-red-500';
  if (score >= 5) return 'bg-orange-400';
  return 'bg-yellow-400';
};

const timeAgo = (isoStr: string): string => {
  const diffMs = Date.now() - new Date(isoStr).getTime();
  const s = Math.floor(diffMs / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
};

const toolCount = (toolsCalled: string | null): number => {
  if (!toolsCalled) return 0;
  return toolsCalled.split(',').filter(Boolean).length;
};

// ── component ─────────────────────────────────────────────────────────────────

const IncidentsPanel: React.FC = () => {
  const { snapshot } = useDashboard();
  const incidents = snapshot.incidents;

  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [newCount, setNewCount] = useState(0);

  const latestIdRef = useRef<number>(0);
  const isFirstFetch = useRef(true);

  useEffect(() => {
    if (incidents.length === 0) return;

    if (isFirstFetch.current) {
      // Establish the baseline — no "new" badge on initial load
      latestIdRef.current = incidents[0]?.id ?? 0;
      isFirstFetch.current = false;
    } else {
      const freshItems = incidents.filter(r => r.id > latestIdRef.current);
      if (freshItems.length > 0) {
        setNewCount(prev => prev + freshItems.length);
        latestIdRef.current = incidents[0]?.id ?? latestIdRef.current;
      }
    }
  }, [incidents]);

  const handleToggle = (id: number) => {
    setExpandedId(prev => (prev === id ? null : id));
    // Clear new-count badge when user opens any report
    if (newCount > 0) setNewCount(0);
  };

  return (
    <div className="glass-card cyber-glow p-4 w-72 md:w-80 flex flex-col gap-0">
      {/* ── Header ── */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-red-500/30">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500" />
        </span>
        <h3 className="digital-text text-red-400 text-sm font-semibold tracking-wider flex-1">
          INCIDENT REPORTS
        </h3>
        {newCount > 0 && (
          <span className="flex items-center justify-center h-5 min-w-[1.25rem] px-1 rounded-full bg-red-600 text-white text-[9px] font-bold mono-text animate-pulse">
            +{newCount}
          </span>
        )}
      </div>

      {/* ── List ── */}
      <div className="flex flex-col gap-2 max-h-36 md:max-h-40 overflow-y-auto pr-1 custom-scrollbar">
        {incidents.length === 0 && (
          <p className="mono-text text-[10px] text-gray-500 text-center py-6">
            No incidents yet — threshold not reached.
          </p>
        )}

        {incidents.map(report => {
          const isExpanded = expandedId === report.id;
          return (
            <button
              key={report.id}
              onClick={() => handleToggle(report.id)}
              className={`w-full text-left rounded border px-3 py-2.5 transition-all duration-200
                bg-black/30 hover:bg-black/50 focus:outline-none
                ${threatBorder(report.threat_level)}`}
            >
              {/* ── Summary row ── */}
              <div className="flex items-center gap-2">
                {/* Severity dot */}
                <span
                  className={`flex-shrink-0 h-2 w-2 rounded-full ${severityDot(report.severity_score)}`}
                />

                {/* Attack type + source IP */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className={`digital-text text-xs font-bold ${threatColor(report.threat_level)}`}>
                      {report.threat_level.toUpperCase()}
                    </span>
                    <span className="text-gray-500 text-[9px]">·</span>
                    <span className="mono-text text-[10px] text-gray-300 truncate">
                      {report.attack_type}
                    </span>
                    {report.is_repeat_attacker && (
                      <span className="flex-shrink-0 px-1 py-px rounded text-[8px] font-bold tracking-wider bg-red-600/30 text-red-400 border border-red-500/40">
                        REPEAT
                      </span>
                    )}
                    {report.campaign_detected && (
                      <span className="flex-shrink-0 px-1 py-px rounded text-[8px] font-bold tracking-wider bg-orange-600/30 text-orange-400 border border-orange-500/40">
                        CAMPAIGN
                      </span>
                    )}
                  </div>
                  <div className="mono-text text-[9px] text-gray-500 truncate mt-0.5">
                    {report.source_ip}
                    <span className="text-gray-600 mx-1">·</span>
                    sev {report.severity_score.toFixed(1)}
                  </div>
                  {report.pattern_summary && (
                    <p className="mono-text text-[9px] text-gray-400 italic truncate mt-0.5">
                      {report.pattern_summary}
                    </p>
                  )}
                </div>

                {/* Time + chevron */}
                <div className="flex-shrink-0 flex flex-col items-end gap-1">
                  <span className="mono-text text-[9px] text-gray-500">
                    {timeAgo(report.generated_at)}
                  </span>
                  <svg
                    className={`w-3 h-3 text-gray-500 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* ── Expanded detail ── */}
              {isExpanded && (
                <div className="mt-3 pt-2.5 border-t border-gray-700/50 flex flex-col gap-2.5">
                  {/* Summary */}
                  <div>
                    <div className="mono-text text-[8px] text-gray-500 uppercase tracking-widest mb-1">
                      Summary
                    </div>
                    <p className="mono-text text-[10px] text-gray-300 leading-relaxed">
                      {report.summary}
                    </p>
                  </div>

                  {/* Recommended action */}
                  <div>
                    <div className="mono-text text-[8px] text-yellow-500/80 uppercase tracking-widest mb-1">
                      Recommended Action
                    </div>
                    <p className="mono-text text-[10px] text-yellow-300/90 leading-relaxed">
                      {report.recommended_action}
                    </p>
                  </div>

                  {/* Pattern context */}
                  {report.pattern_summary && (
                    <div className="rounded border border-gray-600/40 bg-black/20 px-2.5 py-2">
                      <div className={`mono-text text-[8px] uppercase tracking-widest mb-1 ${
                        report.is_repeat_attacker
                          ? 'text-red-400/80'
                          : report.campaign_detected
                          ? 'text-orange-400/80'
                          : 'text-gray-400/80'
                      }`}>
                        {report.is_repeat_attacker
                          ? '⚠ Persistence Detected'
                          : report.campaign_detected
                          ? '⚠ Campaign Activity'
                          : 'Pattern Context'}
                      </div>
                      <p className="mono-text text-[10px] text-gray-300 leading-relaxed italic">
                        {report.pattern_summary}
                      </p>
                    </div>
                  )}

                  {/* Tools used */}
                  <div className="flex items-center gap-1.5 pt-0.5">
                    <svg className="w-3 h-3 text-blue-400/70" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                      />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                    <span className="mono-text text-[9px] text-blue-400/70">
                      Tools Used: {toolCount(report.tools_called)}
                    </span>
                    {report.tools_called && (
                      <span className="mono-text text-[8px] text-gray-600 truncate">
                        ({report.tools_called})
                      </span>
                    )}
                  </div>
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Footer ── */}
      <div className="flex items-center justify-between mt-3 pt-2 border-t border-red-500/20 text-[9px] text-gray-500 mono-text tracking-widest">
        <span>{incidents.length} report{incidents.length !== 1 ? 's' : ''} · Synced via heartbeat</span>
        <span className="text-red-400/60">AI Agent</span>
      </div>
    </div>
  );
};

export default IncidentsPanel;
