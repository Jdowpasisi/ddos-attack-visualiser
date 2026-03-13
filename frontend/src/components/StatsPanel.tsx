import React from 'react';
import { useDashboard } from '../context/DashboardContext';

/** Convert a 2-letter ISO country code to its emoji flag. */
const countryFlag = (code: string): string => {
  const upper = code.toUpperCase();
  if (upper.length !== 2) return '\u{1F310}'; // 🌐 fallback
  const cp1 = 0x1f1e6 - 65 + upper.charCodeAt(0);
  const cp2 = 0x1f1e6 - 65 + upper.charCodeAt(1);
  return String.fromCodePoint(cp1, cp2);
};

const formatRate = (rate: number): string => {
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(1)}M`;
  if (rate >= 1_000) return `${(rate / 1_000).toFixed(1)}K`;
  return String(rate);
};

const StatsPanel: React.FC = () => {
  const { snapshot } = useDashboard();
  const stats = snapshot.stats;

  if (!stats) {
    return (
      <div className="glass-card cyber-glow p-4 w-64 flex items-center justify-center h-16">
        <span className="text-[10px] text-gray-500 mono-text animate-pulse">Syncing…</span>
      </div>
    );
  }

  const trendUp = stats.trend_pct > 0;
  const trendDown = stats.trend_pct < 0;
  const severityPct = Math.min(100, (stats.avg_severity_1m / 10) * 100);

  // Relative bar widths for countries (normalise to largest)
  const maxCountry = stats.top_countries[0]?.count || 1;

  return (
    <div className="glass-card cyber-glow p-4 w-64">
      {/* ── Header ── */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-cyan-500/30">
        <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
            d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6m6 0h6m-6 0V9a2 2 0 012-2h2a2 2 0 012 2v10m6 0v-4a2 2 0 00-2-2h-2a2 2 0 00-2 2v4"
          />
        </svg>
        <h3 className="digital-text text-cyan-400 text-sm font-semibold tracking-wider">
          ATTACK INTEL
        </h3>
      </div>

      {/* ── Events / Min + Trend ── */}
      <div className="flex items-end justify-between mb-3">
        <div>
          <div className="text-[9px] text-gray-500 mono-text uppercase tracking-widest">
            Events / min
          </div>
          <div className="digital-text text-2xl font-bold text-cyan-400 leading-none mt-0.5">
            {stats.events_per_min.toFixed(1)}
          </div>
        </div>

        <div className={`flex items-center gap-1 text-sm font-bold mono-text ${
          trendUp ? 'text-red-400' : trendDown ? 'text-green-400' : 'text-gray-500'
        }`}>
          {trendUp && (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 15l7-7 7 7" />
            </svg>
          )}
          {trendDown && (
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M19 9l-7 7-7-7" />
            </svg>
          )}
          {stats.trend_pct !== 0 ? `${Math.abs(stats.trend_pct).toFixed(0)}%` : '—'}
        </div>
      </div>

      {/* ── Severity Bar ── */}
      <div className="mb-3">
        <div className="flex justify-between text-[9px] text-gray-500 mono-text mb-0.5">
          <span>DB AVG SEVERITY</span>
          <span className="text-cyan-400">{stats.avg_severity_1m.toFixed(1)}</span>
        </div>
        <div className="text-[8px] text-gray-600 mono-text mb-1">from database (1 min)</div>
        <div className="relative h-2 bg-gray-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              stats.avg_severity_1m <= 3 ? 'bg-green-500' :
              stats.avg_severity_1m <= 6 ? 'bg-yellow-500' :
              stats.avg_severity_1m <= 8 ? 'bg-orange-500' : 'bg-red-500'
            }`}
            style={{ width: `${severityPct}%` }}
          />
        </div>
      </div>

      {/* ── Top Countries ── */}
      {stats.top_countries.length > 0 && (
        <div className="mb-3">
          <div className="text-[9px] text-gray-500 mono-text uppercase tracking-widest mb-1.5">
            Top Countries
          </div>
          <div className="space-y-1.5">
            {stats.top_countries.map((c) => (
              <div key={c.country} className="flex items-center gap-2">
                <span className="text-sm leading-none w-6 text-center">{countryFlag(c.country)}</span>
                <span className="text-[10px] mono-text text-gray-400 w-7">{c.country}</span>
                <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                    style={{ width: `${(c.count / maxCountry) * 100}%` }}
                  />
                </div>
                <span className="text-[10px] mono-text text-cyan-400 w-8 text-right">{c.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Top Attack Types ── */}
      {stats.top_attack_types.length > 0 && (
        <div className="mb-3">
          <div className="text-[9px] text-gray-500 mono-text uppercase tracking-widest mb-1.5">
            Top Attack Types
          </div>
          <div className="space-y-1">
            {stats.top_attack_types.map((t) => (
              <div key={t.type} className="flex items-center justify-between gap-2">
                <span className="text-[10px] mono-text text-gray-300 truncate flex-1">
                  {t.type.replace(/_/g, ' ')}
                </span>
                <span className={`text-[10px] mono-text font-bold ${
                  t.avg_severity > 7 ? 'text-red-400' :
                  t.avg_severity > 4 ? 'text-yellow-400' : 'text-green-400'
                }`}>
                  {t.avg_severity.toFixed(1)}
                </span>
                <span className="text-[10px] mono-text text-cyan-400 w-8 text-right">
                  {t.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Footer: Peak Rate ── */}
      <div className="pt-2 border-t border-gray-700/50 flex justify-between items-center">
        <span className="text-[9px] text-gray-500 mono-text uppercase tracking-widest">
          Peak pkt/s
        </span>
        <span className="digital-text text-sm font-bold text-cyan-400">
          {formatRate(stats.peak_packet_rate)}
        </span>
      </div>
    </div>
  );
};

export default StatsPanel;
