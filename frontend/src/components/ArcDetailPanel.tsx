import React from 'react';
import type { GlobeArc } from './AttackGlobe';

interface ArcDetailPanelProps {
  arc: GlobeArc;
  onClose: () => void;
}

const getSeverityLabel = (severity: number): { label: string; colorClass: string } => {
  if (severity <= 3) return { label: 'Low', colorClass: 'text-green-400' };
  if (severity <= 6) return { label: 'Moderate', colorClass: 'text-yellow-400' };
  if (severity <= 8) return { label: 'High', colorClass: 'text-orange-400' };
  return { label: 'Critical', colorClass: 'text-red-400' };
};

const formatTimestamp = (timestamp: string): string => {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    hour12: false,
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
};

const ArcDetailPanel: React.FC<ArcDetailPanelProps> = ({ arc, onClose }) => {
  const { data, hitCount } = arc;
  const severity = getSeverityLabel(data.severity);

  return (
    <div className="glass-card cyber-glow p-5 w-80 max-w-[92vw] border border-cyan-500/30 bg-gray-950/80 backdrop-blur-lg rounded-lg shadow-lg shadow-cyan-500/10">
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-2 border-b border-cyan-500/30">
        <h3 className="digital-text text-cyan-400 text-sm font-semibold tracking-wider uppercase">
          Attack Details
        </h3>
        <button
          onClick={onClose}
          className="text-cyan-500/70 hover:text-cyan-300 transition-colors text-lg leading-none cursor-pointer"
          aria-label="Close"
        >
          ✕
        </button>
      </div>

      {/* Detail rows */}
      <div className="space-y-3 text-sm">
        {/* Severity */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Severity</span>
          <span className={`font-bold tracking-wider ${severity.colorClass}`}>
            {severity.label} ({data.severity}/10)
          </span>
        </div>

        {/* Attack Type */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Attack Type</span>
          <span className="text-cyan-300 font-mono">{data.attackType}</span>
        </div>

        {/* Source IP */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Source IP</span>
          <span className="text-cyan-300 font-mono text-xs">{data.sourceIp}</span>
        </div>

        {/* Target IP */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Target IP</span>
          <span className="text-cyan-300 font-mono text-xs">{data.targetIp}</span>
        </div>

        {/* Packet Rate */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Packet Rate</span>
          <span className="text-cyan-300 font-mono">
            {data.packetRate.toLocaleString()} <span className="text-cyan-600 text-xs">pps</span>
          </span>
        </div>

        {/* Hit Count */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Hit Count</span>
          <span className="text-cyan-300 font-mono">{hitCount.toLocaleString()}</span>
        </div>

        {/* Timestamp */}
        <div className="flex justify-between items-center">
          <span className="text-cyan-600 tracking-wide">Timestamp</span>
          <span className="text-cyan-300 font-mono text-xs">{formatTimestamp(data.timestamp)}</span>
        </div>
      </div>
    </div>
  );
};

export default ArcDetailPanel;
