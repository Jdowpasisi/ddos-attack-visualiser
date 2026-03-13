import { useEffect, useRef, useState } from 'react';

const API_BASE_URL =
  import.meta.env.VITE_API_URL ??
  import.meta.env.VITE_API_BASE_URL ??
  'http://localhost:8000';

const POLL_INTERVAL_MS = 1500;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AgentStatus {
  is_active: boolean;
  current_tool: string | null;
  event_id: number | null;
  attack_type: string | null;
  source_ip: string | null;
  tools_completed: string[];
  started_at: string | null;
}

// ---------------------------------------------------------------------------
// Tool stage config
// ---------------------------------------------------------------------------

interface ToolStage {
  key: string;
  label: string;
  icon: string;
}

const TOOL_STAGES: ToolStage[] = [
  {
    key: 'find_related_incidents',
    label: 'Checking incident memory',
    icon: '🗄',
  },
  {
    key: 'lookup_ip_reputation',
    label: 'Looking up IP reputation',
    icon: '🌐',
  },
  {
    key: 'fetch_cve_data',
    label: 'Fetching CVE data',
    icon: '🔍',
  },
  {
    key: 'get_attack_trend',
    label: 'Analysing attack trends',
    icon: '📈',
  },
  {
    key: 'complete',
    label: 'Generating report',
    icon: '📋',
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const AgentStatusWidget: React.FC = () => {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [elapsed, setElapsed] = useState<number>(0);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const elapsedRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // --- Polling effect ---
  useEffect(() => {
    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/agent/status`);
        if (res.ok) {
          const data: AgentStatus = await res.json();
          setStatus(data);
        }
      } catch {
        // silently ignore network errors between polls
      }
    };

    poll();
    pollRef.current = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  // --- Elapsed time effect ---
  useEffect(() => {
    if (elapsedRef.current) clearInterval(elapsedRef.current);

    if (status?.is_active && status.started_at) {
      const startMs = new Date(status.started_at).getTime();
      const tick = () => setElapsed(Math.floor((Date.now() - startMs) / 1000));
      tick();
      elapsedRef.current = setInterval(tick, 1000);
    } else {
      setElapsed(0);
    }

    return () => {
      if (elapsedRef.current) clearInterval(elapsedRef.current);
    };
  }, [status?.is_active, status?.started_at]);

  if (!status?.is_active) return null;

  const completedSet = new Set(status.tools_completed);
  const isCurrentlyActive = (key: string) => status.current_tool === key;

  // Determine the index of the first completed tool that has NOT been called,
  // i.e. tools that were skipped (agent jumped past them).
  // A tool is "skipped" if: it was never in tools_completed, it is not the
  // current_tool, but a tool that appears *after* it in TOOL_STAGES has been
  // completed or is active.
  const lastTouchedIndex = TOOL_STAGES.reduce((max, stage, idx) => {
    if (completedSet.has(stage.key) || isCurrentlyActive(stage.key)) {
      return Math.max(max, idx);
    }
    return max;
  }, -1);

  const isSkipped = (key: string, idx: number) =>
    !completedSet.has(key) &&
    !isCurrentlyActive(key) &&
    idx < lastTouchedIndex;

  const toolsCalledCount = status.tools_completed.length;
  const totalTools = TOOL_STAGES.length;

  return (
    <div className="border border-orange-500/60 bg-orange-950/20 backdrop-blur-sm rounded-xl p-4 animate-fade-in shadow-lg shadow-orange-900/20">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-orange-500" />
          </span>
          <span className="text-orange-400 font-mono text-xs font-semibold tracking-widest uppercase">
            Agent Investigating
          </span>
        </div>
        <span className="text-orange-300/70 font-mono text-xs tabular-nums">
          {elapsed}s
        </span>
      </div>

      {/* Target info */}
      <div className="bg-orange-900/20 border border-orange-500/30 rounded-lg px-3 py-2 mb-3 grid grid-cols-2 gap-1">
        <div>
          <p className="text-orange-500/60 font-mono text-[10px] uppercase tracking-wider">
            Attack Type
          </p>
          <p className="text-orange-200 font-mono text-xs truncate">
            {status.attack_type ?? '—'}
          </p>
        </div>
        <div>
          <p className="text-orange-500/60 font-mono text-[10px] uppercase tracking-wider">
            Source IP
          </p>
          <p className="text-orange-200 font-mono text-xs truncate">
            {status.source_ip ?? '—'}
          </p>
        </div>
      </div>

      {/* Tool stages */}
      <ol className="space-y-1.5 mb-3">
        {TOOL_STAGES.map((stage, idx) => {
          const done = completedSet.has(stage.key);
          const active = isCurrentlyActive(stage.key);
          const skipped = isSkipped(stage.key, idx);

          let rowClass = 'flex items-center gap-2 text-xs font-mono ';
          let statusIcon: React.ReactNode;
          let labelClass = '';

          if (active) {
            rowClass += 'text-orange-300';
            labelClass = 'text-orange-300';
            statusIcon = (
              <span className="inline-block animate-spin text-orange-400">⟳</span>
            );
          } else if (done) {
            rowClass += 'text-green-400';
            labelClass = 'text-green-400';
            statusIcon = <span className="text-green-500">✓</span>;
          } else if (skipped) {
            rowClass += 'text-gray-600';
            labelClass = 'text-gray-600 line-through';
            statusIcon = <span className="text-gray-600">—</span>;
          } else {
            rowClass += 'text-gray-500';
            labelClass = 'text-gray-500';
            statusIcon = <span className="text-gray-600">○</span>;
          }

          return (
            <li key={stage.key} className={rowClass}>
              <span className="w-4 text-center flex-shrink-0">{statusIcon}</span>
              <span className="flex-shrink-0 text-[11px]">{stage.icon}</span>
              <span className={`${labelClass} truncate`}>{stage.label}</span>
            </li>
          );
        })}
      </ol>

      {/* Footer */}
      <p className="text-orange-500/50 font-mono text-[10px] border-t border-orange-500/20 pt-2">
        {toolsCalledCount} of {totalTools} tools called · report storing on completion
      </p>
    </div>
  );
};

export default AgentStatusWidget;
