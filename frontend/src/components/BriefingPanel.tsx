import { useCallback, useEffect, useRef, useState } from 'react';
import { useDashboard } from '../context/DashboardContext';

const BriefingPanel: React.FC = () => {
  const { snapshot } = useDashboard();
  const [displayedText, setDisplayedText] = useState('Awaiting threat data…');
  const [isTyping, setIsTyping] = useState(false);

  const lastBriefing = useRef<string>('');
  const typingInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  const typeText = useCallback((text: string) => {
    // Clear any in-progress typing
    if (typingInterval.current) clearInterval(typingInterval.current);

    let idx = 0;
    setIsTyping(true);
    setDisplayedText('');

    typingInterval.current = setInterval(() => {
      idx++;
      setDisplayedText(text.slice(0, idx));
      if (idx >= text.length) {
        if (typingInterval.current) clearInterval(typingInterval.current);
        typingInterval.current = null;
        setIsTyping(false);
      }
    }, 18);
  }, []);

  useEffect(() => {
    const briefing = snapshot.briefing;
    if (briefing && briefing !== lastBriefing.current) {
      lastBriefing.current = briefing;
      typeText(briefing);
    }
  }, [snapshot.briefing, typeText]);

  useEffect(() => {
    return () => {
      if (typingInterval.current) clearInterval(typingInterval.current);
    };
  }, []);

  return (
    <div className="glass-card cyber-glow p-4 w-96">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-blue-500/30">
        <span className="relative flex h-2.5 w-2.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500" />
        </span>
        <h3 className="digital-text text-blue-400 text-sm font-semibold tracking-wider">
          AI THREAT ANALYSIS
        </h3>
      </div>

      {/* Body */}
      <div className="min-h-[6rem] max-h-48 overflow-y-auto pr-1">
        <p className="mono-text text-xs leading-relaxed whitespace-pre-wrap text-gray-300">
          {displayedText}
          {isTyping && (
            <span className="animate-pulse text-blue-400">▌</span>
          )}
        </p>
      </div>

      {/* Footer */}
      <div className="mt-3 pt-2 border-t border-blue-500/20 text-[9px] mono-text tracking-widest space-y-1">
        {/* Row 1: Sources */}
        <div className="flex items-center gap-1 text-gray-500">
          <span>Sources:</span>
          <span>{snapshot.briefingEventCount} events</span>
          {snapshot.briefingIncidentCount > 0 && (
            <span className="text-blue-400">
              + {snapshot.briefingIncidentCount} agent reports
            </span>
          )}
        </div>

        {/* Row 2: Badges (conditional) */}
        {(snapshot.repeatAttackers > 0 || snapshot.campaignsDetected > 0) && (
          <div className="flex items-center gap-1.5">
            {snapshot.repeatAttackers > 0 && (
              <span className="px-1.5 py-0.5 rounded bg-red-900/50 text-red-400 border border-red-500/30">
                {snapshot.repeatAttackers} repeat attackers
              </span>
            )}
            {snapshot.campaignsDetected > 0 && (
              <span className="px-1.5 py-0.5 rounded bg-orange-900/50 text-orange-400 border border-orange-500/30">
                {snapshot.campaignsDetected} campaigns
              </span>
            )}
          </div>
        )}

        {/* Row 3: Update cadence + model */}
        <div className="flex items-center justify-between text-gray-500">
          <span>Updates every 60s</span>
          <span className="text-blue-400/60">Llama 3.3 70B</span>
        </div>
      </div>
    </div>
  );
};

export default BriefingPanel;
