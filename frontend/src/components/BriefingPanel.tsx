import { useCallback, useEffect, useRef, useState } from 'react';

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
const POLL_MS = 65_000;

const BriefingPanel: React.FC = () => {
  const [displayedText, setDisplayedText] = useState('Awaiting threat data…');
  const [isTyping, setIsTyping] = useState(false);
  const [isError, setIsError] = useState(false);
  const [eventCount, setEventCount] = useState(0);

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

  const fetchBriefing = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/intel/briefing`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      setEventCount(data.event_count ?? 0);
      setIsError(false);

      if (data.briefing && data.briefing !== lastBriefing.current) {
        lastBriefing.current = data.briefing;
        typeText(data.briefing);
      }
    } catch {
      setIsError(true);
    }
  }, [typeText]);

  useEffect(() => {
    fetchBriefing();
    const poll = setInterval(fetchBriefing, POLL_MS);
    return () => {
      clearInterval(poll);
      if (typingInterval.current) clearInterval(typingInterval.current);
    };
  }, [fetchBriefing]);

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
        <p
          className={`mono-text text-xs leading-relaxed whitespace-pre-wrap ${
            isError ? 'text-red-400' : 'text-gray-300'
          }`}
        >
          {displayedText}
          {isTyping && (
            <span className="animate-pulse text-blue-400">▌</span>
          )}
        </p>
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between mt-3 pt-2 border-t border-blue-500/20 text-[9px] text-gray-500 mono-text tracking-widest">
        <span>
          {eventCount > 0 && `${eventCount} events · `}Updates every 60s
        </span>
        <span className="text-blue-400/60">Llama 3.3 70B</span>
      </div>
    </div>
  );
};

export default BriefingPanel;
