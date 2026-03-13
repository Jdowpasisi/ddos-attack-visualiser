export const ArcLegend = () => (
  <div className="glass-card px-3 py-2 flex flex-col gap-2">
    <p className="digital-text text-gray-600 text-xs uppercase tracking-widest">
      Arc Legend
    </p>
    {/* Real threat intel */}
    <div className="flex items-center gap-2">
      <svg width="64" height="8">
        <defs>
          <linearGradient id="sevGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22c55e" />   {/* LOW: Green */}
            <stop offset="50%" stopColor="#f97316" />  {/* HIGH: Orange */}
            <stop offset="100%" stopColor="#f43f5e" /> {/* CRITICAL: Red */}
          </linearGradient>
        </defs>
        <line
          x1="0" y1="4" x2="64" y2="4"
          stroke="url(#sevGradient)"
          strokeWidth="2"
          strokeDasharray="none"
        />
      </svg>
      <span className="text-gray-400 text-xs">Live threat intel (color = severity)</span>
    </div>
    {/* Simulated */}
    <div className="flex items-center gap-2">
      <svg width="32" height="8">
        <line x1="0" y1="4" x2="32" y2="4" stroke="#00dcff" strokeWidth="2" />
      </svg>
      <span className="text-gray-400 text-xs">Simulated fallback</span>
    </div>
  </div>
);
