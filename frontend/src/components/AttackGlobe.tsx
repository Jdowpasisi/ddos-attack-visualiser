// AttackGlobe.tsx

import React, { useEffect, useState, useRef, useCallback, useMemo } from 'react';
import Globe, { GlobeMethods } from 'react-globe.gl';
import { CyberDashboard, ThreatEvent, AttackStats } from './CyberDashboard';
import { MAX_ARCS, ARC_TTL_MS, FETCH_INTERVAL_MS, STATS_INTERVAL_MS } from '../constants';

// Types for attack data from API
interface AttackArc {
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
  isSimulated: boolean;
}

interface StreamResponse {
  count: number;
  attacks: AttackArc[];
  latest_id: number;
  has_more: boolean;
  backlog: number;
}

// Fixed "My Server" coordinates (US - Ashburn, Virginia - major data center hub)
const MY_SERVER_COORDS = {
  lat: 39.0438,
  lon: -77.4874,
  label: 'My Server (US)',
};

// API Configuration - uses environment variable with fallback
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Arc data structure for Globe
export interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  stroke: number;
  label: string;
  data: AttackArc;
  hitCount: number;       // Number of aggregated events
  lastHitAt: number;      // Timestamp of most recent hit (ms)
  isSimulated: boolean;
}

// Severity to color mapping
const getSeverityColor = (severity: number): string => {
  if (severity <= 3) {
    // Green (low threat)
    return 'rgba(0, 255, 100, 0.8)';
  } else if (severity <= 6) {
    // Yellow/Orange (medium threat)
    const ratio = (severity - 3) / 3;
    const r = Math.round(255);
    const g = Math.round(255 * (1 - ratio * 0.5));
    return `rgba(${r}, ${g}, 0, 0.8)`;
  } else if (severity <= 8) {
    // Orange/Red (high threat)
    const ratio = (severity - 6) / 2;
    const g = Math.round(128 * (1 - ratio));
    return `rgba(255, ${g}, 0, 0.9)`;
  } else {
    // Red/Magenta (critical threat)
    return 'rgba(255, 0, 80, 1.0)';
  }
};

// Aggregation helper functions

// Unique key for an attack pattern
const arcKey = (attack: AttackArc): string =>
  `${attack.sourceIp}|${attack.targetIp}|${attack.attackType}`;

// Calculate visual weight based on repetition
const getStrokeWidth = (hitCount: number, severity: number): number => {
  const base = 0.5 + (severity / 10) * 1.5;
  const hitBonus = Math.min(Math.log2(hitCount) * 0.4, 2.0);
  return Math.min(base + hitBonus, 4.0);
};

// Calculate color intensity based on aggregation
const getAggregatedColor = (severity: number, hitCount: number): string => {
  const effectiveSeverity = Math.min(10, severity + Math.log2(hitCount) * 0.8);
  return getSeverityColor(effectiveSeverity);
};

// Main AttackGlobe component
const AttackGlobe: React.FC = () => {
  const globeRef = useRef<GlobeMethods>(null!);
  const [arcsData, setArcsData] = useState<GlobeArc[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [latestId, setLatestId] = useState(0);
  const [backlog, setBacklog] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [selectedArc, setSelectedArc] = useState<GlobeArc | null>(null);
  const [stats, setStats] = useState<AttackStats | null>(null);

  // Convert AttackArc to GlobeArc
  const mapToGlobeArc = useCallback((attack: AttackArc): GlobeArc => ({
    startLat: attack.srcLat,
    startLng: attack.srcLon,
    endLat: MY_SERVER_COORDS.lat,
    endLng: MY_SERVER_COORDS.lon,
    color: getSeverityColor(attack.severity),
    stroke: getStrokeWidth(1, attack.severity),
    label: `${attack.attackType} · ${attack.sourceIp} → ${attack.targetIp} · 1 hit · Severity ${attack.severity}`,
    data: {
      ...attack,
      // Use current time for TTL calculation so attacks appear "live"
      timestamp: new Date().toISOString(),
    },
    hitCount: 1,
    lastHitAt: Date.now(),
    isSimulated: attack.isSimulated ?? false,
  }), []);

  // Filter out expired arcs based on TTL
  const filterActiveArcs = useCallback((arcs: GlobeArc[]): GlobeArc[] => {
    const now = Date.now();
    return arcs.filter((arc) => {
      return (now - arc.lastHitAt) < ARC_TTL_MS;
    });
  }, []);

  // Fetch live attacks from API using incremental polling
  const fetchLiveAttacks = useCallback(async () => {
    try {
      // Use stream endpoint with since_id for incremental updates
      const url = latestId > 0
        ? `${API_BASE_URL}/api/v1/attacks/stream?since_id=${latestId}&limit=50`
        : `${API_BASE_URL}/api/v1/attacks/stream?limit=100`;
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data: StreamResponse = await response.json();
      
      // Update latest ID for next incremental fetch
      if (data.latest_id > latestId) {
        setLatestId(data.latest_id);
      }
      
      // Update backlog count
      setBacklog(data.backlog ?? 0);
      
      // Map new attacks to Globe arc format
      const newArcs: GlobeArc[] = data.attacks.map(mapToGlobeArc);
      
      // Merge with existing arcs using aggregation
      setArcsData((prevArcs) => {
        const now = Date.now();
        const arcMap = new Map<string, GlobeArc>();

        // 1. Keep existing valid arcs
        filterActiveArcs(prevArcs).forEach(arc => {
          arcMap.set(arcKey(arc.data), arc);
        });

        // 2. Merge new attacks
        newArcs.forEach((incoming) => {
          const key = arcKey(incoming.data);
          const existing = arcMap.get(key);

          if (existing) {
            const newCount = existing.hitCount + 1;
            // KEY FIX: Retain the highest severity and packet rate ever seen for this pattern
            const peakSeverity = Math.max(existing.data.severity, incoming.data.severity);
            const peakPacketRate = Math.max(existing.data.packetRate, incoming.data.packetRate);

            arcMap.set(key, {
              ...existing,
              hitCount: newCount,
              lastHitAt: now,
              // Use peakSeverity for visual calculations
              stroke: getStrokeWidth(newCount, peakSeverity),
              color: getAggregatedColor(peakSeverity, newCount),
              label: `${incoming.data.attackType} · ${incoming.data.sourceIp} → ${incoming.data.targetIp} · ${newCount} hits · Severity ${peakSeverity.toFixed(1)}`,
              // OVERRIDE the data object so the peak values persist and get passed down
              data: {
                ...existing.data,
                severity: peakSeverity,
                packetRate: peakPacketRate,
                timestamp: incoming.data.timestamp // keep the most recent timestamp
              }
            });
          } else {
            // Create new
            arcMap.set(key, {
              ...mapToGlobeArc(incoming.data),
              hitCount: 1,
              lastHitAt: now,
            });
          }
        });

        // 3. Sort by visual weight (severity * hits) and slice
        return Array.from(arcMap.values())
          .sort((a, b) =>
            (b.data.severity * Math.log(b.hitCount + 1)) -
            (a.data.severity * Math.log(a.hitCount + 1))
          )
          .slice(0, MAX_ARCS);
      });
      
      setError(null);
    } catch (err) {
      console.error('Failed to fetch live attacks:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
    } finally {
      setIsLoading(false);
    }
  }, [latestId, mapToGlobeArc, filterActiveArcs]);

  // Fetch attack stats from API
  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/attacks/stats`);
      if (!response.ok) throw new Error(`Stats HTTP ${response.status}`);
      const data: AttackStats = await response.json();
      setStats(data);
    } catch (err) {
      console.error('Failed to fetch attack stats:', err);
    }
  }, []);

  // Stats polling (every 30s)
  useEffect(() => {
    fetchStats();
    const id = setInterval(fetchStats, STATS_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchStats]);

  // Initial fetch and interval setup
  useEffect(() => {
    if (isPaused) return;

    // Initial fetch
    fetchLiveAttacks();
    
    // Set up polling interval
    const intervalId = setInterval(fetchLiveAttacks, FETCH_INTERVAL_MS);
    
    // Cleanup on unmount
    return () => clearInterval(intervalId);
  }, [fetchLiveAttacks, isPaused]);

  // Periodic TTL cleanup - remove expired arcs every second
  useEffect(() => {
    if (isPaused) return;

    const cleanupInterval = setInterval(() => {
      setArcsData((prevArcs) => filterActiveArcs(prevArcs));
    }, 1000);
    
    return () => clearInterval(cleanupInterval);
  }, [filterActiveArcs, isPaused]);

  // Memoized active arcs for rendering (already filtered, but ensures freshness)
  const activeArcs = useMemo(() => filterActiveArcs(arcsData), [arcsData, filterActiveArcs]);

  // Convert arcs to ThreatEvent format for the dashboard
  const threatEvents: ThreatEvent[] = useMemo(() => 
    activeArcs.map(arc => ({
      id: arc.data.id,
      sourceIp: arc.data.sourceIp,
      attackType: arc.data.attackType,
      severity: arc.data.severity,
      timestamp: arc.data.timestamp,
    })).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()),
    [activeArcs]
  );

  // Configure globe on mount
  useEffect(() => {
    if (globeRef.current) {
      // Set initial camera position to show the globe nicely
      globeRef.current.pointOfView({
        lat: 30,
        lng: -40,
        altitude: 2.5,
      });
      
      // Auto-rotate for visual effect
      const controls = globeRef.current.controls();
      if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.5;
      }
    }
  }, []);

  // Calculate how many real arcs we currently have
  const realArcCount = arcsData.filter(arc => !arc.isSimulated).length;
  const SIMULATED_VISIBILITY_THRESHOLD = 20;

  // Filter out simulated arcs entirely if we are at or above threshold
  const visibleArcs = realArcCount >= SIMULATED_VISIBILITY_THRESHOLD
    ? arcsData.filter(arc => !arc.isSimulated)
    : arcsData;

  // Calculate dynamic opacity for simulated arcs (0.0 to 0.6)
  const simulatedOpacityFloat = realArcCount >= SIMULATED_VISIBILITY_THRESHOLD
    ? 0
    : (1 - realArcCount / SIMULATED_VISIBILITY_THRESHOLD) * 0.6;

  // Convert float to 2-character hex (e.g., 0.6 -> "99", 0.3 -> "4c")
  const simulatedOpacityHex = Math.floor(simulatedOpacityFloat * 255)
    .toString(16)
    .padStart(2, '0');

  // Server point data for visualization
  const serverPointData = [
    {
      lat: MY_SERVER_COORDS.lat,
      lng: MY_SERVER_COORDS.lon,
      size: 0.5,
      color: '#00ff88',
      label: MY_SERVER_COORDS.label,
    },
  ];

  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        backgroundColor: '#000011',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <Globe
        ref={globeRef}
        globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
        backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
        // Arc layer configuration - use visibleArcs (TTL-filtered + simulated visibility)
        arcsData={visibleArcs}
        arcStartLat={(d) => (d as GlobeArc).startLat}
        arcStartLng={(d) => (d as GlobeArc).startLng}
        arcEndLat={(d) => (d as GlobeArc).endLat}
        arcEndLng={(d) => (d as GlobeArc).endLng}
        arcColor={(arc) => {
          const a = arc as GlobeArc;
          const isSelected = selectedArc?.data.id === a.data.id;
          const hasSel = selectedArc !== null;
          const opacity = hasSel && !isSelected ? "40" : "FF";

          // Simulated arcs use dynamic opacity based on real arc count
          if (a.isSimulated) {
            const dimState = hasSel && !isSelected ? "20" : simulatedOpacityHex;
            return a.color + dimState;
          }
          return a.color + opacity;
        }}
        arcStroke={(arc) => {
          const a = arc as GlobeArc;
          const base = a.stroke ?? 1;
          if (selectedArc?.data.id === a.data.id) return base * 2;
          return base;
        }}
        onArcClick={(d) => {
          const arc = d as GlobeArc;
          setSelectedArc((prev) =>
            prev && arcKey(prev.data) === arcKey(arc.data) ? null : arc
          );
        }}
        arcDashLength={0.4}
        arcDashGap={0.6}
        arcDashAnimateTime={1500}
        arcLabel={(d) => (d as GlobeArc).label}
        arcsTransitionDuration={300}
        // Point layer for server location
        pointsData={serverPointData}
        pointLat={(d) => (d as typeof serverPointData[0]).lat}
        pointLng={(d) => (d as typeof serverPointData[0]).lng}
        pointColor={(d) => (d as typeof serverPointData[0]).color}
        pointAltitude={0.01}
        pointRadius={(d) => (d as typeof serverPointData[0]).size}
        pointLabel={(d) => (d as typeof serverPointData[0]).label}
        // Ring effect for server
        ringsData={serverPointData}
        ringLat={(d) => (d as typeof serverPointData[0]).lat}
        ringLng={(d) => (d as typeof serverPointData[0]).lng}
        ringColor={() => '#00ff88'}
        ringMaxRadius={3}
        ringPropagationSpeed={2}
        ringRepeatPeriod={1000}
        // Atmosphere
        atmosphereColor="#3a8ee6"
        atmosphereAltitude={0.15}
        // Performance
        animateIn={true}
      />

      {/* Cyber Threat Intelligence Dashboard */}
      <CyberDashboard
        threats={threatEvents}
        arcs={activeArcs}
        stats={stats}
        backlog={backlog}
        totalEvents={activeArcs.length}
        arcCount={visibleArcs.length}
        arcMax={MAX_ARCS}
        isLive={!isLoading && !error}
        error={error}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused((p) => !p)}
        selectedArc={selectedArc}
        onDeselectArc={() => setSelectedArc(null)}
        serverStatus={MY_SERVER_COORDS}
      />

      {/* Paused state full-screen border overlay */}
      {isPaused && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            zIndex: 25,
            pointerEvents: 'none',
            border: '2px solid rgba(239,68,68,0.45)',
          }}
        />
      )}

      {/* Server Location Info is now rendered inside CyberDashboard (bottom-left column) */}
    </div>
  );
};

export default AttackGlobe;
