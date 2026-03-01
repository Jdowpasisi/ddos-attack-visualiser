import React, { useEffect, useState, useRef, useCallback, useMemo } from 'react';
import Globe, { GlobeMethods } from 'react-globe.gl';
import { CyberDashboard, ServerStatus, ThreatEvent } from './CyberDashboard';

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
}

interface StreamResponse {
  count: number;
  attacks: AttackArc[];
  latest_id: number;
  has_more: boolean;
}

// Fixed "My Server" coordinates (US - Ashburn, Virginia - major data center hub)
const MY_SERVER_COORDS = {
  lat: 39.0438,
  lon: -77.4874,
  label: 'My Server (US)',
};

// API Configuration - uses environment variable with fallback
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const FETCH_INTERVAL_MS = 5000;

// Arc TTL (Time To Live) in milliseconds - attacks fade after this time
// Increased to keep attacks visible longer (5 minutes)
const ARC_TTL_MS = 300000; // 5 minutes (300 seconds)

// Maximum number of arcs to keep in state
const MAX_ARCS = 100;

// Arc data structure for Globe
interface GlobeArc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  stroke: number;
  label: string;
  data: AttackArc;
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

// Main AttackGlobe component
const AttackGlobe: React.FC = () => {
  const globeRef = useRef<GlobeMethods>(null!);
  const [arcsData, setArcsData] = useState<GlobeArc[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [latestId, setLatestId] = useState(0);

  // Convert AttackArc to GlobeArc
  const mapToGlobeArc = useCallback((attack: AttackArc): GlobeArc => ({
    startLat: attack.srcLat,
    startLng: attack.srcLon,
    endLat: MY_SERVER_COORDS.lat,
    endLng: MY_SERVER_COORDS.lon,
    color: getSeverityColor(attack.severity),
    stroke: Math.max(0.5, Math.min(3, attack.strokeWidth)),
    label: `${attack.attackType} | ${attack.sourceIp} → ${attack.targetIp} | Severity: ${attack.severity}`,
    data: {
      ...attack,
      // Use current time for TTL calculation so attacks appear "live"
      timestamp: new Date().toISOString(),
    },
  }), []);

  // Filter out expired arcs based on TTL
  const filterActiveArcs = useCallback((arcs: GlobeArc[]): GlobeArc[] => {
    const now = Date.now();
    return arcs.filter((arc) => {
      const attackTime = new Date(arc.data.timestamp).getTime();
      return (now - attackTime) < ARC_TTL_MS;
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
      
      // Map new attacks to Globe arc format
      const newArcs: GlobeArc[] = data.attacks.map(mapToGlobeArc);
      
      // Merge with existing arcs, apply TTL filter, and limit count
      setArcsData((prevArcs) => {
        // Combine existing (filtered by TTL) with new arcs
        const existingActive = filterActiveArcs(prevArcs);
        const combined = [...existingActive, ...newArcs];
        
        // Deduplicate by attack ID
        const uniqueArcs = combined.reduce((acc, arc) => {
          if (!acc.some((a) => a.data.id === arc.data.id)) {
            acc.push(arc);
          }
          return acc;
        }, [] as GlobeArc[]);
        
        // Limit to MAX_ARCS, keeping newest
        const sorted = uniqueArcs.sort((a, b) => 
          new Date(b.data.timestamp).getTime() - new Date(a.data.timestamp).getTime()
        );
        
        return sorted.slice(0, MAX_ARCS);
      });
      
      setError(null);
    } catch (err) {
      console.error('Failed to fetch live attacks:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
    } finally {
      setIsLoading(false);
    }
  }, [latestId, mapToGlobeArc, filterActiveArcs]);

  // Initial fetch and interval setup
  useEffect(() => {
    // Initial fetch
    fetchLiveAttacks();
    
    // Set up polling interval
    const intervalId = setInterval(fetchLiveAttacks, FETCH_INTERVAL_MS);
    
    // Cleanup on unmount
    return () => clearInterval(intervalId);
  }, [fetchLiveAttacks]);

  // Periodic TTL cleanup - remove expired arcs every second
  useEffect(() => {
    const cleanupInterval = setInterval(() => {
      setArcsData((prevArcs) => filterActiveArcs(prevArcs));
    }, 1000);
    
    return () => clearInterval(cleanupInterval);
  }, [filterActiveArcs]);

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
        // Arc layer configuration - use activeArcs (TTL-filtered)
        arcsData={activeArcs}
        arcStartLat={(d) => (d as GlobeArc).startLat}
        arcStartLng={(d) => (d as GlobeArc).startLng}
        arcEndLat={(d) => (d as GlobeArc).endLat}
        arcEndLng={(d) => (d as GlobeArc).endLng}
        arcColor={(d) => (d as GlobeArc).color}
        arcStroke={(d) => (d as GlobeArc).stroke}
        arcDashLength={0.5}
        arcDashGap={0.2}
        arcDashAnimateTime={2000}
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
        totalEvents={activeArcs.length}
        isLive={!isLoading && !error}
        error={error}
      />

      {/* Server Location Info */}
      <div className="absolute bottom-4 left-4 z-10 md:bottom-6 md:left-6">
        <ServerStatus
          label={MY_SERVER_COORDS.label}
          lat={MY_SERVER_COORDS.lat}
          lon={MY_SERVER_COORDS.lon}
        />
      </div>
    </div>
  );
};

export default AttackGlobe;
