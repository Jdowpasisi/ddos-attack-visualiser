declare module 'react-globe.gl' {
  import { Object3D } from 'three';
  import { ComponentType, RefObject } from 'react';

  export interface GlobeMethods {
    pointOfView: (pov?: { lat?: number; lng?: number; altitude?: number }, transitionMs?: number) => { lat: number; lng: number; altitude: number };
    pauseAnimation: () => void;
    resumeAnimation: () => void;
    controls: () => any;
    scene: () => Object3D;
    camera: () => any;
    renderer: () => any;
  }

  export interface GlobeProps {
    // Container
    width?: number;
    height?: number;

    // Globe appearance
    globeImageUrl?: string;
    backgroundImageUrl?: string;
    bumpImageUrl?: string;
    showAtmosphere?: boolean;
    atmosphereColor?: string;
    atmosphereAltitude?: number;
    animateIn?: boolean;

    // Points layer
    pointsData?: object[];
    pointLat?: string | ((obj: object) => number);
    pointLng?: string | ((obj: object) => number);
    pointColor?: string | ((obj: object) => string);
    pointAltitude?: number | string | ((obj: object) => number);
    pointRadius?: number | string | ((obj: object) => number);
    pointLabel?: string | ((obj: object) => string);
    pointsMerge?: boolean;
    pointsTransitionDuration?: number;
    onPointClick?: (point: object, event: MouseEvent) => void;
    onPointHover?: (point: object | null, prevPoint: object | null) => void;

    // Arcs layer
    arcsData?: object[];
    arcStartLat?: string | ((obj: object) => number);
    arcStartLng?: string | ((obj: object) => number);
    arcEndLat?: string | ((obj: object) => number);
    arcEndLng?: string | ((obj: object) => number);
    arcColor?: string | ((obj: object) => string | string[]);
    arcAltitude?: number | string | ((obj: object) => number);
    arcAltitudeAutoScale?: number | string | ((obj: object) => number);
    arcStroke?: number | string | ((obj: object) => number);
    arcCurveResolution?: number;
    arcCircularResolution?: number;
    arcDashLength?: number | string | ((obj: object) => number);
    arcDashGap?: number | string | ((obj: object) => number);
    arcDashInitialGap?: number | string | ((obj: object) => number);
    arcDashAnimateTime?: number | string | ((obj: object) => number);
    arcLabel?: string | ((obj: object) => string);
    arcsTransitionDuration?: number;
    onArcClick?: (arc: object, event: MouseEvent) => void;
    onArcHover?: (arc: object | null, prevArc: object | null) => void;

    // Rings layer
    ringsData?: object[];
    ringLat?: string | ((obj: object) => number);
    ringLng?: string | ((obj: object) => number);
    ringAltitude?: number | string | ((obj: object) => number);
    ringColor?: string | ((obj: object) => string | string[]);
    ringResolution?: number;
    ringMaxRadius?: number | string | ((obj: object) => number);
    ringPropagationSpeed?: number | string | ((obj: object) => number);
    ringRepeatPeriod?: number | string | ((obj: object) => number);

    // Labels layer
    labelsData?: object[];
    labelLat?: string | ((obj: object) => number);
    labelLng?: string | ((obj: object) => number);
    labelText?: string | ((obj: object) => string);
    labelColor?: string | ((obj: object) => string);
    labelAltitude?: number | string | ((obj: object) => number);
    labelSize?: number | string | ((obj: object) => number);
    labelTypeFace?: object;
    labelRotation?: number | string | ((obj: object) => number);
    labelResolution?: number;
    labelIncludeDot?: boolean;
    labelDotRadius?: number | string | ((obj: object) => number);
    labelsTransitionDuration?: number;

    // Custom layer
    customLayerData?: object[];
    customThreeObject?: (obj: object) => Object3D;
    customThreeObjectUpdate?: (obj: Object3D, objData: object) => void;

    // Hexed polygons layer
    hexPolygonsData?: object[];
    
    // Paths layer
    pathsData?: object[];

    // Tiles layer
    tilesData?: object[];

    // Polygons layer
    polygonsData?: object[];

    // Hex bin layer
    hexBinPointsData?: object[];

    // Callbacks
    onGlobeReady?: () => void;
    onGlobeClick?: (coords: { lat: number; lng: number }, event: MouseEvent) => void;
    onGlobeRightClick?: (coords: { lat: number; lng: number }, event: MouseEvent) => void;
  }

  const Globe: ComponentType<GlobeProps & { ref?: RefObject<GlobeMethods> }>;
  export default Globe;
}
