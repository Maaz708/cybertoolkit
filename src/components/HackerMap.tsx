import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in react-leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
    iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
    iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
    shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Custom SVG crosshair icons for different risk levels
const createCustomIcon = (color: string) => {
    const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 36 36">
      <circle cx="18" cy="18" r="5" fill="${color}" opacity="1"/>
      <circle cx="18" cy="18" r="9" fill="none" stroke="${color}" stroke-width="1.5" opacity="0.8"/>
      <circle cx="18" cy="18" r="14" fill="none" stroke="${color}" stroke-width="0.8" opacity="0.4"/>
      <line x1="18" y1="2" x2="18" y2="9" stroke="${color}" stroke-width="1.5"/>
      <line x1="18" y1="27" x2="18" y2="34" stroke="${color}" stroke-width="1.5"/>
      <line x1="2" y1="18" x2="9" y2="18" stroke="${color}" stroke-width="1.5"/>
      <line x1="27" y1="18" x2="34" y2="18" stroke="${color}" stroke-width="1.5"/>
    </svg>`;
    return new L.Icon({
        iconUrl: `data:image/svg+xml;base64,${btoa(svg)}`,
        iconSize: [36, 36],
        iconAnchor: [18, 18],
        popupAnchor: [0, -22],
    });
};

const redIcon    = createCustomIcon('#ff2d2d');
const orangeIcon = createCustomIcon('#ff8c00');
const greenIcon  = createCustomIcon('#00ff88');
const blueIcon   = createCustomIcon('#00aaff');

interface HackerMapProps {
    data: Array<{
        ip: string;
        country: string;
        city: string;
        lat: number;
        lon: number;
        isp: string;
        riskLevel: 'normal' | 'medium' | 'high';
        connectionCount: number;
        country_code: string;
        region?: string;
        org?: string;
    }>;
}

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  :root {
    --bg-void: #020408;
    --bg-panel: #080e14;
    --bg-card: #0b1520;
    --bg-elevated: #0f1e2e;
    --border-dim: rgba(0, 200, 255, 0.12);
    --border-glow: rgba(0, 200, 255, 0.35);
    --accent-cyan: #00c8ff;
    --accent-green: #00ff88;
    --accent-red: #ff2d2d;
    --accent-orange: #ff8c00;
    --text-primary: #c8eaf5;
    --text-secondary: #5a8a9f;
    --text-mono: #00c8ff;
    --glow-cyan: 0 0 12px rgba(0,200,255,0.5);
    --glow-red: 0 0 12px rgba(255,45,45,0.6);
    --glow-green: 0 0 12px rgba(0,255,136,0.5);
    --glow-orange: 0 0 12px rgba(255,140,0,0.5);
  }

  .hm-root {
    font-family: 'Rajdhani', sans-serif;
    background: var(--bg-void);
    color: var(--text-primary);
    padding: 20px;
    border-radius: 4px;
    border: 1px solid var(--border-dim);
    position: relative;
    overflow: hidden;
  }

  .hm-root::before {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      to bottom,
      transparent 0px,
      transparent 3px,
      rgba(0,0,0,0.06) 3px,
      rgba(0,0,0,0.06) 4px
    );
    pointer-events: none;
    z-index: 0;
  }

  .hm-inner { position: relative; z-index: 1; }

  .hm-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
    padding-bottom: 14px;
    border-bottom: 1px solid var(--border-dim);
  }

  .hm-header-icon {
    width: 38px; height: 38px;
    border: 1px solid var(--accent-cyan);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    box-shadow: var(--glow-cyan);
    color: var(--accent-cyan);
    font-size: 18px;
    flex-shrink: 0;
    animation: pulse-border 3s ease-in-out infinite;
  }

  @keyframes pulse-border {
    0%, 100% { box-shadow: 0 0 8px rgba(0,200,255,0.4); }
    50%       { box-shadow: 0 0 20px rgba(0,200,255,0.9); }
  }

  .hm-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 15px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2px;
    text-shadow: var(--glow-cyan);
  }

  .hm-subtitle {
    font-size: 11px;
    color: var(--text-secondary);
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
  }

  .hm-live-badge {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--accent-green);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .hm-live-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent-green);
    box-shadow: var(--glow-green);
    animation: blink 1.2s step-end infinite;
  }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.15} }

  .hm-stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 16px;
  }

  .hm-stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-top-width: 2px;
    padding: 12px 10px;
    text-align: center;
    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
    transition: border-color 0.2s;
  }

  .hm-stat-card:hover { background: var(--bg-elevated); }

  .hm-stat-card.total    { border-top-color: var(--accent-cyan); }
  .hm-stat-card.high     { border-top-color: var(--accent-red); }
  .hm-stat-card.medium   { border-top-color: var(--accent-orange); }
  .hm-stat-card.countries { border-top-color: var(--accent-green); }

  .hm-stat-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 28px;
    line-height: 1;
    margin-bottom: 4px;
  }

  .hm-stat-card.total     .hm-stat-value { color: var(--accent-cyan);   text-shadow: var(--glow-cyan); }
  .hm-stat-card.high      .hm-stat-value { color: var(--accent-red);    text-shadow: var(--glow-red); }
  .hm-stat-card.medium    .hm-stat-value { color: var(--accent-orange); text-shadow: var(--glow-orange); }
  .hm-stat-card.countries .hm-stat-value { color: var(--accent-green);  text-shadow: var(--glow-green); }

  .hm-stat-label {
    font-size: 10px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-family: 'Share Tech Mono', monospace;
  }

  .hm-map-wrapper {
    position: relative;
    margin-bottom: 16px;
    border: 1px solid var(--border-glow);
    box-shadow: 0 0 30px rgba(0,200,255,0.06);
  }

  .hm-map-wrapper::before,
  .hm-map-wrapper::after {
    content: '';
    position: absolute;
    width: 18px; height: 18px;
    z-index: 1000;
    pointer-events: none;
  }
  .hm-map-wrapper::before {
    top: -1px; left: -1px;
    border-top: 2px solid var(--accent-cyan);
    border-left: 2px solid var(--accent-cyan);
  }
  .hm-map-wrapper::after {
    bottom: -1px; right: -1px;
    border-bottom: 2px solid var(--accent-cyan);
    border-right: 2px solid var(--accent-cyan);
  }

  .hm-map-corner-tr,
  .hm-map-corner-bl {
    position: absolute;
    width: 18px; height: 18px;
    z-index: 1000;
    pointer-events: none;
  }
  .hm-map-corner-tr {
    top: -1px; right: -1px;
    border-top: 2px solid var(--accent-cyan);
    border-right: 2px solid var(--accent-cyan);
  }
  .hm-map-corner-bl {
    bottom: -1px; left: -1px;
    border-bottom: 2px solid var(--accent-cyan);
    border-left: 2px solid var(--accent-cyan);
  }

  .hm-map-label {
    position: absolute;
    top: 10px; left: 14px;
    z-index: 1000;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-cyan);
    letter-spacing: 2px;
    opacity: 0.7;
    pointer-events: none;
    text-shadow: var(--glow-cyan);
  }

  .hm-map-container {
    height: 420px;
    width: 100%;
  }

  /* Dark map tiles via CSS filter */
  .hm-map-container .leaflet-tile {
    filter: invert(1) hue-rotate(180deg) brightness(0.72) saturate(0.45) contrast(1.1) !important;
  }

  /* Popup override */
  .leaflet-popup-content-wrapper {
    background: #06101a !important;
    border: 1px solid rgba(0,200,255,0.35) !important;
    border-radius: 2px !important;
    box-shadow: 0 0 24px rgba(0,200,255,0.15) !important;
    color: #c8eaf5 !important;
    padding: 0 !important;
  }
  .leaflet-popup-content {
    margin: 12px 14px !important;
  }
  .leaflet-popup-tip-container { filter: drop-shadow(0 0 4px rgba(0,200,255,0.3)); }
  .leaflet-popup-tip { background: #06101a !important; }
  .leaflet-popup-close-button { color: #00c8ff !important; top: 6px !important; right: 8px !important; }

  .hm-popup-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: #00c8ff;
    text-shadow: 0 0 8px rgba(0,200,255,0.5);
    margin-bottom: 6px;
  }

  .hm-popup-badge {
    display: inline-block;
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 2px 7px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
    border-radius: 2px;
  }
  .hm-popup-badge.high   { background: rgba(255,45,45,0.15);  color:#ff2d2d; border:1px solid rgba(255,45,45,0.5); }
  .hm-popup-badge.medium { background: rgba(255,140,0,0.15);  color:#ff8c00; border:1px solid rgba(255,140,0,0.5); }
  .hm-popup-badge.normal { background: rgba(0,255,136,0.12);  color:#00ff88; border:1px solid rgba(0,255,136,0.4); }

  .hm-popup-row {
    font-family: 'Rajdhani', sans-serif;
    font-size: 12px;
    line-height: 1.8;
    color: #6a9ab0;
  }
  .hm-popup-row strong { color: #a8cfe0; font-weight: 600; }
  .hm-popup-coords {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #2e5a70;
    margin-top: 4px;
  }

  /* IP List panel */
  .hm-list-panel {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 14px 16px;
    max-height: 220px;
    overflow-y: auto;
  }

  .hm-list-panel::-webkit-scrollbar { width: 3px; }
  .hm-list-panel::-webkit-scrollbar-track { background: transparent; }
  .hm-list-panel::-webkit-scrollbar-thumb { background: rgba(0,200,255,0.3); border-radius: 2px; }

  .hm-list-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2.5px;
    margin-bottom: 10px;
    opacity: 0.75;
  }

  .hm-list-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 7px 0;
    border-bottom: 1px solid rgba(0,200,255,0.05);
  }
  .hm-list-item:last-child { border-bottom: none; }
  .hm-list-item:hover { background: rgba(0,200,255,0.03); margin: 0 -16px; padding: 7px 16px; }

  .hm-list-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .hm-list-dot.high   { background: var(--accent-red);    box-shadow: var(--glow-red); }
  .hm-list-dot.medium { background: var(--accent-orange); box-shadow: var(--glow-orange); }
  .hm-list-dot.normal { background: var(--accent-green);  box-shadow: var(--glow-green); }

  .hm-list-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text-mono);
    min-width: 125px;
  }

  .hm-list-location {
    font-size: 12px;
    color: var(--text-secondary);
    flex: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-family: 'Rajdhani', sans-serif;
  }

  .hm-list-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 1px 6px;
    border-radius: 2px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }
  .hm-list-badge.high   { background: rgba(255,45,45,0.12);  color:#ff2d2d; border:1px solid rgba(255,45,45,0.35); }
  .hm-list-badge.medium { background: rgba(255,140,0,0.12);  color:#ff8c00; border:1px solid rgba(255,140,0,0.35); }
  .hm-list-badge.normal { background: rgba(0,255,136,0.10);  color:#00ff88; border:1px solid rgba(0,255,136,0.28); }

  .hm-more-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-secondary);
    text-align: center;
    display: block;
    margin-top: 10px;
    letter-spacing: 1.5px;
    opacity: 0.6;
  }
`;

const HackerMap: React.FC<HackerMapProps> = ({ data }) => {
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        setIsClient(true);
    }, []);

    if (!isClient) {
        return (
            <div className="hm-root">
                <style>{styles}</style>
                <div className="hm-inner">
                    <div className="hm-header">
                        <div className="hm-header-icon">⊕</div>
                        <div>
                            <div className="hm-title">Hacker Tracking Map</div>
                            <div className="hm-subtitle">Real-time IP Geolocation Intelligence</div>
                        </div>
                    </div>
                    <div style={{ height: 400, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#2e5a70', fontFamily: 'Share Tech Mono, monospace', fontSize: 12, letterSpacing: 3 }}>
                        INITIALIZING MAP...
                    </div>
                </div>
            </div>
        );
    }

    // ── Original logic — untouched ─────────────────────────────────────────
    const getIcon = (riskLevel: string) => {
        switch (riskLevel) {
            case 'high': return redIcon;
            case 'medium': return orangeIcon;
            case 'normal': return greenIcon;
            default: return blueIcon;
        }
    };

    const getRiskColor = (riskLevel: string) => {
        switch (riskLevel) {
            case 'high': return 'error';
            case 'medium': return 'warning';
            case 'normal': return 'success';
            default: return 'default';
        }
    };

    const stats = {
        total: data?.length || 0,
        high: data?.filter(d => d.riskLevel === 'high').length || 0,
        medium: data?.filter(d => d.riskLevel === 'medium').length || 0,
        normal: data?.filter(d => d.riskLevel === 'normal').length || 0,
        countries: [...new Set(data?.map(d => d.country))].length || 0
    };
    // ──────────────────────────────────────────────────────────────────────

    return (
        <div className="hm-root">
            <style>{styles}</style>
            <div className="hm-inner">

                {/* Header */}
                <div className="hm-header">
                    <div className="hm-header-icon">⊕</div>
                    <div>
                        <div className="hm-title">Hacker Tracking Map</div>
                        <div className="hm-subtitle">// Real-time IP Geolocation Intelligence</div>
                    </div>
                    <div className="hm-live-badge">
                        <span className="hm-live-dot" />
                        LIVE
                    </div>
                </div>

                {/* Stats */}
                <div className="hm-stats">
                    <div className="hm-stat-card total">
                        <div className="hm-stat-value">{stats.total}</div>
                        <div className="hm-stat-label">Total IPs</div>
                    </div>
                    <div className="hm-stat-card high">
                        <div className="hm-stat-value">{stats.high}</div>
                        <div className="hm-stat-label">High Risk</div>
                    </div>
                    <div className="hm-stat-card medium">
                        <div className="hm-stat-value">{stats.medium}</div>
                        <div className="hm-stat-label">Medium Risk</div>
                    </div>
                    <div className="hm-stat-card countries">
                        <div className="hm-stat-value">{stats.countries}</div>
                        <div className="hm-stat-label">Countries</div>
                    </div>
                </div>

                {/* Map */}
                <div className="hm-map-wrapper">
                    <div className="hm-map-corner-tr" />
                    <div className="hm-map-corner-bl" />
                    <div className="hm-map-label">// THREAT SURFACE MAP</div>
                    <MapContainer
                        center={[20, 0]}
                        zoom={2}
                        className="hm-map-container"
                        zoomControl={true}
                    >
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />

                        {data?.map((location, index) => (
                            <Marker
                                key={`${location.ip}-${index}`}
                                position={[location.lat, location.lon]}
                                icon={getIcon(location.riskLevel)}
                            >
                                <Popup>
                                    <div className="hm-popup-ip">⊕ {location.ip}</div>
                                    <div className={`hm-popup-badge ${location.riskLevel || 'low'}`}>
                                        {(location.riskLevel || 'low').toUpperCase()} RISK
                                    </div>
                                    <div className="hm-popup-row">
                                        <strong>Location:</strong> {location.city}, {location.country}
                                    </div>
                                    <div className="hm-popup-row">
                                        <strong>ISP:</strong> {location.isp}
                                    </div>
                                    {location.org && (
                                        <div className="hm-popup-row">
                                            <strong>Org:</strong> {location.org}
                                        </div>
                                    )}
                                    <div className="hm-popup-row">
                                        <strong>Connections:</strong> {location.connectionCount}
                                    </div>
                                    <div className="hm-popup-coords">
                                        {location.lat?.toFixed(4)}, {location.lon?.toFixed(4)}
                                    </div>
                                </Popup>
                            </Marker>
                        ))}
                    </MapContainer>
                </div>

                {/* IP List */}
                <div className="hm-list-panel">
                    <div className="hm-list-header">⊞ Tracked IP Addresses</div>
                    {data?.slice(0, 10).map((location, index) => (
                        <div className="hm-list-item" key={index}>
                            <span className={`hm-list-dot ${location.riskLevel}`} />
                            <span className="hm-list-ip">{location.ip}</span>
                            <span className="hm-list-location">
                                {location.city}, {location.country_code}
                            </span>
                            <span className={`hm-list-badge ${location.riskLevel}`}>
                                {location.riskLevel}
                            </span>
                        </div>
                    ))}
                    {data?.length > 10 && (
                        <span className="hm-more-text">
                            + {data.length - 10} MORE TARGETS
                        </span>
                    )}
                </div>

            </div>
        </div>
    );
};

export default HackerMap;
