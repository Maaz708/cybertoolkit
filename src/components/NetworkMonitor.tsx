import React, { useEffect, useState, useRef } from 'react';
import {
  NetworkCheck, Shield, Warning, CheckCircle,
  Error as ErrorIcon, Refresh, Router, LanOutlined,
  TrendingUp, LockOpen, Lock, FiberManualRecord,
  BarChart, BugReport, Visibility, Block,
  PlayArrow, Stop, Public, Devices as DevicesIcon,
  Security as SecurityScanIcon, Memory as MemoryIcon,
  Timeline, Speed, Language
} from '@mui/icons-material';
import { Line } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';
import axios from 'axios';
import { DatePicker } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import dayjs, { Dayjs } from 'dayjs';
import HackerMap from './HackerMap';

Chart.register(...registerables);

const COLORS = ['#00d4ff', '#00ff88', '#ff4d6d', '#a78bfa', '#fbbf24', '#ff7849'];

const severityColor: Record<string, string> = {
  critical: '#ff4d6d', high: '#ff7849', medium: '#fbbf24', low: '#00ff88', info: '#00d4ff',
};
const severityBg: Record<string, string> = {
  critical: 'rgba(255,77,109,0.1)', high: 'rgba(255,120,73,0.1)', medium: 'rgba(251,191,36,0.1)', low: 'rgba(0,255,136,0.1)', info: 'rgba(0,212,255,0.1)',
};

const formatBytes = (b: number) => {
  if (!b) return '0 B';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
};

const verdictColor = (level: string) => {
  if (!level) return '#00d4ff';
  const l = level.toLowerCase();
  if (l.includes('attack') || l.includes('critical')) return '#ff4d6d';
  if (l.includes('suspicious')) return '#fbbf24';
  if (l.includes('caution')) return '#ff7849';
  return '#00ff88';
};

const ScoreRing = ({ score }: { score: number }) => {
  const r = 50, circ = 2 * Math.PI * r;
  const safe = Math.max(0, Math.min(100, score));
  const offset = circ - (safe / 100) * circ;
  const col = safe > 75 ? '#00ff88' : safe > 50 ? '#fbbf24' : '#ff4d6d';
  return (
    <div style={{ position: 'relative', width: 130, height: 130, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width="130" height="130" style={{ position: 'absolute', transform: 'rotate(-90deg)' }}>
        <circle cx="65" cy="65" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
        <circle cx="65" cy="65" r={r} fill="none" stroke={col} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${col})`, transition: 'stroke-dashoffset 1.2s ease' }} />
      </svg>
      <div style={{ textAlign: 'center', zIndex: 1 }}>
        <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 28, fontWeight: 900, color: col, lineHeight: 1 }}>{safe}</div>
        <div style={{ fontSize: 9, color: '#64748b', letterSpacing: 2, marginTop: 4 }}>SECURITY</div>
      </div>
    </div>
  );
};

const StatPill = ({ label, value, color = '#00d4ff', sub }: { label: string; value: string | number; color?: string; sub?: string }) => (
  <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 12, padding: '14px 18px', position: 'relative', overflow: 'hidden' }}>
    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
    <div style={{ fontSize: 10, color: '#475569', letterSpacing: 2, marginBottom: 6, fontWeight: 600 }}>{label.toUpperCase()}</div>
    <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 22, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
    {sub && <div style={{ fontSize: 11, color: '#475569', marginTop: 4 }}>{sub}</div>}
  </div>
);

const SectionCard = ({ icon: Icon, title, color = '#00d4ff', children, extra }: any) => (
  <div style={{ background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, overflow: 'hidden', boxShadow: '0 4px 24px rgba(0,0,0,0.3)' }}>
    <div style={{ position: 'relative', height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
    <div style={{ padding: '20px 22px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: `${color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon style={{ color, fontSize: 18 }} />
          </div>
          <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>{title}</span>
        </div>
        {extra}
      </div>
      {children}
    </div>
  </div>
);

interface NetworkStats {
  timestamp: string;
  interfaces: Array<{ name: string; type: string; operstate: string; ip4: string; ip6: string; mac: string }>;
  traffic: Array<{ interface: string; rx_bytes: number; tx_bytes: number; rx_sec: number; tx_sec: number; ms: number }>;
  connections: { total: number; protocols: Record<string, number>; details: Array<{ pid: number; process: string; localAddress: string; localPort: number; remoteAddress: string; remotePort: number; state: string; protocol: string; timestamp: string }> };
  hacker_map: Array<{ ip: string; country: string; city: string; lat: number; lon: number; isp: string; riskLevel: 'normal' | 'medium' | 'high'; connectionCount: number; country_code: string; region?: string; org?: string }>;
  open_ports_analysis: Array<{ port: number; service: string; process: string; state: string; risk: 'low' | 'medium' | 'high'; status: string }>;
  bandwidth: { inbound: number; outbound: number };
}

interface SecurityAnalysis {
  timestamp: string;
  active_connections: number;
  suspicious_connections: number;
  exposed_ports: PortDetail[];
  interfaces_up: number;
  total_interfaces: number;
}

interface PortDetail { port: number; service: string; process: string; state: string; risk: 'low' | 'medium' | 'high'; }

interface HistoricalBandwidthData {
  timestamp: string;
  networkStats: { bandwidth: { averageRxSpeed: number; averageTxSpeed: number } };
  alerts: Array<{ severity: 'high' | 'warning'; message: string; timestamp: string }>;
}

const NetworkMonitor = () => {
  const [networkStats, setNetworkStats] = useState<NetworkStats | null>(null);
  const [securityAnalysis, setSecurityAnalysis] = useState<SecurityAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [intervalId, setIntervalId] = useState<ReturnType<typeof setInterval> | null>(null);
  const [selectedDate, setSelectedDate] = useState<Dayjs>(dayjs());
  const [historicalData, setHistoricalData] = useState<HistoricalBandwidthData[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<any[]>([]);
  const [connectionsToShow, setConnectionsToShow] = useState(10);
  const [portsToShow, setPortsToShow] = useState(10);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [trafficChartData, setTrafficChartData] = useState<number[]>([]);
  const [connectionHistory, setConnectionHistory] = useState<number[]>([]);
  const [timeLabels, setTimeLabels] = useState<string[]>([]);

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8080");
    ws.onopen = () => console.log('Connected to Network Monitor WebSocket');
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === "NETWORK_UPDATE") {
          const data = message.payload;
          const apiData = data;
          setNetworkStats({
            timestamp: data.timestamp,
            interfaces: apiData.network_stats?.interfaces || [],
            traffic: [{ interface: "eth0", rx_bytes: apiData.network_stats?.totalBytesReceived || 0, tx_bytes: apiData.network_stats?.totalBytesSent || 0, rx_sec: (apiData.bandwidth?.inbound || 0) / 1024 / 1024, tx_sec: (apiData.bandwidth?.outbound || 0) / 1024 / 1024, ms: Date.now() }],
            connections: { total: apiData.connections || 0, protocols: apiData.protocols || { TCP: 0, UDP: 0, Other: 0 }, details: (apiData.connectionsList || []).map((conn: any) => ({ pid: conn.pid || 0, process: conn.process || "Unknown", localAddress: conn.local, localPort: parseInt(conn.local?.split(':')[1]) || 0, remoteAddress: conn.remote?.split(':')[0], remotePort: parseInt(conn.remote?.split(':')[1]) || 0, state: conn.status, protocol: conn.protocol, timestamp: Date.now() })) },
            hacker_map: apiData.hacker_map || [],
            open_ports_analysis: apiData.open_ports_analysis || [],
            bandwidth: apiData.bandwidth || { inbound: 0, outbound: 0 }
          });
          setTrafficHistory(prev => [...prev.slice(-20), { time: new Date().toLocaleTimeString(), inbound: (apiData.bandwidth?.inbound || 0) / 1024 / 1024, outbound: (apiData.bandwidth?.outbound || 0) / 1024 / 1024 }]);
          const now = new Date();
          const label = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
          const totalBytes = (apiData.network_stats?.totalBytesReceived || 0) + (apiData.network_stats?.totalBytesSent || 0);
          const connCount = apiData.connections || 0;
          setTrafficChartData(prev => [...prev.slice(-19), totalBytes]);
          setConnectionHistory(prev => [...prev.slice(-19), connCount]);
          setTimeLabels(prev => [...prev.slice(-19), label]);
          setLastUpdated(now);
        }
      } catch (err) { console.error('WebSocket message error:', err); }
    };
    ws.onclose = () => console.log('Disconnected from Network Monitor WebSocket');
    ws.onerror = (error) => console.error('WebSocket error:', error);
    return () => { ws.close(); };
  }, []);

  const startMonitoring = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await axios.post('/api/network/start', { interval: 5000 });
      setIsMonitoring(true);
      await fetchData();
      const interval = setInterval(fetchData, 5000);
      setIntervalId(interval);
    } catch (err) {
      console.error('Failed to start monitoring:', err);
      setError('Failed to start network monitoring');
      setIsMonitoring(false);
    } finally { setIsLoading(false); }
  };

  const stopMonitoring = async () => {
    if (intervalId) { clearInterval(intervalId); setIntervalId(null); }
    try { await axios.post('/api/network/stop'); } catch (err) { console.error('Failed to stop monitoring:', err); }
    setIsMonitoring(false);
    setNetworkStats(null);
    setSecurityAnalysis(null);
  };

  const fetchData = async () => {
    try {
      const [statusResponse, securityResponse] = await Promise.all([axios.get('/api/network/status'), axios.get('/api/network/security')]);
      if (statusResponse.data?.data && securityResponse.data?.data) {
        const apiData = statusResponse.data.data;
        setNetworkStats({
          timestamp: apiData.timestamp,
          interfaces: apiData.network_stats?.interfaces || [],
          traffic: [{ interface: "eth0", rx_bytes: apiData.network_stats?.totalBytesReceived || 0, tx_bytes: apiData.network_stats?.totalBytesSent || 0, rx_sec: (apiData.bandwidth?.inbound || 0) / 1024 / 1024, tx_sec: (apiData.bandwidth?.outbound || 0) / 1024 / 1024, ms: Date.now() }],
          connections: { total: apiData.connections || 0, protocols: apiData.protocols || { TCP: 0, UDP: 0, Other: 0 }, details: (apiData.connectionsList || []).map((conn: any) => ({ pid: conn.pid || 0, process: conn.process || "Unknown", localAddress: conn.local, localPort: parseInt(conn.local?.split(':')[1]) || 0, remoteAddress: conn.remote?.split(':')[0], remotePort: parseInt(conn.remote?.split(':')[1]) || 0, state: conn.status, protocol: conn.protocol, timestamp: Date.now() })) },
          hacker_map: apiData.hacker_map || [],
          open_ports_analysis: apiData.open_ports_analysis || [],
          bandwidth: apiData.bandwidth || { inbound: 0, outbound: 0 }
        });
        setSecurityAnalysis(securityResponse.data.data);
        setLastUpdated(new Date());
      } else { throw new Error('Invalid data'); }
    } catch (err) {
      console.error('Error fetching network data:', err);
      setError('Failed to fetch network data');
      stopMonitoring();
    }
  };

  useEffect(() => { return () => { if (intervalId) clearInterval(intervalId); }; }, [intervalId]);

  const trafficChartConfig = {
    labels: timeLabels,
    datasets: [{ label: 'Bytes/s', data: trafficChartData, borderColor: '#00ff88', backgroundColor: 'rgba(0,255,136,0.07)', tension: 0.4, fill: true, pointRadius: 2, pointBackgroundColor: '#00ff88' }],
  };

  const connChartData = {
    labels: timeLabels,
    datasets: [{ label: 'Connections', data: connectionHistory, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.07)', tension: 0.4, fill: true, pointRadius: 2, pointBackgroundColor: '#00d4ff' }],
  };

  const chartOpts: any = {
    responsive: true, maintainAspectRatio: false, animation: { duration: 400 },
    plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1a1f2e', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1 } },
    scales: { x: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#334155', maxTicksLimit: 5, font: { size: 10 } } }, y: { grid: { color: 'rgba(255,255,255,0.03)' }, ticks: { color: '#334155', font: { size: 10 } } } },
  };

  const score = networkStats ? Math.max(0, Math.min(100, 100 - (networkStats.open_ports_analysis?.filter(p => p.risk === 'high').length || 0) * 5)) : 85;
  const connections = networkStats?.connections?.details || [];
  const ports = networkStats?.open_ports_analysis || [];
  const interfaces = networkStats?.interfaces || [];

  const renderConnectionDetails = () => {
    if (!networkStats?.connections) return null;
    const displayedConnections = connections.slice(0, connectionsToShow);
    const hasMore = connections.length > connectionsToShow;
    return (
      <div style={{ marginBottom: 24, animation: 'fadeInUp 0.65s ease' }}>
        <SectionCard icon={LanOutlined} title={`Active Connections (${connections.length} total)`} color="#00d4ff"
          extra={hasMore && (
            <button onClick={() => setConnectionsToShow(prev => prev + 10)} style={{ padding: '6px 14px', borderRadius: 8, background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.25)', color: '#00d4ff', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>Load More</button>
          )}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr>
                  {['Process', 'Local Address', 'Remote Address', 'State', 'Protocol'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '8px 10px', fontSize: 10, color: '#334155', letterSpacing: 1.5, fontWeight: 600, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>{h.toUpperCase()}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayedConnections.length > 0 ? displayedConnections.map((c: any, i: number) => (
                  <tr key={i} className="conn-row" style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                    <td style={{ padding: '9px 10px', color: '#94a3b8' }}>{c.process || '—'}</td>
                    <td style={{ padding: '9px 10px', color: '#64748b', fontFamily: 'monospace', fontSize: 11 }}>{c.localAddress}:{c.localPort}</td>
                    <td style={{ padding: '9px 10px', color: '#64748b', fontFamily: 'monospace', fontSize: 11 }}>{c.remoteAddress}:{c.remotePort}</td>
                    <td style={{ padding: '9px 10px' }}>
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, background: 'rgba(0,255,136,0.08)', color: '#00ff88', border: '1px solid rgba(0,255,136,0.2)', fontWeight: 700 }}>{c.state}</span>
                    </td>
                    <td style={{ padding: '9px 10px', color: '#475569', fontWeight: 600 }}>{c.protocol}</td>
                  </tr>
                )) : (<tr><td colSpan={5} style={{ padding: '32px', textAlign: 'center', color: '#334155', fontSize: 12 }}>No connection data</td></tr>)}
              </tbody>
            </table>
          </div>
        </SectionCard>
      </div>
    );
  };

  const renderExposedPorts = () => {
    if (!networkStats?.open_ports_analysis?.length) return null;
    const displayedPorts = ports.slice(0, portsToShow);
    const hasMore = ports.length > portsToShow;
    return (
      <div style={{ marginBottom: 24, animation: 'fadeInUp 0.7s ease' }}>
        <SectionCard icon={SecurityScanIcon} title={`Exposed Ports (${ports.length} total)`} color="#ff4d6d"
          extra={hasMore && (
            <button onClick={() => setPortsToShow(prev => prev + 10)} style={{ padding: '6px 14px', borderRadius: 8, background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.25)', color: '#ff4d6d', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>Load More</button>
          )}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 20 }}>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr>
                    {['Port', 'Service', 'Process', 'Risk', 'Status'].map(h => (
                      <th key={h} style={{ textAlign: 'left', padding: '8px 10px', fontSize: 10, color: '#334155', letterSpacing: 1.5, fontWeight: 600, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>{h.toUpperCase()}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayedPorts.map((port: any, i: number) => (
                    port?.port ? (
                      <tr key={port.port} className="conn-row" style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '9px 10px', color: '#94a3b8', fontFamily: 'monospace' }}>{port.port}</td>
                        <td style={{ padding: '9px 10px', color: '#64748b' }}>{port.service}</td>
                        <td style={{ padding: '9px 10px', color: '#64748b' }}>{port.process}</td>
                        <td style={{ padding: '9px 10px' }}>
                          <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, background: severityBg[port.risk] || 'rgba(0,255,136,0.08)', color: severityColor[port.risk] || '#00ff88', border: `1px solid ${severityColor[port.risk] || '#00ff88'}30`, fontWeight: 700 }}>{port.risk.toUpperCase()}</span>
                        </td>
                        <td style={{ padding: '9px 10px' }}>
                          <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, background: 'rgba(0,212,255,0.08)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.2)', fontWeight: 700 }}>{port.status.toUpperCase()}</span>
                        </td>
                      </tr>
                    ) : null
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{ padding: '16px', borderRadius: 12, background: 'rgba(15,21,33,0.8)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0', marginBottom: 12 }}>Port Security Summary</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[{ label: 'High Risk', count: ports.filter(p => p?.risk === 'high').length, color: '#ff4d6d', icon: ErrorIcon }, { label: 'Medium Risk', count: ports.filter(p => p?.risk === 'medium').length, color: '#fbbf24', icon: Warning }, { label: 'Low Risk', count: ports.filter(p => p?.risk === 'low').length, color: '#00ff88', icon: CheckCircle }].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', borderRadius: 10, background: `${item.color}0d`, border: `1px solid ${item.color}20` }}>
                    <item.icon style={{ color: item.color, fontSize: 18 }} />
                    <div style={{ flex: 1 }}><div style={{ fontSize: 11, color: '#cbd5e1' }}>{item.label}</div></div>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 18, fontWeight: 700, color: item.color }}>{item.count}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </SectionCard>
      </div>
    );
  };

  const renderTopIPs = () => {
    const topIPs = connections.reduce((acc: Record<string, number>, conn: any) => {
      const ip = conn.remoteAddress;
      if (ip && !['127.0.0.1', '::1', '0.0.0.0'].includes(ip)) acc[ip] = (acc[ip] || 0) + 1;
      return acc;
    }, {});
    const sortedIPs = Object.entries(topIPs).sort(([, a], [, b]) => (b as number) - (a as number)).slice(0, 5).map(([ip, count]) => ({ ip, count }));
    if (!sortedIPs.length) return null;
    return (
      <SectionCard icon={Public} title="Top Connected IPs" color="#a78bfa">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {sortedIPs.map((item: any, index: number) => (
            <div key={item.ip} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderRadius: 10, background: 'rgba(167,139,250,0.05)', border: '1px solid rgba(167,139,250,0.12)' }}>
              <span style={{ fontFamily: 'monospace', fontSize: 13, color: '#cbd5e1', fontWeight: 600 }}>{item.ip}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, color: '#64748b' }}>{item.count} conn</span>
                <div style={{ width: 34, height: 34, borderRadius: 8, background: 'rgba(167,139,250,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontFamily: "'Orbitron', monospace", fontSize: 14, fontWeight: 700, color: '#a78bfa' }}>{item.count}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>
    );
  };

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', fontFamily: "'Syne','Segoe UI',sans-serif", color: '#e2e8f0', padding: '32px clamp(16px,4vw,40px)' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Syne:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; }
        @keyframes fadeInUp { from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)} }
        @keyframes pulse { 0%,100%{opacity:1}50%{opacity:0.4} }
        @keyframes spin { to{transform:rotate(360deg)} }
        .conn-row:hover { background: rgba(255,255,255,0.03) !important; }
        .conn-row { transition: background 0.15s; }
      `}</style>

      <div style={{ maxWidth: 1300, margin: '0 auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 32, flexWrap: 'wrap', gap: 16, animation: 'fadeInUp 0.4s ease' }}>
          <div>
            <div style={{ fontSize: 10, color: '#00ff88', letterSpacing: 4, fontWeight: 600, marginBottom: 6 }}>LIVE MONITORING</div>
            <h1 style={{ fontFamily: "'Orbitron', monospace", fontSize: 'clamp(20px,3.5vw,30px)', fontWeight: 900, color: '#f1f5f9', lineHeight: 1.1, margin: 0 }}>
              Network <span style={{ color: '#00ff88' }}>Monitor</span>
            </h1>
            {lastUpdated && <div style={{ fontSize: 11, color: '#334155', marginTop: 6 }}>Last updated: {lastUpdated.toLocaleTimeString()}</div>}
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            {isLoading && <div style={{ width: 18, height: 18, borderRadius: '50%', border: '2px solid rgba(0,212,255,0.2)', borderTopColor: '#00d4ff', animation: 'spin 1s linear infinite', alignSelf: 'center' }} />}
            {!isMonitoring ? (
              <button onClick={startMonitoring} disabled={isLoading} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 24px', borderRadius: 10, background: 'linear-gradient(135deg, #0066ff, #00d4ff)', border: 'none', color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer', letterSpacing: 1 }}>
                <PlayArrow style={{ fontSize: 16 }} /> START MONITORING
              </button>
            ) : (
              <button onClick={stopMonitoring} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '10px 24px', borderRadius: 10, background: 'rgba(255,77,109,0.15)', border: '1px solid rgba(255,77,109,0.4)', color: '#ff4d6d', fontSize: 13, fontWeight: 700, cursor: 'pointer', letterSpacing: 1 }}>
                <Stop style={{ fontSize: 16 }} /> STOP MONITORING
              </button>
            )}
            
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '9px 16px', borderRadius: 10, background: 'rgba(0,255,136,0.07)', border: '1px solid rgba(0,255,136,0.2)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: isMonitoring ? '#00ff88' : '#334155', display: 'block', animation: isMonitoring ? 'pulse 2s infinite' : 'none' }} />
              <span style={{ fontSize: 11, color: isMonitoring ? '#00ff88' : '#475569', fontWeight: 700 }}>{isMonitoring ? 'LIVE' : 'OFFLINE'}</span>
            </div>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div style={{ marginBottom: 24, padding: '14px 18px', borderRadius: 12, background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.3)', display: 'flex', alignItems: 'center', gap: 10, animation: 'fadeInUp 0.3s ease' }}>
            <ErrorIcon style={{ color: '#ff4d6d', fontSize: 18 }} />
            <span style={{ fontSize: 13, color: '#ff4d6d' }}>{error}</span>
          </div>
        )}

        {/* Inactive State */}
        {!isMonitoring && !isLoading && (
          <div style={{ marginBottom: 24, padding: '40px 24px', borderRadius: 16, background: 'rgba(15,21,33,0.8)', border: '1px dashed rgba(255,255,255,0.1)', textAlign: 'center', animation: 'fadeInUp 0.5s ease' }}>
            <div style={{ width: 60, height: 60, borderRadius: 16, background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px' }}>
              <NetworkCheck style={{ color: '#00d4ff', fontSize: 28 }} />
            </div>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#e2e8f0', marginBottom: 8 }}>Monitoring Inactive</div>
            <div style={{ fontSize: 13, color: '#475569', maxWidth: 400, margin: '0 auto' }}>Click "Start Monitoring" to begin real-time network surveillance and threat detection.</div>
          </div>
        )}

        {/* Dashboard Content */}
        {isMonitoring && networkStats && (
          <>
            {/* Top Stats */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(160px,1fr))', gap: 14, marginBottom: 24, animation: 'fadeInUp 0.5s ease' }}>
              <StatPill label="Total Connections" value={networkStats?.connections?.total || 0} color="#00d4ff" />
              <StatPill label="Open Ports" value={networkStats?.open_ports_analysis?.length || 0} color="#ff4d6d" />
              <StatPill label="Unique IPs" value={networkStats?.hacker_map?.length || 0} color="#a78bfa" />
              <StatPill label="Data Sent" value={formatBytes(networkStats?.bandwidth?.outbound || 0)} color="#00ff88" />
              <StatPill label="Data Received" value={formatBytes(networkStats?.bandwidth?.inbound || 0)} color="#00d4ff" />
              <StatPill label="Bandwidth" value={`${((networkStats?.bandwidth?.inbound || 0) + (networkStats?.bandwidth?.outbound || 0)).toFixed(1)} MB/s`} color="#fbbf24" />
            </div>

            {/* Security Score Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(280px,1fr))', gap: 20, marginBottom: 24 }}>
              <div style={{ background: 'linear-gradient(135deg, #0f1521, #131a2a)', border: '1px solid rgba(255,255,255,0.06)', borderRadius: 16, padding: '24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, animation: 'fadeInUp 0.55s ease' }}>
                <div style={{ fontSize: 10, color: '#475569', letterSpacing: 3, alignSelf: 'flex-start' }}>SECURITY SCORE</div>
                <ScoreRing score={score} />
                <div style={{ display: 'flex', gap: 12, width: '100%' }}>
                  {[{ label: 'Critical', val: ports.filter(p => p.risk === 'high').length, color: '#ff4d6d' }, { label: 'Medium', val: ports.filter(p => p.risk === 'medium').length, color: '#fbbf24' }, { label: 'Low', val: ports.filter(p => p.risk === 'low').length, color: '#00ff88' }].map(t => (
                    <div key={t.label} style={{ flex: 1, textAlign: 'center', padding: '8px', borderRadius: 10, background: `${t.color}10`, border: `1px solid ${t.color}20` }}>
                      <div style={{ fontFamily: "'Orbitron',monospace", fontSize: 18, fontWeight: 700, color: t.color }}>{t.val}</div>
                      <div style={{ fontSize: 10, color: '#475569', marginTop: 2 }}>{t.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              <SectionCard icon={BarChart} title="Protocol Distribution" color="#a78bfa">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {Object.entries(networkStats?.connections?.protocols || {}).map(([protocol, count], index) => (
                    <div key={protocol} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ width: 12, height: 12, borderRadius: 3, background: COLORS[index % 5] }} />
                      <div style={{ flex: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: 12, color: '#cbd5e1' }}>{protocol}</span>
                        <span style={{ fontSize: 12, color: '#64748b', fontFamily: 'monospace' }}>{count} conn</span>
                      </div>
                      <div style={{ width: 80, height: 4, borderRadius: 4, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${Math.min(100, (count / (networkStats?.connections?.total || 1)) * 100)}%`, background: COLORS[index % 5], borderRadius: 4 }} />
                      </div>
                    </div>
                  ))}
                </div>
              </SectionCard>

              <SectionCard icon={Router} title="Network Interfaces" color="#00d4ff">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {interfaces.length > 0 ? interfaces.slice(0, 5).map((iface, i) => (
                    <div key={i} style={{ padding: '10px 12px', borderRadius: 10, background: 'rgba(0,212,255,0.05)', border: '1px solid rgba(0,212,255,0.12)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#cbd5e1', fontWeight: 600 }}>{iface.ip4 || iface.ip6 || 'N/A'}</span>
                        <span style={{ fontSize: 9, padding: '1px 7px', borderRadius: 20, background: 'rgba(0,212,255,0.12)', color: '#00d4ff', fontWeight: 700 }}>{iface.ip4 ? 'IPv4' : 'IPv6'}</span>
                      </div>
                      <div style={{ fontSize: 10, color: '#334155', fontFamily: 'monospace' }}>MAC: {iface.mac || 'N/A'}</div>
                    </div>
                  )) : <div style={{ fontSize: 12, color: '#334155', padding: '16px', textAlign: 'center' }}>No interfaces found</div>}
                </div>
              </SectionCard>
            </div>

            {/* Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(300px,1fr))', gap: 20, marginBottom: 24, animation: 'fadeInUp 0.6s ease' }}>
              <SectionCard icon={TrendingUp} title="Bandwidth Over Time" color="#00ff88">
                <div style={{ height: 160 }}>
                  {trafficChartData.length > 1 ? <Line data={trafficChartConfig} options={chartOpts} /> : <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#334155', fontSize: 12 }}>Collecting data...</div>}
                </div>
              </SectionCard>
              <SectionCard icon={NetworkCheck} title="Connection Count" color="#00d4ff">
                <div style={{ height: 160 }}>
                  {connectionHistory.length > 1 ? <Line data={connChartData} options={chartOpts} /> : <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#334155', fontSize: 12 }}>Collecting data...</div>}
                </div>
              </SectionCard>
            </div>

            {/* Hacker Map */}
            {networkStats?.hacker_map?.length > 0 && (
              <div style={{ marginBottom: 24, animation: 'fadeInUp 0.65s ease' }}>
                <SectionCard icon={Language} title="Global Connection Map" color="#00ff88">
                  <div style={{ height: 400 }}><HackerMap data={networkStats.hacker_map} /></div>
                </SectionCard>
              </div>
            )}

            {renderConnectionDetails()}
            {renderExposedPorts()}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(280px,1fr))', gap: 20, marginBottom: 24, animation: 'fadeInUp 0.7s ease' }}>
              {renderTopIPs()}
            </div>
          </>
        )}

        {/* Footer */}
        <div style={{ marginTop: 32, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 0', borderTop: '1px solid rgba(255,255,255,0.04)', flexWrap: 'wrap', gap: 8 }}>
          <div style={{ fontSize: 10, color: '#1e293b', letterSpacing: 2 }}>NETWORK MONITOR · FORENSICOS v2.4</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: isMonitoring ? '#00ff88' : '#334155', display: 'block', animation: isMonitoring ? 'pulse 2s infinite' : 'none' }} />
            <span style={{ fontSize: 10, color: '#334155' }}>{isMonitoring ? 'Auto-refresh every 5s' : 'Monitoring inactive'}</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkMonitor;
