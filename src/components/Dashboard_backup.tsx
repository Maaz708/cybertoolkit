import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Security, Storage, NetworkCheck, Email, Cloud, Shield, BugReport, Fingerprint,
  Assessment, Warning, CheckCircle, ErrorOutline, TrendingUp, Menu,
  Dashboard as DashboardIcon, Analytics, Settings
} from '@mui/icons-material';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

const modules = [
  {
    title: 'File Analysis',
    icon: Storage,
    color: '#00d4ff',
    glow: '0 0 20px rgba(0,212,255,0.4)',
    stats: { label: 'Files Scanned', value: '12,847', change: '+3.2%' },
    description: 'Extract metadata, detect suspicious files, trace origins and identify anomalous file properties.',
    status: 'active',
  },
  {
    title: 'Network Monitor',
    icon: NetworkCheck,
    color: '#00ff88',
    glow: '0 0 20px rgba(0,255,136,0.4)',
    stats: { label: 'Connections Live', value: '188', change: '+12' },
    description: 'Real-time traffic analysis with packet-level inspection and protocol anomaly detection.',
    status: 'active',
  },
  {
    title: 'Malware Detection',
    icon: BugReport,
    color: '#ff4d6d',
    glow: '0 0 20px rgba(255,77,109,0.4)',
    stats: { label: 'Threats Blocked', value: '47', change: '-2 today' },
    description: 'ML-powered detection engine scanning for known and zero-day malware signatures.',
    status: 'alert',
  },
  {
    title: 'Email Forensics',
    icon: Email,
    color: '#a78bfa',
    glow: '0 0 20px rgba(167,139,250,0.4)',
    stats: { label: 'Headers Analyzed', value: '2,391', change: '+8.1%' },
    description: 'Deep header parsing, phishing detection, and communication pattern forensics.',
    status: 'active',
  },
];

const securityScore = 82;

const lineData = {
  labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul'],
  datasets: [
    {
      label: 'Email Forensics',
      data: [65, 59, 80, 81, 56, 55, 40],
      borderColor: '#a78bfa',
      backgroundColor: 'rgba(167,139,250,0.08)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointBackgroundColor: '#a78bfa',
    },
    {
      label: 'File Analysis',
      data: [28, 48, 40, 19, 86, 27, 90],
      borderColor: '#00d4ff',
      backgroundColor: 'rgba(0,212,255,0.08)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointBackgroundColor: '#00d4ff',
    },
    {
      label: 'Malware Detection',
      data: [12, 33, 45, 67, 23, 45, 78],
      borderColor: '#ff4d6d',
      backgroundColor: 'rgba(255,77,109,0.08)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointBackgroundColor: '#ff4d6d',
    },
    {
      label: 'Network Monitor',
      data: [45, 67, 23, 45, 78, 90, 100],
      borderColor: '#00ff88',
      backgroundColor: 'rgba(0,255,136,0.08)',
      tension: 0.4,
      fill: true,
      pointRadius: 4,
      pointBackgroundColor: '#00ff88',
    },
  ],
};

const donutData = {
  labels: ['Safe', 'Warnings', 'Critical'],
  datasets: [{
    data: [68, 22, 10],
    backgroundColor: ['#00ff88', '#fbbf24', '#ff4d6d'],
    borderColor: 'transparent',
    hoverOffset: 8,
  }],
};

const barData = {
  labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
  datasets: [{
    label: 'Threats',
    data: [4, 7, 3, 9, 5, 2, 6],
    backgroundColor: (ctx: { raw: number }) => {
      const v = ctx.raw;
      if (v >= 8) return '#ff4d6d';
      if (v >= 5) return '#fbbf24';
      return '#00d4ff';
    },
    borderRadius: 6,
    borderSkipped: false,
  }],
};

const chartOpts = {
  responsive: true,
  plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1a1f2e', titleColor: '#e2e8f0', bodyColor: '#94a3b8', borderColor: '#334155', borderWidth: 1 } },
  scales: {
    x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } },
    y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } },
  },
};

const donutOpts = {
  responsive: true,
  cutout: '72%' as const,
  plugins: {
    legend: { position: 'bottom' as const, labels: { color: '#94a3b8', padding: 16, font: { size: 12 } } },
    tooltip: { backgroundColor: '#1a1f2e', titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
  },
};

const alerts = [
  { id: 1, severity: 'critical', msg: 'Suspicious outbound connection to 185.234.x.x', time: '2m ago' },
  { id: 2, severity: 'warning', msg: 'Unusual process accessing /etc/passwd', time: '8m ago' },
  { id: 3, severity: 'info', msg: 'Port scan detected from 192.168.1.44', time: '15m ago' },
  { id: 4, severity: 'warning', msg: 'Email header mismatch detected in batch #4412', time: '31m ago' },
];

const severityConfig: Record<string, { color: string; bg: string; icon: typeof ErrorOutline }> = {
  critical: { color: '#ff4d6d', bg: 'rgba(255,77,109,0.1)', icon: ErrorOutline },
  warning: { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)', icon: Warning },
  info: { color: '#00d4ff', bg: 'rgba(0,212,255,0.1)', icon: CheckCircle },
};

function ScoreRing({ score }: { score: number }) {
  const r = 54, circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score > 75 ? '#00ff88' : score > 50 ? '#fbbf24' : '#ff4d6d';
  return (
    <div style={{ position: 'relative', width: 140, height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width="140" height="140" style={{ position: 'absolute', transform: 'rotate(-90deg)' }}>
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10" />
        <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dashoffset 1.5s ease' }} />
      </svg>
      <div style={{ textAlign: 'center', zIndex: 1 }}>
        <div style={{ fontSize: 32, fontWeight: 800, color, fontFamily: "'Orbitron', monospace", lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: 11, color: '#64748b', letterSpacing: 2, marginTop: 4 }}>SCORE</div>
      </div>
    </div>
  );
}

function AnimatedCounter({ target, duration = 1500 }: { target: number; duration?: number }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0, step = target / (duration / 16);
    const t = setInterval(() => {
      start = Math.min(start + step, target);
      setVal(Math.floor(start));
      if (start >= target) clearInterval(t);
    }, 16);
    return () => clearInterval(t);
  }, [target, duration]);
  return <span>{val.toLocaleString()}</span>;
}

export default function Dashboard() {
  const [activeModule, setActiveModule] = useState<number | null>(null);
  const [tick, setTick] = useState(0);

  // Real data states
  const [networkStats, setNetworkStats] = useState({
    connections: 0,
    bandwidth: 0,
    isMonitoring: false,
  });
  const [securityScore, setSecurityScore] = useState(85);
  const [realAlerts, setRealAlerts] = useState<Array<{id: number; severity: string; msg: string; time: string}>>([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    activeThreats: 0,
    filesAnalyzed: 0,
    networkEvents: 0,
  });
  const [trafficHistory, setTrafficHistory] = useState<Array<{time: string; inbound: number; outbound: number}>>([]);
  const [protocols, setProtocols] = useState({ TCP: 0, UDP: 0, Other: 0 });
  const [threatData, setThreatData] = useState([68, 22, 10]);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch real data
  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);

        // Fetch network status
        const networkRes = await axios.get('/api/network/status').catch(() => null);
        if (networkRes?.data?.data) {
          const data = networkRes.data.data;
          setNetworkStats({
            connections: data.connections?.length || 0,
            bandwidth: (data.bandwidth?.inbound || 0) + (data.bandwidth?.outbound || 0),
            isMonitoring: data.isMonitoring || false,
          });
          setProtocols(data.protocols || { TCP: 0, UDP: 0, Other: 0 });
          setStats(prev => ({ ...prev, networkEvents: data.connections?.length || 0 }));

          // Add to traffic history
          setTrafficHistory(prev => {
            const newPoint = {
              time: new Date().toLocaleTimeString(),
              inbound: (data.bandwidth?.inbound || 0) / 1024 / 1024,
              outbound: (data.bandwidth?.outbound || 0) / 1024 / 1024,
            };
            return [...prev, newPoint].slice(-20);
          });
        }

        // Fetch security analysis
        const securityRes = await axios.get('/api/network/security').catch(() => null);
        if (securityRes?.data?.data) {
          const data = securityRes.data.data;
          setSecurityScore(data.securityScore || 85);
          setStats(prev => ({
            ...prev,
            activeThreats: data.suspicious_connections || 0,
          }));

          // Generate alerts from security data
          const newAlerts = [];
          if (data.suspicious_connections > 0) {
            newAlerts.push({
              id: 1,
              severity: 'warning',
              msg: `${data.suspicious_connections} suspicious connections detected`,
              time: 'Just now',
            });
          }
          if (data.exposed_ports?.length > 0) {
            newAlerts.push({
              id: 2,
              severity: 'info',
              msg: `${data.exposed_ports.length} exposed ports found`,
              time: 'Just now',
            });
          }
          setRealAlerts(newAlerts);
        }

        // Fetch file analysis history
        const fileRes = await axios.get('/api/files/history').catch(() => null);
        if (fileRes?.data?.history) {
          const fileCount = fileRes.data.history.length;
          setStats(prev => ({
            ...prev,
            filesAnalyzed: fileCount,
            totalScans: fileCount,
          }));
        }

        // Calculate threat distribution
        setThreatData([
          Math.max(10, 100 - stats.activeThreats * 2),
          Math.min(40, stats.activeThreats * 3),
          Math.min(30, stats.activeThreats),
        ]);

      } catch (err) {
        console.error('Error fetching dashboard data:', err);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    const tickInterval = setInterval(() => setTick(p => p + 1), 3000);

    return () => {
      clearInterval(interval);
      clearInterval(tickInterval);
    };
  }, [stats.activeThreats]);

  // Update modules with real data
  const dynamicModules = [
    {
      title: 'File Analysis',
      icon: Storage,
      color: '#00d4ff',
      glow: '0 0 20px rgba(0,212,255,0.4)',
      stats: { label: 'Files Scanned', value: stats.filesAnalyzed.toString(), change: '+3.2%' },
      description: 'Extract metadata, detect suspicious files, trace origins and identify anomalous file properties.',
      status: 'active',
    },
    {
      title: 'Network Monitor',
      icon: NetworkCheck,
      color: '#00ff88',
      glow: '0 0 20px rgba(0,255,136,0.4)',
      stats: { label: 'Connections Live', value: networkStats.connections.toString(), change: networkStats.isMonitoring ? 'Active' : 'Stopped' },
      description: 'Real-time traffic analysis with packet-level inspection and protocol anomaly detection.',
      status: networkStats.isMonitoring ? 'active' : 'inactive',
    },
    {
      title: 'Malware Detection',
      icon: BugReport,
      color: '#ff4d6d',
      glow: '0 0 20px rgba(255,77,109,0.4)',
      stats: { label: 'Threats Blocked', value: stats.activeThreats.toString(), change: stats.activeThreats > 0 ? 'Alert' : 'Clear' },
      description: 'ML-powered detection engine scanning for known and zero-day malware signatures.',
      status: stats.activeThreats > 0 ? 'alert' : 'active',
    },
    {
      title: 'Email Forensics',
      icon: Email,
      color: '#a78bfa',
      glow: '0 0 20px rgba(167,139,250,0.4)',
      stats: { label: 'Headers Analyzed', value: '2,391', change: '+8.1%' },
      description: 'Deep header parsing, phishing detection, and communication pattern forensics.',
      status: 'active',
    },
  ];

  // Dynamic chart data
  const dynamicLineData = {
    labels: trafficHistory.length > 0 ? trafficHistory.map(t => t.time) : ['No Data'],
    datasets: trafficHistory.length > 0 ? [
      {
        label: 'Inbound',
        data: trafficHistory.map(t => t.inbound),
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.08)',
        tension: 0.4,
        fill: true,
        pointRadius: 3,
        pointBackgroundColor: '#00d4ff',
      },
      {
        label: 'Outbound',
        data: trafficHistory.map(t => t.outbound),
        borderColor: '#00ff88',
        backgroundColor: 'rgba(0,255,136,0.08)',
        tension: 0.4,
        fill: true,
        pointRadius: 3,
        pointBackgroundColor: '#00ff88',
      },
    ] : [],
  };

  const dynamicBarData = {
    labels: ['TCP', 'UDP', 'Other'],
    datasets: [{
      label: 'Connections',
      data: [protocols.TCP, protocols.UDP, protocols.Other],
      backgroundColor: ['#00d4ff', '#00ff88', '#a78bfa'],
      borderRadius: 6,
      borderSkipped: false,
    }],
  };

  // Use real alerts if available, otherwise fallback to static
  const displayAlerts = realAlerts.length > 0 ? realAlerts : alerts;

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a', fontFamily: "'Syne', 'Segoe UI', sans-serif", color: '#e2e8f0' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Syne:wght@400;600;700;800&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #0a0e1a; } ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        .module-card { transition: transform 0.3s cubic-bezier(.34,1.56,.64,1), box-shadow 0.3s; cursor: pointer; }
        .module-card:hover { transform: translateY(-6px) scale(1.02); }
        .alert-row { transition: background 0.2s; }
        .alert-row:hover { background: rgba(255,255,255,0.03) !important; }
        .nav-item { transition: color 0.2s, background 0.2s; cursor: pointer; }
        .nav-item:hover { color: #00d4ff !important; background: rgba(0,212,255,0.07) !important; }
        .stat-card { transition: box-shadow 0.3s, transform 0.3s; }
        .stat-card:hover { transform: translateY(-3px); box-shadow: 0 12px 40px rgba(0,0,0,0.4) !important; }
        @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.4 } }
        @keyframes scanline { 0% { top: 0 } 100% { top: 100% } }
        @keyframes fadeInUp { from { opacity:0; transform:translateY(24px) } to { opacity:1; transform:translateY(0) } }
        .fade-in { animation: fadeInUp 0.6s ease forwards; }
      `}</style>

      {/* Top Navbar */}
      <nav style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 32px', height: 64,
        background: 'rgba(10,14,26,0.95)',
        borderBottom: '1px solid rgba(0,212,255,0.12)',
        backdropFilter: 'blur(20px)',
        position: 'sticky', top: 0, zIndex: 100,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #00d4ff, #0066ff)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Fingerprint style={{ color: '#fff', fontSize: 20 }} />
          </div>
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: 14, color: '#e2e8f0', letterSpacing: 2 }}>DIGITAL FORENSICS<span style={{ color: '#00d4ff' }}>ToolKit</span></div>
            <div style={{ fontSize: 10, color: '#475569', letterSpacing: 3 }}>DIGITAL FORENSICS TOOLKIT v1.0</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {[].map(item => (
            <div key={item} className="nav-item" style={{ padding: '6px 16px', borderRadius: 8, fontSize: 13, color: '#64748b', fontWeight: 600 }}>{item}</div>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(0,255,136,0.08)', border: '1px solid rgba(0,255,136,0.2)', borderRadius: 20, padding: '4px 12px' }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00ff88', display: 'block', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 12, color: '#00ff88', fontWeight: 600 }}>LIVE</span>
          </div>
          <div style={{ width: 34, height: 34, borderRadius: '50%', background: 'linear-gradient(135deg, #334155, #1e293b)', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '2px solid #334155', fontSize: 13, fontWeight: 700, color: '#94a3b8' }}>M</div>
        </div>
      </nav>

      <div style={{ padding: '32px', maxWidth: 1440, margin: '0 auto' }}>

        {/* Header */}
        <div className="fade-in" style={{ marginBottom: 32, animationDelay: '0s' }}>
          <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
            <div>
              <div style={{ fontSize: 11, color: '#475569', letterSpacing: 4, fontWeight: 600, marginBottom: 6 }}>SECURITY DASHBOARD</div>
              <h1 style={{ fontFamily: "'Orbitron', monospace", fontSize: 'clamp(22px, 4vw, 36px)', fontWeight: 900, color: '#f1f5f9', lineHeight: 1.1 }}>
                Digital Forensics<br /><span style={{ color: '#00d4ff' }}>Toolkit</span>
              </h1>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
               </div>
          </div>
        </div>

        {/* Top Stats */}
        <div className="fade-in" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 28, animationDelay: '0.1s' }}>
          {[
            { label: 'Total Scans', value: stats.totalScans, icon: Assessment, color: '#00d4ff', change: '+5.4%' },
            { label: 'Active Threats', value: stats.activeThreats, icon: BugReport, color: '#ff4d6d', change: stats.activeThreats > 0 ? 'Alert' : 'Clear' },
            { label: 'Files Analyzed', value: stats.filesAnalyzed, icon: Storage, color: '#a78bfa', change: '+3.2%' },
            { label: 'Network Events', value: networkStats.connections, icon: NetworkCheck, color: '#00ff88', change: networkStats.isMonitoring ? 'Active' : 'Stopped' },
          ].map((s, i) => (
            <div key={i} className="stat-card" style={{
              background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
              border: `1px solid rgba(255,255,255,0.06)`,
              borderRadius: 16, padding: '20px 22px',
              boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
              position: 'relative', overflow: 'hidden',
            }}>
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${s.color}, transparent)` }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 2, marginBottom: 8, fontWeight: 600 }}>{s.label.toUpperCase()}</div>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 28, fontWeight: 700, color: '#f1f5f9', lineHeight: 1 }}>
                    <AnimatedCounter target={s.value} />
                  </div>
                  <div style={{ fontSize: 12, color: s.color, marginTop: 6, fontWeight: 600 }}>{s.change}</div>
                </div>
                <div style={{ width: 44, height: 44, borderRadius: 12, background: `rgba(${s.color === '#00d4ff' ? '0,212,255' : s.color === '#ff4d6d' ? '255,77,109' : s.color === '#a78bfa' ? '167,139,250' : '0,255,136'},0.1)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <s.icon style={{ color: s.color, fontSize: 22 }} />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Main Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 20, marginBottom: 28 }}>

          {/* Module Cards */}
          <div style={{ gridColumn: 'span 8', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
            {dynamicModules.map((mod, i) => (
              <div key={i} className="module-card fade-in" onClick={() => setActiveModule(activeModule === i ? null : i)}
                style={{
                  background: activeModule === i ? `linear-gradient(135deg, rgba(${mod.color === '#00d4ff' ? '0,212,255' : mod.color === '#00ff88' ? '0,255,136' : mod.color === '#ff4d6d' ? '255,77,109' : '167,139,250'},0.08) 0%, #0f1521 100%)` : 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
                  border: `1px solid ${activeModule === i ? mod.color + '40' : 'rgba(255,255,255,0.06)'}`,
                  borderRadius: 16, padding: '22px',
                  boxShadow: activeModule === i ? mod.glow : '0 4px 24px rgba(0,0,0,0.3)',
                  animationDelay: `${0.15 + i * 0.08}s`,
                  position: 'relative', overflow: 'hidden',
                }}>
                <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${mod.color}80, transparent)` }} />
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ width: 40, height: 40, borderRadius: 10, background: `rgba(${mod.color === '#00d4ff' ? '0,212,255' : mod.color === '#00ff88' ? '0,255,136' : mod.color === '#ff4d6d' ? '255,77,109' : '167,139,250'},0.12)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <mod.icon style={{ color: mod.color, fontSize: 20 }} />
                    </div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>{mod.title}</div>
                  </div>
                  <div style={{
                    fontSize: 10, fontWeight: 700, letterSpacing: 1.5, padding: '3px 9px', borderRadius: 20,
                    color: mod.status === 'alert' ? '#ff4d6d' : '#00ff88',
                    background: mod.status === 'alert' ? 'rgba(255,77,109,0.1)' : 'rgba(0,255,136,0.1)',
                    border: `1px solid ${mod.status === 'alert' ? 'rgba(255,77,109,0.3)' : 'rgba(0,255,136,0.3)'}`,
                  }}>{mod.status.toUpperCase()}</div>
                </div>
                <p style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6, marginBottom: 16 }}>{mod.description}</p>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ fontSize: 10, color: '#475569', letterSpacing: 1, marginBottom: 3 }}>{mod.stats.label.toUpperCase()}</div>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 20, fontWeight: 700, color: mod.color }}>{mod.stats.value}</div>
                  </div>
                  <div style={{ fontSize: 12, color: mod.stats.change.startsWith('+') ? '#00ff88' : '#ff4d6d', fontWeight: 600 }}>{mod.stats.change}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Security Score */}
          <div className="fade-in" style={{
            gridColumn: 'span 4',
            background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 16, padding: '24px',
            boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
            display: 'flex', flexDirection: 'column', gap: 20,
            animationDelay: '0.45s',
          }}>
            <div>
              <div style={{ fontSize: 11, color: '#475569', letterSpacing: 2, marginBottom: 4, fontWeight: 600 }}>SECURITY POSTURE</div>
              <div style={{ fontSize: 18, fontWeight: 700, color: '#f1f5f9' }}>Threat Overview</div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'center' }}>
              <ScoreRing score={securityScore} />
            </div>
            <Doughnut data={{
              labels: ['Safe', 'Warnings', 'Critical'],
              datasets: [{
                data: threatData,
                backgroundColor: ['#00ff88', '#fbbf24', '#ff4d6d'],
                borderColor: 'transparent',
                hoverOffset: 8,
              }],
            }} options={donutOpts} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                { label: 'System Integrity', val: Math.max(70, 100 - stats.activeThreats * 2), color: '#00ff88' },
                { label: 'Network Security', val: networkStats.isMonitoring ? Math.min(95, 75 + networkStats.connections / 10) : 60, color: '#00d4ff' },
                { label: 'File System', val: stats.filesAnalyzed > 0 ? 88 : 75, color: '#a78bfa' },
              ].map((bar, i) => (
                <div key={i}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                    <span style={{ fontSize: 12, color: '#64748b' }}>{bar.label}</span>
                    <span style={{ fontSize: 12, color: bar.color, fontWeight: 700 }}>{bar.val}%</span>
                  </div>
                  <div style={{ height: 4, borderRadius: 4, background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${bar.val}%`, borderRadius: 4, background: `linear-gradient(90deg, ${bar.color}60, ${bar.color})`, boxShadow: `0 0 8px ${bar.color}60`, transition: 'width 1s ease' }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Charts Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 20, marginBottom: 28 }}>
          <div className="fade-in" style={{
            gridColumn: 'span 8',
            background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 16, padding: '24px',
            boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
            animationDelay: '0.5s',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <div>
                <div style={{ fontSize: 11, color: '#475569', letterSpacing: 2, marginBottom: 4, fontWeight: 600 }}>MODULE STATISTICS</div>
                <div style={{ fontSize: 16, fontWeight: 700, color: '#f1f5f9' }}>Activity Over Time</div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {['1W', '1M', '3M', '1Y'].map(r => (
                  <div key={r} style={{ padding: '4px 12px', borderRadius: 8, background: r === '1M' ? 'rgba(0,212,255,0.15)' : 'transparent', border: `1px solid ${r === '1M' ? 'rgba(0,212,255,0.4)' : 'rgba(255,255,255,0.06)'}`, fontSize: 12, color: r === '1M' ? '#00d4ff' : '#64748b', cursor: 'pointer', fontWeight: 600 }}>{r}</div>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap' }}>
              {lineData.datasets.map((d, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 24, height: 3, borderRadius: 2, background: d.borderColor }} />
                  <span style={{ fontSize: 12, color: '#64748b' }}>{d.label}</span>
                </div>
              ))}
            </div>
            <Line data={trafficHistory.length > 0 ? dynamicLineData : lineData} options={chartOpts} />
          </div>

          <div className="fade-in" style={{
            gridColumn: 'span 4',
            background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 16, padding: '24px',
            boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
            animationDelay: '0.55s',
          }}>
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 11, color: '#475569', letterSpacing: 2, marginBottom: 4, fontWeight: 600 }}>WEEKLY THREATS</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: '#f1f5f9' }}>Threat Frequency</div>
            </div>
            <Bar data={dynamicBarData} options={{ ...chartOpts, plugins: { ...chartOpts.plugins, legend: { display: false } } }} />
            <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
              {[{ label: 'Critical', color: '#ff4d6d' }, { label: 'Warning', color: '#fbbf24' }, { label: 'Info', color: '#00d4ff' }].map(l => (
                <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: l.color }} />
                  <span style={{ fontSize: 11, color: '#64748b' }}>{l.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live Alerts */}
        <div className="fade-in" style={{
          background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 16, padding: '24px',
          boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
          animationDelay: '0.6s',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ fontSize: 11, color: '#475569', letterSpacing: 2, fontWeight: 600 }}>RECENT ALERTS</div>
              <div style={{ padding: '2px 10px', borderRadius: 20, background: displayAlerts.length > 0 ? 'rgba(255,77,109,0.1)' : 'rgba(0,255,136,0.1)', border: `1px solid ${displayAlerts.length > 0 ? 'rgba(255,77,109,0.3)' : 'rgba(0,255,136,0.3)'}`, fontSize: 11, color: displayAlerts.length > 0 ? '#ff4d6d' : '#00ff88', fontWeight: 700 }}>{displayAlerts.length} ACTIVE</div>
            </div>
            <span style={{ fontSize: 12, color: '#00d4ff', cursor: 'pointer', fontWeight: 600 }}>View All →</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {displayAlerts.map((a, i) => {
              const cfg = severityConfig[a.severity];
              return (
                <div key={a.id} className="alert-row" style={{
                  display: 'flex', alignItems: 'center', gap: 14,
                  padding: '14px 16px', borderRadius: 12,
                  background: cfg.bg,
                  border: `1px solid ${cfg.color}20`,
                }}>
                  <cfg.icon style={{ color: cfg.color, fontSize: 18, flexShrink: 0 }} />
                  <div style={{ flex: 1, fontSize: 13, color: '#cbd5e1', fontWeight: 500 }}>{a.msg}</div>
                  <div style={{ fontSize: 11, color: '#475569', flexShrink: 0 }}>{a.time}</div>
                  <div style={{ padding: '3px 10px', borderRadius: 20, background: `${cfg.color}15`, border: `1px solid ${cfg.color}30`, fontSize: 10, color: cfg.color, fontWeight: 700, letterSpacing: 1, flexShrink: 0 }}>{a.severity.toUpperCase()}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div style={{ marginTop: 32, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 0', borderTop: '1px solid rgba(255,255,255,0.04)', flexWrap: 'wrap', gap: 8 }}>
          <div style={{ fontSize: 11, color: '#334155', letterSpacing: 2 }}>FORENSICOS 2026 — ALL SYSTEMS OPERATIONAL</div>
          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#00ff88', animation: 'pulse 2s infinite' }} />
            <span style={{ fontSize: 11, color: '#475569' }}>Last scan: {new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      </div>
    </div>
  );
}