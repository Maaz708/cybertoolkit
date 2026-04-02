import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Storage, NetworkCheck, Email, Cloud, BugReport, Fingerprint,
  Dashboard as DashboardIcon, Settings, Logout, ChevronLeft, ChevronRight
} from '@mui/icons-material';

// Navigation items
const navItems = [
  { label: 'Dashboard', icon: DashboardIcon, path: '/dashboard' },
  { label: 'File Analysis', icon: Storage, path: '/file-analysis' },
  { label: 'Network Monitor', icon: NetworkCheck, path: '/network-monitor' },
  { label: 'Malware Detection', icon: BugReport, path: '/malware-detection' },
  { label: 'Email Forensics', icon: Email, path: '/email-forensics' },
  /*{ label: 'Cloud Forensics', icon: Cloud, path: '/cloud-forensics' },*/
  { label: 'File Recovery', icon: Storage, path: '/file-recovery' },
  /*{ label: 'Settings', icon: Settings, path: '/settings' },*/
];

// Sidebar component
interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
  activePath: string;
  navigate: (path: string, options?: { replace?: boolean }) => void;
}

function Sidebar({ isOpen, toggleSidebar, activePath, navigate }: SidebarProps) {
  return (
    <div style={{
      width: isOpen ? 240 : 70,
      height: '100vh',
      background: 'linear-gradient(180deg, #0f1521 0%, #1a1f2e 100%)',
      borderRight: '1px solid rgba(255,255,255,0.06)',
      position: 'fixed',
      left: 0,
      top: 0,
      zIndex: 100,
      transition: 'width 0.3s ease',
      display: 'flex',
      flexDirection: 'column',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: isOpen ? 'flex-start' : 'center',
        gap: 12,
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}>
        <div style={{
          width: 40, height: 40, borderRadius: 10,
          background: 'linear-gradient(135deg, #00d4ff, #0066ff)',
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          <Fingerprint style={{ color: '#fff', fontSize: 22 }} />
        </div>
        {isOpen && (
          <div>
            <div style={{ fontFamily: "'Orbitron', monospace", fontWeight: 700, fontSize: 16, color: '#e2e8f0' }}>
             DIGITAL FORENSIC<span style={{ color: '#00d4ff' }}>Toolkit</span>
            </div>
            <div style={{ fontSize: 10, color: '#475569', letterSpacing: 2 }}>v1.0</div>
          </div>
        )}
      </div>

      {/* Toggle button */}
      <button
        onClick={toggleSidebar}
        style={{
          position: 'absolute',
          right: -12,
          top: 28,
          width: 24,
          height: 24,
          borderRadius: '50%',
          background: '#00d4ff',
          border: 'none',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 10px rgba(0,212,255,0.5)',
        }}
      >
        {isOpen ? <ChevronLeft style={{ color: '#fff', fontSize: 16 }} /> : <ChevronRight style={{ color: '#fff', fontSize: 16 }} />}
      </button>

      {/* Navigation items */}
      <div style={{ padding: '16px 8px', flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
        {navItems.map((item) => {
          const isActive = activePath === item.path;
          return (
            <div
              key={item.label}
              onClick={() => {
                console.log('Navigating to:', item.path);
                navigate(item.path);
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                padding: '12px 16px',
                borderRadius: 10,
                cursor: 'pointer',
                transition: 'all 0.2s',
                background: isActive ? 'rgba(0,212,255,0.15)' : 'transparent',
                border: isActive ? '1px solid rgba(0,212,255,0.3)' : '1px solid transparent',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'transparent';
                }
              }}
            >
              <item.icon style={{ color: isActive ? '#00d4ff' : '#64748b', fontSize: 22 }} />
              {isOpen && (
                <span style={{
                  fontSize: 14,
                  fontWeight: 600,
                  color: isActive ? '#00d4ff' : '#94a3b8',
                }}>
                  {item.label}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* User Profile */}
      <div style={{ padding: '16px 8px', borderTop: '1px solid rgba(255,255,255,0.06)', marginTop: 'auto' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '12px 16px',
            borderRadius: 10,
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          onClick={() => navigate('/profile')}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(0,212,255,0.1)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'transparent';
          }}
        >
          <div style={{
            width: 36,
            height: 36,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #0066ff, #00d4ff)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 14,
            fontWeight: 700,
            color: '#fff'
          }}>
            JD
          </div>
          {isOpen && (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>
                John Doe
              </span>
              <span style={{ fontSize: 11, color: '#00d4ff', fontWeight: 500 }}>
                Free Plan
              </span>
            </div>
          )}
        </div>

        {/* Settings */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '10px 16px',
            borderRadius: 10,
            cursor: 'pointer',
            transition: 'all 0.2s',
            marginTop: 8,
          }}
          onClick={() => navigate('/settings')}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'transparent';
          }}
        >
          <Settings style={{ color: '#64748b', fontSize: 20 }} />
          {isOpen && (
            <span style={{ fontSize: 13, fontWeight: 500, color: '#94a3b8' }}>
              Settings
            </span>
          )}
        </div>
      </div>

      {/* Logout */}
      <div style={{ padding: '16px 8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '12px 16px',
            borderRadius: 10,
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          onClick={() => {
            navigate('/', { replace: true });
            // Clear auth state
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            window.location.reload();
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255,77,109,0.15)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'transparent';
          }}
        >
          <Logout style={{ color: '#ff4d6d', fontSize: 22 }} />
          {isOpen && (
            <span style={{ fontSize: 14, fontWeight: 600, color: '#ff4d6d' }}>
              Logout
            </span>
          )}  
        </div>
      </div>
    </div>
  );
}

// Layout wrapper component
interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Debug logging
  console.log('Layout rendered, current path:', location.pathname);
  console.log('Children received:', children ? 'Yes' : 'No');

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0a0e1a' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Syne:wght@400;600;700;800&display=swap');
      `}</style>
      
      {/* Sidebar */}
      <Sidebar
        isOpen={sidebarOpen}
        toggleSidebar={() => setSidebarOpen(!sidebarOpen)}
        activePath={location.pathname}
        navigate={(path) => navigate(path)}
      />

      {/* Main Content */}
      <div style={{
        flex: 1,
        marginLeft: sidebarOpen ? 240 : 70,
        transition: 'margin-left 0.3s ease',
        minHeight: '100vh',
        overflowX: 'hidden',
        backgroundColor: '#1a1f2e',
        padding: '20px',
        color: '#fff',
      }}>
        <div key={location.pathname} style={{ minHeight: '100px' }}>
          {children}
        </div>
      </div>
    </div>
  );
}
