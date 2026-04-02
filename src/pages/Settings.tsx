import React, { useState } from 'react';
import { 
  Notifications, Security, Palette, Language, 
  Save, CheckCircle 
} from '@mui/icons-material';

export default function Settings() {
  const [saved, setSaved] = useState(false);
  const [settings, setSettings] = useState({
    emailNotifications: true,
    securityAlerts: true,
    darkMode: true,
    twoFactor: false,
    language: 'English'
  });

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const toggleSetting = (key: keyof typeof settings) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div style={{ padding: '20px', color: '#fff' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h1 style={{ fontSize: '28px' }}>Settings</h1>
        <button
          onClick={handleSave}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 20px',
            background: saved ? '#00ff88' : 'linear-gradient(135deg, #0066ff, #00d4ff)',
            border: 'none',
            borderRadius: '8px',
            color: '#fff',
            fontSize: '14px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          {saved ? <CheckCircle style={{ fontSize: 18 }} /> : <Save style={{ fontSize: 18 }} />}
          {saved ? 'Saved!' : 'Save Changes'}
        </button>
      </div>

      <div style={{ display: 'grid', gap: '24px', maxWidth: '700px' }}>
        {/* Notifications */}
        <SettingCard 
          icon={<Notifications />} 
          title="Notifications" 
          description="Manage your notification preferences"
        >
          <Toggle 
            label="Email Notifications"
            checked={settings.emailNotifications}
            onChange={() => toggleSetting('emailNotifications')}
          />
          <Toggle 
            label="Security Alerts"
            checked={settings.securityAlerts}
            onChange={() => toggleSetting('securityAlerts')}
          />
        </SettingCard>

        {/* Security */}
        <SettingCard 
          icon={<Security />} 
          title="Security" 
          description="Secure your account"
        >
          <Toggle 
            label="Two-Factor Authentication"
            checked={settings.twoFactor}
            onChange={() => toggleSetting('twoFactor')}
          />
          <button style={{
            marginTop: '12px',
            padding: '10px 16px',
            background: 'rgba(0,212,255,0.1)',
            border: '1px solid rgba(0,212,255,0.3)',
            borderRadius: '8px',
            color: '#00d4ff',
            fontSize: '13px',
            cursor: 'pointer'
          }}>
            Change Password
          </button>
        </SettingCard>

        {/* Appearance */}
        <SettingCard 
          icon={<Palette />} 
          title="Appearance" 
          description="Customize your experience"
        >
          <Toggle 
            label="Dark Mode"
            checked={settings.darkMode}
            onChange={() => toggleSetting('darkMode')}
          />
        </SettingCard>

        {/* Language */}
        <SettingCard 
          icon={<Language />} 
          title="Language" 
          description="Select your preferred language"
        >
          <select 
            value={settings.language}
            onChange={(e) => setSettings(prev => ({ ...prev, language: e.target.value }))}
            style={{
              padding: '10px 16px',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '8px',
              color: '#e2e8f0',
              fontSize: '14px',
              cursor: 'pointer'
            }}
          >
            <option value="English">English</option>
            <option value="Spanish">Spanish</option>
            <option value="French">French</option>
            <option value="German">German</option>
          </select>
        </SettingCard>
      </div>
    </div>
  );
}

function SettingCard({ icon, title, description, children }: { 
  icon: React.ReactNode, 
  title: string, 
  description: string,
  children: React.ReactNode 
}) {
  return (
    <div style={{
      padding: '24px',
      background: 'linear-gradient(135deg, #0f1521 0%, #1a1f2e 100%)',
      borderRadius: '16px',
      border: '1px solid rgba(255,255,255,0.06)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
        <div style={{ color: '#00d4ff' }}>{icon}</div>
        <div>
          <h3 style={{ fontSize: '18px', marginBottom: '2px' }}>{title}</h3>
          <p style={{ fontSize: '13px', color: '#64748b' }}>{description}</p>
        </div>
      </div>
      <div style={{ paddingLeft: '36px' }}>
        {children}
      </div>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string, checked: boolean, onChange: () => void }) {
  return (
    <div style={{ 
      display: 'flex', 
      alignItems: 'center', 
      justifyContent: 'space-between',
      padding: '12px 0',
      borderBottom: '1px solid rgba(255,255,255,0.04)'
    }}>
      <span style={{ fontSize: '14px', color: '#e2e8f0' }}>{label}</span>
      <button
        onClick={onChange}
        style={{
          width: '44px',
          height: '24px',
          borderRadius: '12px',
          border: 'none',
          background: checked ? '#00d4ff' : 'rgba(255,255,255,0.1)',
          cursor: 'pointer',
          position: 'relative',
          transition: 'all 0.2s'
        }}
      >
        <div style={{
          width: '20px',
          height: '20px',
          borderRadius: '50%',
          background: '#fff',
          position: 'absolute',
          top: '2px',
          left: checked ? '22px' : '2px',
          transition: 'all 0.2s'
        }} />
      </button>
    </div>
  );
}
