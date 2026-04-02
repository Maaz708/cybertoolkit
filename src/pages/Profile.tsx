import React from 'react';
import { Person, Email, Business, CalendarToday, Security } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

export default function Profile() {
  const { user } = useAuth();

  return (
    <div style={{ padding: '20px', color: '#fff' }}>
      <h1 style={{ fontSize: '28px', marginBottom: '24px' }}>User Profile</h1>
      
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        gap: '20px',
        marginBottom: '32px',
        padding: '24px',
        background: 'linear-gradient(135deg, #0f1521 0%, #1a1f2e 100%)',
        borderRadius: '16px',
        border: '1px solid rgba(255,255,255,0.06)'
      }}>
        <div style={{
          width: 80,
          height: 80,
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #0066ff, #00d4ff)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '32px',
          fontWeight: 700,
          color: '#fff'
        }}>
          {user?.firstName?.[0] || 'J'}{user?.lastName?.[0] || 'D'}
        </div>
        <div>
          <h2 style={{ fontSize: '24px', marginBottom: '4px' }}>
            {user?.firstName || 'John'} {user?.lastName || 'Doe'}
          </h2>
          <p style={{ color: '#00d4ff', fontSize: '14px' }}>{user?.subscriptionTier || 'Free'} Plan</p>
          <p style={{ color: '#64748b', fontSize: '13px' }}>{user?.email || 'john.doe@example.com'}</p>
        </div>
      </div>

      <div style={{ display: 'grid', gap: '16px', maxWidth: '600px' }}>
        <InfoCard icon={<Person />} label="Full Name" value={`${user?.firstName || 'John'} ${user?.lastName || 'Doe'}`} />
        <InfoCard icon={<Email />} label="Email" value={user?.email || 'john.doe@example.com'} />
        <InfoCard icon={<Business />} label="Company" value={user?.companyName || 'Not specified'} />
        <InfoCard icon={<CalendarToday />} label="Member Since" value={new Date(user?.createdAt || Date.now()).toLocaleDateString()} />
        <InfoCard icon={<Security />} label="Role" value={user?.role || 'User'} />
      </div>
    </div>
  );
}

function InfoCard({ icon, label, value }: { icon: React.ReactNode, label: string, value: string }) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '16px',
      padding: '16px 20px',
      background: 'rgba(255,255,255,0.02)',
      borderRadius: '12px',
      border: '1px solid rgba(255,255,255,0.04)'
    }}>
      <div style={{ color: '#00d4ff' }}>{icon}</div>
      <div>
        <p style={{ fontSize: '12px', color: '#64748b', marginBottom: '2px' }}>{label}</p>
        <p style={{ fontSize: '15px', color: '#e2e8f0' }}>{value}</p>
      </div>
    </div>
  );
}
