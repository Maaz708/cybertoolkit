import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Security, Email, Lock, Visibility, VisibilityOff } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const API_BASE_URL = 'http://localhost:5000';

interface LoginFormData {
  email: string;
  password: string;
}

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [formData, setFormData] = useState<LoginFormData>({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    if (error) setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const result = await login(formData.email, formData.password);
      
      if (result.success) {
        console.log('✅ Login successful, redirecting to dashboard');
        // Force navigation with replace to avoid back button issues
        navigate('/dashboard', { replace: true });
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (err: any) {
      console.error('Login error:', err);
      setError(err.message || 'Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '20px',
      fontFamily: "'Syne', 'Segoe UI', sans-serif"
    }}>
      {/* Background Effects */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'radial-gradient(circle at 20% 80%, rgba(0,212,255,0.1) 0%, transparent 50%)',
      }} />
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'radial-gradient(circle at 80% 20%, rgba(167,139,250,0.1) 0%, transparent 50%)',
      }} />

      <div style={{
        position: 'relative',
        width: '100%',
        maxWidth: '450px',
        background: 'rgba(30,41,59,0.8)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '20px',
        padding: '40px',
        boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)'
      }}>
        {/* Logo and Title */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            width: '60px',
            height: '60px',
            background: 'linear-gradient(135deg, #00d4ff, #0066ff)',
            borderRadius: '15px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
            boxShadow: '0 10px 25px rgba(0,212,255,0.3)'
          }}>
            <Security style={{ fontSize: '30px', color: '#fff' }} />
          </div>
          <h1 style={{
            fontSize: '28px',
            fontWeight: '800',
            color: '#fff',
            marginBottom: '8px',
            fontFamily: "'Orbitron', monospace"
          }}>
            CyberToolkit
          </h1>
          <p style={{
            color: '#94a3b8',
            fontSize: '16px',
            margin: 0
          }}>
            Digital Forensics Platform
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit}>
          {/* Email Field */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              color: '#e2e8f0',
              fontSize: '14px',
              fontWeight: '600',
              marginBottom: '8px'
            }}>
              Email Address
            </label>
            <div style={{ position: 'relative' }}>
              <Email style={{
                position: 'absolute',
                left: '16px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                fontSize: '20px'
              }} />
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                required
                placeholder="xyz@example.com"
                style={{
                  width: '100%',
                  padding: '14px 16px 14px 48px',
                  background: 'rgba(15,23,42,0.6)',
                  border: '1px solid rgba(100,116,139,0.3)',
                  borderRadius: '12px',
                  color: '#fff',
                  fontSize: '16px',
                  outline: 'none',
                  transition: 'all 0.3s ease'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#00d4ff';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,212,255,0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>
          </div>

          {/* Password Field */}
          <div style={{ marginBottom: '32px' }}>
            <label style={{
              display: 'block',
              color: '#e2e8f0',
              fontSize: '14px',
              fontWeight: '600',
              marginBottom: '8px'
            }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock style={{
                position: 'absolute',
                left: '16px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                fontSize: '20px'
              }} />
              <input
                type={showPassword ? 'text' : 'password'}
                name="password"
                value={formData.password}
                onChange={handleChange}
                required
                placeholder="Enter your password"
                style={{
                  width: '100%',
                  padding: '14px 48px 14px 48px',
                  background: 'rgba(15,23,42,0.6)',
                  border: '1px solid rgba(100,116,139,0.3)',
                  borderRadius: '12px',
                  color: '#fff',
                  fontSize: '16px',
                  outline: 'none',
                  transition: 'all 0.3s ease'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#00d4ff';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,212,255,0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                  e.target.style.boxShadow = 'none';
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '16px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: '#64748b',
                  cursor: 'pointer',
                  padding: '4px'
                }}
              >
                {showPassword ? <VisibilityOff /> : <Visibility />}
              </button>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div style={{
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '24px',
              color: '#f87171',
              fontSize: '14px'
            }}>
              {error}
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            style={{
              width: '100%',
              padding: '16px',
              background: isLoading 
                ? 'linear-gradient(135deg, #64748b, #475569)' 
                : 'linear-gradient(135deg, #00d4ff, #0066ff)',
              border: 'none',
              borderRadius: '12px',
              color: '#fff',
              fontSize: '16px',
              fontWeight: '700',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              transition: 'all 0.3s ease',
              boxShadow: isLoading ? 'none' : '0 10px 25px rgba(0,212,255,0.3)'
            }}
            onMouseEnter={(e) => {
              if (!isLoading) {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = '0 15px 35px rgba(0,212,255,0.4)';
              }
            }}
            onMouseLeave={(e) => {
              if (!isLoading) {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 10px 25px rgba(0,212,255,0.3)';
              }
            }}
          >
            {isLoading ? 'Signing In...' : 'Sign In'}
          </button>
        </form>

        {/* Register Link */}
        <div style={{
          textAlign: 'center',
          marginTop: '32px',
          paddingTop: '24px',
          borderTop: '1px solid rgba(100,116,139,0.2)'
        }}>
          <p style={{
            color: '#94a3b8',
            fontSize: '14px',
            margin: 0
          }}>
            Don't have an account?{' '}
            <Link 
              to="/register"
              style={{
                color: '#00d4ff',
                textDecoration: 'none',
                fontWeight: '600',
                transition: 'color 0.3s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = '#00a8cc';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = '#00d4ff';
              }}
            >
              Sign up here
            </Link>
          </p>
        </div>

        {/* Demo Credentials */}
        
      </div>
    </div>
  );
}
