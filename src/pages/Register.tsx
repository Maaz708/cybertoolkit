import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Security, Email, Lock, Person, Business, Visibility, VisibilityOff } from '@mui/icons-material';
import axios from 'axios';
import { API_BASE_URL } from '../config/api';

interface RegisterFormData {
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  companyName: string;
}

interface ApiResponse {
  success: boolean;
  user?: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    companyName: string;
    role: string;
    subscriptionTier: string;
    createdAt: string;
  };
  error?: string;
  message?: string;
}

export default function Register() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState<RegisterFormData>({
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: '',
    companyName: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    if (error) setError('');
    if (success) setSuccess('');
  };

  const validateForm = (): boolean => {
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return false;
    }
    
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      return false;
    }

    if (!formData.email.includes('@')) {
      setError('Please enter a valid email address');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateForm()) return;

    setIsLoading(true);
    setError('');
    setSuccess('');

    try {
      const { confirmPassword, ...submitData } = formData;
      const response = await axios.post<ApiResponse>(`${API_BASE_URL}/api/auth/register`, submitData);
      
      if (response.data.success) {
        setSuccess('Account created successfully! Please sign in.');
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        setError(response.data.error || 'Registration failed');
      }
    } catch (err: any) {
      console.error('Registration error:', err);
        console.log('Error response:', err.response?.data); // Add this line
      setError(err.response?.data?.error || 'Network error. Please try again.');
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
        background: 'radial-gradient(circle at 20% 80%, rgba(0,255,136,0.1) 0%, transparent 50%)',
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
        maxWidth: '500px',
        background: 'rgba(30,41,59,0.8)',
        backdropFilter: 'blur(20px)',
        border: '1px solid rgba(255,255,255,0.1)',
        borderRadius: '20px',
        padding: '40px',
        boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)'
      }}>
        {/* Logo and Title */}
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <div style={{
            width: '60px',
            height: '60px',
            background: 'linear-gradient(135deg, #00ff88, #00cc6a)',
            borderRadius: '15px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
            boxShadow: '0 10px 25px rgba(0,255,136,0.3)'
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
            Create Account
          </h1>
          <p style={{
            color: '#94a3b8',
            fontSize: '16px',
            margin: 0
          }}>
            Join CyberToolkit Platform
          </p>
        </div>

        {/* Registration Form */}
        <form onSubmit={handleSubmit}>
          {/* Name Fields */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
            <div>
              <label style={{
                display: 'block',
                color: '#e2e8f0',
                fontSize: '14px',
                fontWeight: '600',
                marginBottom: '8px'
              }}>
                First Name
              </label>
              <div style={{ position: 'relative' }}>
                <Person style={{
                  position: 'absolute',
                  left: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: '#64748b',
                  fontSize: '18px'
                }} />
                <input
                  type="text"
                  name="firstName"
                  value={formData.firstName}
                  onChange={handleChange}
                  required
                  placeholder="John"
                  style={{
                    width: '100%',
                    padding: '12px 12px 12px 40px',
                    background: 'rgba(15,23,42,0.6)',
                    border: '1px solid rgba(100,116,139,0.3)',
                    borderRadius: '10px',
                    color: '#fff',
                    fontSize: '15px',
                    outline: 'none',
                    transition: 'all 0.3s ease'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#00ff88';
                    e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
              </div>
            </div>
            <div>
              <label style={{
                display: 'block',
                color: '#e2e8f0',
                fontSize: '14px',
                fontWeight: '600',
                marginBottom: '8px'
              }}>
                Last Name
              </label>
              <div style={{ position: 'relative' }}>
                <Person style={{
                  position: 'absolute',
                  left: '12px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: '#64748b',
                  fontSize: '18px'
                }} />
                <input
                  type="text"
                  name="lastName"
                  value={formData.lastName}
                  onChange={handleChange}
                  required
                  placeholder="Doe"
                  style={{
                    width: '100%',
                    padding: '12px 12px 12px 40px',
                    background: 'rgba(15,23,42,0.6)',
                    border: '1px solid rgba(100,116,139,0.3)',
                    borderRadius: '10px',
                    color: '#fff',
                    fontSize: '15px',
                    outline: 'none',
                    transition: 'all 0.3s ease'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#00ff88';
                    e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
              </div>
            </div>
          </div>

          {/* Company Name */}
          <div style={{ marginBottom: '20px' }}>
            <label style={{
              display: 'block',
              color: '#e2e8f0',
              fontSize: '14px',
              fontWeight: '600',
              marginBottom: '8px'
            }}>
              Company Name (Optional)
            </label>
            <div style={{ position: 'relative' }}>
              <Business style={{
                position: 'absolute',
                left: '16px',
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#64748b',
                fontSize: '20px'
              }} />
              <input
                type="text"
                name="companyName"
                value={formData.companyName}
                onChange={handleChange}
                placeholder="Acme Corp"
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
                  e.target.style.borderColor = '#00ff88';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>
          </div>

          {/* Email Field */}
          <div style={{ marginBottom: '20px' }}>
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
                placeholder="john@example.com"
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
                  e.target.style.borderColor = '#00ff88';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>
          </div>

          {/* Password Field */}
          <div style={{ marginBottom: '20px' }}>
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
                placeholder="Min 8 characters"
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
                  e.target.style.borderColor = '#00ff88';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
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

          {/* Confirm Password Field */}
          <div style={{ marginBottom: '24px' }}>
            <label style={{
              display: 'block',
              color: '#e2e8f0',
              fontSize: '14px',
              fontWeight: '600',
              marginBottom: '8px'
            }}>
              Confirm Password
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
                type={showConfirmPassword ? 'text' : 'password'}
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
                placeholder="Confirm your password"
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
                  e.target.style.borderColor = '#00ff88';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0,255,136,0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(100,116,139,0.3)';
                  e.target.style.boxShadow = 'none';
                }}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
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
                {showConfirmPassword ? <VisibilityOff /> : <Visibility />}
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
              marginBottom: '20px',
              color: '#f87171',
              fontSize: '14px'
            }}>
              {error}
            </div>
          )}

          {/* Success Message */}
          {success && (
            <div style={{
              background: 'rgba(0,255,136,0.1)',
              border: '1px solid rgba(0,255,136,0.3)',
              borderRadius: '8px',
              padding: '12px',
              marginBottom: '20px',
              color: '#00ff88',
              fontSize: '14px'
            }}>
              {success}
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
                : 'linear-gradient(135deg, #00ff88, #00cc6a)',
              border: 'none',
              borderRadius: '12px',
              color: '#fff',
              fontSize: '16px',
              fontWeight: '700',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              transition: 'all 0.3s ease',
              boxShadow: isLoading ? 'none' : '0 10px 25px rgba(0,255,136,0.3)'
            }}
            onMouseEnter={(e) => {
              if (!isLoading) {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = '0 15px 35px rgba(0,255,136,0.4)';
              }
            }}
            onMouseLeave={(e) => {
              if (!isLoading) {
                e.currentTarget.style.transform = 'translateY(0)';
                e.currentTarget.style.boxShadow = '0 10px 25px rgba(0,255,136,0.3)';
              }
            }}
          >
            {isLoading ? 'Creating Account...' : 'Create Account'}
          </button>
        </form>

        {/* Login Link */}
        <div style={{
          textAlign: 'center',
          marginTop: '24px',
          paddingTop: '24px',
          borderTop: '1px solid rgba(100,116,139,0.2)'
        }}>
          <p style={{
            color: '#94a3b8',
            fontSize: '14px',
            margin: 0
          }}>
            Already have an account?{' '}
            <Link 
              to="/login"
              style={{
                color: '#00ff88',
                textDecoration: 'none',
                fontWeight: '600',
                transition: 'color 0.3s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = '#00cc6a';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = '#00ff88';
              }}
            >
              Sign in here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
