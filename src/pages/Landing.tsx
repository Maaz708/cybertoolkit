import React from 'react';
import { Box, Container, Typography, Button, Grid, Card, CardContent, Chip, Stack, Fade, Slide } from '@mui/material';
import { Security, NetworkCheck, Email, BugReport, Speed, Shield, GppGood, Timeline, Assessment, CloudUpload, Search, Lock } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';

const Landing = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: <NetworkCheck sx={{ fontSize: 40, color: '#00d4ff' }} />,
      title: 'Network Monitoring',
      description: 'Real-time network traffic analysis and connection monitoring with threat detection.',
      color: '#00d4ff'
    },
    {
      icon: <BugReport sx={{ fontSize: 40, color: '#f59e0b' }} />,
      title: 'Malware Analysis',
      description: 'Advanced file scanning and malware detection with comprehensive threat intelligence.',
      color: '#f59e0b'
    },
    {
      icon: <Email sx={{ fontSize: 40, color: '#10b981' }} />,
      title: 'Email Forensics',
      description: 'Phishing detection and email analysis with detailed threat assessment.',
      color: '#10b981'
    },
    {
      icon: <Shield sx={{ fontSize: 40, color: '#ef4444' }} />,
      title: 'Security Assessment',
      description: 'Comprehensive security scoring and vulnerability assessment tools.',
      color: '#ef4444'
    },
    {
      icon: <CloudUpload sx={{ fontSize: 40, color: '#8b5cf6' }} />,
      title: 'File Analysis',
      description: 'Deep file analysis and metadata extraction for forensic investigations.',
      color: '#8b5cf6'
    },
    {
      icon: <Lock sx={{ fontSize: 40, color: '#06b6d4' }} />,
      title: 'Data Protection',
      description: 'Enterprise-grade encryption and secure data handling for sensitive information.',
      color: '#06b6d4'
    }
  ];

  const useCases = [
    {
      title: 'Enterprise Security',
      description: 'Monitor and protect corporate networks from advanced threats and data breaches.',
      icon: <Security />,
      tags: ['Threat Detection', 'Compliance', 'Risk Management']
    },
    {
      title: 'Incident Response',
      description: 'Rapid forensic analysis and incident containment for security teams.',
      icon: <Timeline />,
      tags: ['Forensics', 'Response Time', 'Evidence Collection']
    },
    {
      title: 'Compliance Auditing',
      description: 'Automated security assessments and compliance reporting for regulatory requirements.',
      icon: <Assessment />,
      tags: ['GDPR', 'SOC 2', 'ISO 27001']
    },
    {
      title: 'Research & Development',
      description: 'Advanced threat research and malware analysis for security researchers.',
      icon: <Search />,
      tags: ['Research', 'Analysis', 'Intelligence']
    }
  ];

  const stats = [
    { number: '99.9%', label: 'Threat Detection Accuracy' },
    { number: '< 1s', label: 'Response Time' },
    { number: '24/7', label: 'Monitoring' },
    { number: '100+', label: 'Threat Signatures' }
  ];

  return (
    <Box sx={{ minHeight: '100vh', background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)' }}>
      {/* Hero Section */}
      <Container maxWidth="lg" sx={{ py: { xs: 8, md: 12 } }}>
        <Grid container spacing={4} alignItems="center">
          <Grid item xs={12} md={6}>
            <motion.div
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.8 }}
            >
              <Typography
                variant="h2"
                sx={{
                  fontFamily: "'Orbitron', monospace",
                  fontWeight: 700,
                  fontSize: { xs: '2.5rem', md: '3.5rem' },
                  color: '#e2e8f0',
                  mb: 2,
                  lineHeight: 1.2
                }}
              >
                CyberToolkit
              </Typography>
              <Typography
                variant="h5"
                sx={{
                  fontFamily: "'Syne', 'Segoe UI', sans-serif",
                  fontWeight: 600,
                  color: '#00d4ff',
                  mb: 3
                }}
              >
                Advanced Digital Forensics Platform
              </Typography>
              <Typography
                variant="body1"
                sx={{
                  color: '#94a3b8',
                  fontSize: '1.1rem',
                  lineHeight: 1.6,
                  mb: 4
                }}
              >
                Comprehensive security analysis and threat detection platform designed for modern cybersecurity professionals. 
                Monitor, analyze, and protect your digital infrastructure with enterprise-grade tools.
              </Typography>
              <Stack direction="row" spacing={3}>
                <Button
                  variant="contained"
                  size="large"
                  onClick={() => navigate('/login')}
                  sx={{
                    background: 'linear-gradient(45deg, #00d4ff, #0099cc)',
                    color: '#0f172a',
                    fontFamily: "'Syne', 'Segoe UI', sans-serif",
                    fontWeight: 600,
                    px: 4,
                    py: 1.5,
                    '&:hover': {
                      background: 'linear-gradient(45deg, #0099cc, #00d4ff)',
                      transform: 'translateY(-2px)',
                      boxShadow: '0 10px 25px rgba(0, 212, 255, 0.3)'
                    }
                  }}
                >
                  Get Started
                </Button>
                <Button
                  variant="outlined"
                  size="large"
                  onClick={() => navigate('/register')}
                  sx={{
                    borderColor: '#00d4ff',
                    color: '#00d4ff',
                    fontFamily: "'Syne', 'Segoe UI', sans-serif",
                    fontWeight: 600,
                    px: 4,
                    py: 1.5,
                    '&:hover': {
                      borderColor: '#0099cc',
                      background: 'rgba(0, 212, 255, 0.1)',
                      transform: 'translateY(-2px)'
                    }
                  }}
                >
                  Sign Up Free
                </Button>
              </Stack>
            </motion.div>
          </Grid>
          <Grid item xs={12} md={6}>
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.8, delay: 0.2 }}
            >
              <Box
                sx={{
                  background: 'rgba(0, 212, 255, 0.1)',
                  border: '1px solid rgba(0, 212, 255, 0.3)',
                  borderRadius: 4,
                  p: 4,
                  backdropFilter: 'blur(10px)'
                }}
              >
                <Grid container spacing={2}>
                  {stats.map((stat, index) => (
                    <Grid item xs={6} key={index}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography
                          variant="h3"
                          sx={{
                            color: '#00d4ff',
                            fontFamily: "'Orbitron', monospace",
                            fontWeight: 700
                          }}
                        >
                          {stat.number}
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{ color: '#94a3b8' }}
                        >
                          {stat.label}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </motion.div>
          </Grid>
        </Grid>
      </Container>

      {/* 🚀 CLIENT-FOCUSED INTRO SECTION */}
      <section style={{
        padding: '60px 32px 20px',
        maxWidth: 1440,
        margin: '0 auto'
      }}>
        <div style={{
          background: 'linear-gradient(135deg, rgba(0,212,255,0.08), rgba(167,139,250,0.08))',
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 20,
          padding: '40px',
          backdropFilter: 'blur(20px)',
          position: 'relative',
          overflow: 'hidden'
        }}>
          
          {/* Glow Effect */}
          <div style={{
            position: 'absolute',
            top: '-50px',
            right: '-50px',
            width: '200px',
            height: '200px',
            background: 'radial-gradient(circle, rgba(0,212,255,0.15), transparent)',
            borderRadius: '50%'
          }} />

          <div style={{ position: 'relative', zIndex: 1 }}>

            {/* Heading */}
            <h1 style={{
              fontFamily: "'Orbitron', monospace",
              fontSize: 'clamp(26px, 4vw, 40px)',
              fontWeight: 900,
              color: '#fff',
              marginBottom: 16,
              lineHeight: 1.2
            }}>
              Digital Forensics, <span style={{ color: '#00d4ff' }}>Reimagined for Real-Time Intelligence</span>
            </h1>

            {/* Subtext */}
            <p style={{
              fontSize: 15,
              color: '#94a3b8',
              maxWidth: 800,
              lineHeight: 1.6,
              marginBottom: 20
            }}>
              Analyze, detect, and recover critical data using advanced forensic intelligence. 
              Built for cybersecurity professionals, developers, and investigators who demand speed, accuracy, and actionable insights—without complexity.
            </p>

            {/* Supporting Line */}
            <div style={{
              display: 'flex',
              gap: 20,
              marginBottom: 30,
              flexWrap: 'wrap',
              fontSize: 13,
              color: '#64748b',
              fontWeight: 500
            }}>
              <span style={{ color: '#00d4ff' }}>⚡ Real-time monitoring</span>
              <span style={{ color: '#a78bfa' }}>🧠 AI-powered threat detection</span>
              <span style={{ color: '#00ff88' }}>🔍 Deep forensic visibility</span>
            </div>

            {/* Story Section */}
            <div style={{
              background: 'rgba(255,255,255,0.02)',
              padding: 25,
              borderRadius: 12,
              border: '1px solid rgba(255,255,255,0.06)',
              marginBottom: 30
            }}>
              <div style={{ fontSize: 14, color: '#fff', fontWeight: 700, marginBottom: 12 }}>Every breach starts quietly.</div>
              <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6, marginBottom: 12 }}>
                A hidden file. An unusual connection. A single overlooked signal.
              </div>
              <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6, marginBottom: 12 }}>
                Most tools react too late—after damage is already done.
              </div>
              <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>
                That's why we built Digital Forensics Toolkit. A platform designed not just to monitor—but to understand. 
                Not just to detect—but to explain. Not just to alert—but to act.
              </div>
              <div style={{ fontSize: 13, color: '#0984feff', fontWeight: 600, lineHeight: 1.6 }}>
                From real-time network tracking to deep file analysis and malware detection, this system transforms complex data into clear, actionable intelligence—so you can respond faster, smarter, and with confidence.
              </div>
            </div>

            {/* WHY / WHAT / HOW / WHEN */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 20
            }}>
              
              {/* WHY */}
              <div style={{
                background: 'rgba(255,255,255,0.03)',
                padding: 20,
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.06)'
              }}>
                <div style={{ color: '#00d4ff', fontWeight: 700, marginBottom: 8 }}>WHY IT MATTERS</div>
                <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
Because milliseconds matter in cybersecurity.

  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>⚡ Real-time insights — not delayed reports</div>
<div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>🎯 High-precision detection — fewer false positives</div>
<div  style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>🧩 Unified dashboard — no tool switching</div>
<div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>🔐 Enterprise-grade intelligence — simplified    </div>            </div>
              </div>

              {/* WHAT */}
              <div style={{
                background: 'rgba(255,255,255,0.03)',
                padding: 20,
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.06)'
              }}>
                <div style={{ color: '#a78bfa', fontWeight: 700, marginBottom: 8 }}>WHAT IT DOES</div>
                <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
A Unified Intelligence Layer for Cybersecurity

  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>File Analysis</div>
Extract metadata, trace origins, and detect anomalies in seconds.
  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>Network Monitoring</div>
Real-time packet-level visibility with live connection tracking.
  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>Malware Detection</div>
AI-powered engine identifying both known and zero-day threats.
  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, lineHeight: 1.6 }}>Email Forensics</div>
Deep header inspection and phishing pattern detection.                </div>
              </div>

              {/* HOW */}
              <div style={{
                background: 'rgba(255,255,255,0.03)',
                padding: 20,
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.06)'
              }}>
                <div style={{ color: '#00ff88', fontWeight: 700, marginBottom: 8 }}>HOW IT WORKS</div>
                <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
                  <div style={{ color: '#00ff88', fontWeight: 700 }}  >Collect</div>
Aggregates data from files, network traffic, and system activity.
<div style={{ color: '#00ff88', fontWeight: 700 }}>Analyze</div>
Applies intelligent models and forensic rules to detect anomalies.
<div style={{ color: '#00ff88', fontWeight: 700 }}>Visualize</div>
Converts raw data into intuitive dashboards and live insights.
<div style={{ color: '#00ff88', fontWeight: 700 }}>Act</div>
Enables rapid response through alerts, scoring, and threat prioritization. Transform complex data into clear, actionable intelligence.
                </div>
              </div>

              {/* WHEN */}
              <div style={{
                background: 'rgba(255,255,255,0.03)',
                padding: 20,
                borderRadius: 12,
                border: '1px solid rgba(255,255,255,0.06)'
              }}>
                <div style={{ color: '#ff4d6d', fontWeight: 700, marginBottom: 8 }}>WHEN TO USE</div>
                <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
                  Active threat monitoring, suspected breach, continuous auditing, suspicious file analysis, strengthening security posture.
                </div>
              </div>

            </div>

            {/* CTA */}
            <div style={{
              marginTop: 30,
              display: 'flex',
              gap: 15,
              flexWrap: 'wrap'
            }}>
              <button 
                onClick={() => navigate('/login')}
                style={{
                  padding: '12px 24px',
                  borderRadius: 30,
                  border: 'none',
                  background: 'linear-gradient(135deg, #00d4ff, #0066ff)',
                  color: '#fff',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: '0 8px 30px rgba(0,212,255,0.3)',
                  transition: 'all 0.3s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = '0 12px 40px rgba(0,212,255,0.4)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = '0 8px 30px rgba(0,212,255,0.3)';
                }}
              >
                Get Started
              </button>

              <button 
                onClick={() => navigate('/register')}
                style={{
                  padding: '12px 24px',
                  borderRadius: 30,
                  border: '1px solid rgba(255,255,255,0.1)',
                  background: 'transparent',
                  color: '#94a3b8',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.3s ease'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = 'rgba(255,255,255,0.05)';
                  e.currentTarget.style.color = '#fff';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = '#94a3b8';
                }}
              >
                Create Account
              </button>
            </div>

            {/* Final Value Proposition */}
            <div style={{
              marginTop: 25,
              padding: 20,
              background: 'rgba(0,212,255,0.05)',
              border: '1px solid rgba(0,212,255,0.2)',
              borderRadius: 12,
              textAlign: 'center'
            }}>
              <div style={{ fontSize: 14, color: '#00d4ff', fontWeight: 700, marginBottom: 8 }}>
                Stop reacting. Start anticipating.
              </div>
              <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.5 }}>
                Digital Forensics Toolkit gives you the clarity to see threats before they escalate—and the tools to act before it's too late.
              </div>
            </div>

            {/* KEY FEATURES */}
            <div style={{
              marginTop: 30,
              padding: 25,
              background: 'rgba(255,255,255,0.02)',
              borderRadius: 12,
              border: '1px solid rgba(255,255,255,0.06)'
            }}>
              <div style={{ fontSize: 16, color: '#fff', fontWeight: 700, marginBottom: 16, textAlign: 'center' }}>
                🚀 KEY FEATURES
              </div>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: 15
              }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#00d4ff', fontSize: 16 }}>📊</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, marginBottom: 4 }}>Live Threat Monitoring Dashboard</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Real-time security posture and threat visibility</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#a78bfa', fontSize: 16 }}>🎯</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#a78bfa', fontWeight: 600, marginBottom: 4 }}>Security Score & Risk Visualization</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Comprehensive risk assessment at a glance</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#00ff88', fontSize: 16 }}>🔍</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#00ff88', fontWeight: 600, marginBottom: 4 }}>Protocol & Traffic Analysis</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Deep packet inspection and protocol tracking</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#ff4d6d', fontSize: 16 }}>⚠️</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#ff4d6d', fontWeight: 600, marginBottom: 4 }}>Automated Alert System</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Smart threat detection and prioritization</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#00d4ff', fontSize: 16 }}>📈</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, marginBottom: 4 }}>Historical Data Tracking</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Trend analysis and forensic timeline</div>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{ color: '#a78bfa', fontSize: 16 }}>📊</span>
                  <div>
                    <div style={{ fontSize: 13, color: '#a78bfa', fontWeight: 600, marginBottom: 4 }}>Interactive Charts & Insights</div>
                    <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>Dynamic data visualization and reporting</div>
                  </div>
                </div>
              </div>
            </div>

            {/* USE CASES */}
            <div style={{
              marginTop: 25,
              padding: 25,
              background: 'rgba(167,139,250,0.05)',
              borderRadius: 12,
              border: '1px solid rgba(167,139,250,0.2)'
            }}>
              <div style={{ fontSize: 16, color: '#fff', fontWeight: 700, marginBottom: 16, textAlign: 'center' }}>
                🛡️ USE CASES
              </div>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: 15
              }}>
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  padding: 15,
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🏢</div>
                  <div style={{ fontSize: 13, color: '#a78bfa', fontWeight: 600, marginBottom: 4 }}>SOC Teams</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.4 }}>24/7 security operations monitoring</div>
                </div>
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  padding: 15,
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🔍</div>
                  <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600, marginBottom: 4 }}>Digital Forensics</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.4 }}>Incident investigation and evidence collection</div>
                </div>
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  padding: 15,
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🚨</div>
                  <div style={{ fontSize: 13, color: '#ff4d6d', fontWeight: 600, marginBottom: 4 }}>Incident Response</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.4 }}>Rapid breach containment and analysis</div>
                </div>
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  padding: 15,
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>💻</div>
                  <div style={{ fontSize: 13, color: '#00ff88', fontWeight: 600, marginBottom: 4 }}>Developers</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.4 }}>Building secure systems and applications</div>
                </div>
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  padding: 15,
                  borderRadius: 8,
                  border: '1px solid rgba(255,255,255,0.06)',
                  textAlign: 'center'
                }}>
                  <div style={{ fontSize: 24, marginBottom: 8 }}>🚀</div>
                  <div style={{ fontSize: 13, color: '#ff4d6d', fontWeight: 600, marginBottom: 4 }}>Startups</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.4 }}>Scalable security from day one</div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* Features Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: "'Orbitron', monospace",
              fontWeight: 700,
              fontSize: '2.5rem',
              color: '#e2e8f0',
              textAlign: 'center',
              mb: 2
            }}
          >
            Powerful Features
          </Typography>
          <Typography
            variant="h6"
            sx={{
              color: '#94a3b8',
              textAlign: 'center',
              mb: 6
            }}
          >
            Everything you need for comprehensive digital security and forensic analysis
          </Typography>
        </motion.div>

        <Grid container spacing={4}>
          {features.map((feature, index) => (
            <Grid item xs={12} md={4} key={index}>
              <motion.div
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <Card
                  sx={{
                    background: 'rgba(30, 41, 59, 0.8)',
                    border: '1px solid rgba(0, 212, 255, 0.2)',
                    height: '100%',
                    transition: 'all 0.3s ease',
                    '&:hover': {
                      transform: 'translateY(-5px)',
                      borderColor: feature.color,
                      boxShadow: `0 10px 30px rgba(0, 0, 0, 0.3), 0 0 20px ${feature.color}33`
                    }
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ mb: 2 }}>
                      {feature.icon}
                    </Box>
                    <Typography
                      variant="h5"
                      sx={{
                        fontFamily: "'Syne', 'Segoe UI', sans-serif",
                        fontWeight: 600,
                        color: '#e2e8f0',
                        mb: 2
                      }}
                    >
                      {feature.title}
                    </Typography>
                    <Typography
                      variant="body2"
                      sx={{
                        color: '#94a3b8',
                        lineHeight: 1.6
                      }}
                    >
                      {feature.description}
                    </Typography>
                  </CardContent>
                </Card>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* Use Cases Section */}
      <Container maxWidth="lg" sx={{ py: 8 }}>
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <Typography
            variant="h3"
            sx={{
              fontFamily: "'Orbitron', monospace",
              fontWeight: 700,
              fontSize: '2.5rem',
              color: '#e2e8f0',
              textAlign: 'center',
              mb: 2
            }}
          >
            Use Cases
          </Typography>
          <Typography
            variant="h6"
            sx={{
              color: '#94a3b8',
              textAlign: 'center',
              mb: 6
            }}
          >
            Trusted by security teams, researchers, and organizations worldwide
          </Typography>
        </motion.div>

        <Grid container spacing={4}>
          {useCases.map((useCase, index) => (
            <Grid item xs={12} md={6} key={index}>
              <motion.div
                initial={{ opacity: 0, x: index % 2 === 0 ? -30 : 30 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <Card
                  sx={{
                    background: 'rgba(30, 41, 59, 0.8)',
                    border: '1px solid rgba(0, 212, 255, 0.2)',
                    height: '100%',
                    transition: 'all 0.3s ease',
                    '&:hover': {
                      transform: 'translateY(-5px)',
                      borderColor: '#00d4ff',
                      boxShadow: '0 10px 30px rgba(0, 0, 0, 0.3)'
                    }
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <Box
                        sx={{
                          background: 'rgba(0, 212, 255, 0.1)',
                          borderRadius: 2,
                          p: 1,
                          mr: 2
                        }}
                      >
                        {useCase.icon}
                      </Box>
                      <Typography
                        variant="h5"
                        sx={{
                          fontFamily: "'Syne', 'Segoe UI', sans-serif",
                          fontWeight: 600,
                          color: '#e2e8f0'
                        }}
                      >
                        {useCase.title}
                      </Typography>
                    </Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: '#94a3b8',
                        lineHeight: 1.6,
                        mb: 2
                      }}
                    >
                      {useCase.description}
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      {useCase.tags.map((tag, tagIndex) => (
                        <Chip
                          key={tagIndex}
                          label={tag}
                          size="small"
                          sx={{
                            background: 'rgba(0, 212, 255, 0.1)',
                            color: '#00d4ff',
                            border: '1px solid rgba(0, 212, 255, 0.3)',
                            fontSize: '0.75rem'
                          }}
                        />
                      ))}
                    </Stack>
                  </CardContent>
                </Card>
              </motion.div>
            </Grid>
          ))}
        </Grid>
      </Container>

      {/* CTA Section */}
      <Container maxWidth="md" sx={{ py: 8 }}>
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          viewport={{ once: true }}
        >
          <Box
            sx={{
              background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.1), rgba(0, 153, 204, 0.1))',
              border: '1px solid rgba(0, 212, 255, 0.3)',
              borderRadius: 4,
              p: 6,
              textAlign: 'center',
              backdropFilter: 'blur(10px)'
            }}
          >
            <Typography
              variant="h3"
              sx={{
                fontFamily: "'Orbitron', monospace",
                fontWeight: 700,
                color: '#e2e8f0',
                mb: 2
              }}
            >
              Ready to Secure Your Digital Infrastructure?
            </Typography>
            <Typography
              variant="body1"
              sx={{
                color: '#94a3b8',
                mb: 4
              }}
            >
              Join thousands of security professionals who trust CyberToolkit for their digital forensics needs.
            </Typography>
            <Stack direction="row" spacing={3} justifyContent="center">
              <Button
                variant="contained"
                size="large"
                onClick={() => navigate('/login')}
                sx={{
                  background: 'linear-gradient(45deg, #00d4ff, #0099cc)',
                  color: '#0f172a',
                  fontFamily: "'Syne', 'Segoe UI', sans-serif",
                  fontWeight: 600,
                  px: 4,
                  py: 1.5,
                  '&:hover': {
                    background: 'linear-gradient(45deg, #0099cc, #00d4ff)',
                    transform: 'translateY(-2px)',
                    boxShadow: '0 10px 25px rgba(0, 212, 255, 0.3)'
                  }
                }}
              >
                Start Free Trial
              </Button>
              <Button
                variant="outlined"
                size="large"
                onClick={() => navigate('/register')}
                sx={{
                  borderColor: '#00d4ff',
                  color: '#00d4ff',
                  fontFamily: '"Syne", "Segoe UI", sans-serif',
                  fontWeight: 600,
                  px: 4,
                  py: 1.5,
                  '&:hover': {
                    borderColor: '#0099cc',
                    background: 'rgba(0, 212, 255, 0.1)',
                    transform: 'translateY(-2px)'
                  }
                }}
              >
                Create Account
              </Button>
            </Stack>
          </Box>
        </motion.div>
      </Container>
    </Box>
  );
};

export default Landing;
