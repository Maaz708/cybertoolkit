import React, { useState } from 'react';
import axios from 'axios';

interface EmailAnalysis {
  success: boolean;
  message: string;
  summary: {
    riskLevel: string;
    securityScore: number;
    totalAttachments: number;
    suspiciousItemsFound: number;
  };
  emailDetails: {
    sender: string;
    subject: string;
    recipients: string;
    receivedDate: string;
    size: string;
  };
  securityCheck: {
    spfProtection: {
      status: boolean;
      description: string;
    };
    dmarcProtection: {
      status: boolean;
      description: string;
    };
    returnPath: {
      status: boolean;
      description: string;
    };
    suspiciousLinks: {
      count: number;
      items: string[];
    };
    suspiciousAttachments: {
      count: number;
      items: string[];
    };
  };
  attachments: Array<{
    name: string;
    type: string;
    size: string;
    safety: string;
  }>;
  recommendations: Array<{
    priority: string;
    title: string;
    description: string;
  }>;
  analyzedAt: string;
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
    --accent-yellow: #ffe600;
    --text-primary: #c8eaf5;
    --text-secondary: #5a8a9f;
    --text-mono: #00c8ff;
    --glow-cyan: 0 0 12px rgba(0,200,255,0.5);
    --glow-red: 0 0 14px rgba(255,45,45,0.6);
    --glow-green: 0 0 12px rgba(0,255,136,0.5);
    --glow-orange: 0 0 12px rgba(255,140,0,0.5);
  }

  .ef-root {
    font-family: 'Rajdhani', sans-serif;
    background: var(--bg-void);
    color: var(--text-primary);
    padding: 24px;
    max-width: 900px;
    margin: 32px auto;
    border: 1px solid var(--border-dim);
    position: relative;
    overflow: hidden;
  }

  /* Scanline overlay */
  .ef-root::before {
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      to bottom,
      transparent 0px, transparent 3px,
      rgba(0,0,0,0.06) 3px, rgba(0,0,0,0.06) 4px
    );
    pointer-events: none;
    z-index: 0;
  }

  /* Corner brackets */
  .ef-root::after {
    content: '';
    position: absolute;
    bottom: -1px; right: -1px;
    width: 20px; height: 20px;
    border-bottom: 2px solid var(--accent-cyan);
    border-right: 2px solid var(--accent-cyan);
    pointer-events: none;
  }

  .ef-corner-tl, .ef-corner-tr, .ef-corner-bl {
    position: absolute;
    width: 20px; height: 20px;
    pointer-events: none;
    z-index: 2;
  }
  .ef-corner-tl { top: -1px; left: -1px; border-top: 2px solid var(--accent-cyan); border-left: 2px solid var(--accent-cyan); }
  .ef-corner-tr { top: -1px; right: -1px; border-top: 2px solid var(--accent-cyan); border-right: 2px solid var(--accent-cyan); }
  .ef-corner-bl { bottom: -1px; left: -1px; border-bottom: 2px solid var(--accent-cyan); border-left: 2px solid var(--accent-cyan); }

  .ef-inner { position: relative; z-index: 1; }

  /* Header */
  .ef-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border-dim);
  }

  .ef-header-icon {
    width: 42px; height: 42px;
    border: 1px solid var(--accent-cyan);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    color: var(--accent-cyan);
    flex-shrink: 0;
    animation: pulse-ring 3s ease-in-out infinite;
  }

  @keyframes pulse-ring {
    0%,100% { box-shadow: 0 0 8px rgba(0,200,255,0.4); }
    50%      { box-shadow: 0 0 22px rgba(0,200,255,0.9); }
  }

  .ef-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 16px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2.5px;
    text-shadow: var(--glow-cyan);
  }

  .ef-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-secondary);
    letter-spacing: 1.5px;
    margin-top: 2px;
  }

  .ef-status-badge {
    margin-left: auto;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-green);
    display: flex; align-items: center; gap: 6px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .ef-status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent-green);
    box-shadow: var(--glow-green);
    animation: blink 1.4s step-end infinite;
  }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.15} }

  /* Upload area */
  .ef-upload-area {
    border: 1px dashed rgba(0,200,255,0.25);
    background: var(--bg-card);
    padding: 28px 20px;
    text-align: center;
    margin-bottom: 20px;
    transition: border-color 0.2s, background 0.2s;
    cursor: pointer;
    position: relative;
  }
  .ef-upload-area:hover {
    border-color: var(--accent-cyan);
    background: var(--bg-elevated);
  }

  .ef-upload-icon {
    font-size: 32px;
    margin-bottom: 8px;
    opacity: 0.6;
    display: block;
  }

  .ef-upload-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text-secondary);
    letter-spacing: 1.5px;
    text-transform: uppercase;
  }

  .ef-file-input {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
    width: 100%;
    height: 100%;
  }

  /* Analyzing state */
  .ef-analyzing {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    padding: 32px 0;
  }

  .ef-spinner {
    width: 48px; height: 48px;
    border: 2px solid rgba(0,200,255,0.12);
    border-top-color: var(--accent-cyan);
    border-right-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    box-shadow: var(--glow-cyan);
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .ef-analyzing-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--accent-cyan);
    letter-spacing: 3px;
    text-transform: uppercase;
    animation: flicker 1.5s ease-in-out infinite;
  }

  @keyframes flicker { 0%,100%{opacity:1} 50%{opacity:0.5} }

  /* Alert banners */
  .ef-alert {
    padding: 12px 16px;
    margin-bottom: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    letter-spacing: 1px;
    display: flex;
    align-items: center;
    gap: 10px;
    border-left: 3px solid;
  }

  .ef-alert.error   { background: rgba(255,45,45,0.08);  border-color: var(--accent-red);    color: #ff6b6b; }
  .ef-alert.warning { background: rgba(255,140,0,0.08);  border-color: var(--accent-orange);  color: #ffaa44; }
  .ef-alert.success { background: rgba(0,255,136,0.07);  border-color: var(--accent-green);   color: #00ff88; }

  .ef-alert-icon { font-size: 16px; flex-shrink: 0; }

  /* Section headers */
  .ef-section-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2.5px;
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border-dim);
    opacity: 0.8;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* Stats grid */
  .ef-stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 20px;
  }

  .ef-stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-top-width: 2px;
    padding: 12px 10px;
    text-align: center;
    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
    transition: border-color 0.2s;
  }
  .ef-stat-card:hover { background: var(--bg-elevated); }

  .ef-stat-card.score    { border-top-color: var(--accent-cyan); }
  .ef-stat-card.risk     { border-top-color: var(--accent-orange); }
  .ef-stat-card.attach   { border-top-color: var(--accent-green); }
  .ef-stat-card.threat   { border-top-color: var(--accent-red); }

  .ef-stat-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 24px;
    line-height: 1;
    margin-bottom: 4px;
  }

  .ef-stat-card.score .ef-stat-value { color: var(--accent-cyan);   text-shadow: var(--glow-cyan); }
  .ef-stat-card.risk .ef-stat-value  { color: var(--accent-orange); text-shadow: var(--glow-orange); }
  .ef-stat-card.attach .ef-stat-value { color: var(--accent-green);  text-shadow: var(--glow-green); }
  .ef-stat-card.threat .ef-stat-value { color: var(--accent-red);    text-shadow: var(--glow-red); }

  .ef-stat-label {
    font-size: 10px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-family: 'Share Tech Mono', monospace;
  }

  /* Info cards */
  .ef-info-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 14px 16px;
    margin-bottom: 12px;
    clip-path: polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 6px 100%, 0 calc(100% - 6px));
  }

  .ef-info-card-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 6px;
  }

  .ef-info-card-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text-primary);
    word-break: break-all;
    line-height: 1.5;
  }

  /* Security checks grid */
  .ef-security-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin-bottom: 16px;
  }

  .ef-security-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 12px 14px;
    position: relative;
  }

  .ef-security-status {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }

  .ef-security-icon {
    width: 16px; height: 16px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .ef-security-icon.valid { background: var(--accent-green); box-shadow: var(--glow-green); }
  .ef-security-icon.invalid { background: var(--accent-red); box-shadow: var(--glow-red); }

  .ef-security-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .ef-security-desc {
    font-family: 'Rajdhani', sans-serif;
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  /* Threat detection */
  .ef-threat-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 16px;
  }

  .ef-threat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 12px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .ef-threat-info {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ef-threat-icon {
    font-size: 16px;
    flex-shrink: 0;
  }

  .ef-threat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .ef-threat-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 2px 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-radius: 2px;
  }
  .ef-threat-badge.warn { background: rgba(255,140,0,0.15); color: var(--accent-orange); border: 1px solid rgba(255,140,0,0.4); }
  .ef-threat-safe { background: rgba(0,255,136,0.10); color: var(--accent-green); border: 1px solid rgba(0,255,136,0.3); }

  /* Attachments list */
  .ef-attachments {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    margin-bottom: 12px;
  }

  .ef-attachments-header {
    padding: 10px 14px;
    background: rgba(0,200,255,0.07);
    border-bottom: 1px solid rgba(0,200,255,0.15);
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ef-attachment-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid rgba(0,200,255,0.08);
  }
  .ef-attachment-item:last-child { border-bottom: none; }

  .ef-attachment-name {
    font-family: 'Rajdhani', sans-serif;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
  }

  .ef-attachment-meta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-secondary);
    margin-left: 10px;
  }

  .ef-attachment-safety {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 2px 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-radius: 2px;
    margin-left: 8px;
  }
  .ef-attachment-safety.safe { background: rgba(0,255,136,0.10); color: var(--accent-green); border: 1px solid rgba(0,255,136,0.3); }
  .ef-attachment-safety.suspicious { background: rgba(255,140,0,0.15); color: var(--accent-orange); border: 1px solid rgba(255,140,0,0.4); }
  .ef-attachment-safety.dangerous { background: rgba(255,45,45,0.15); color: var(--accent-red); border: 1px solid rgba(255,45,45,0.4); }

  /* Recommendations */
  .ef-recommendations {
    background: var(--bg-card);
    border: 1px solid rgba(255,140,0,0.2);
  }

  .ef-recommendations-header {
    padding: 10px 14px;
    background: rgba(255,140,0,0.07);
    border-bottom: 1px solid rgba(255,140,0,0.15);
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-orange);
    text-transform: uppercase;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .ef-recommendation-item {
    padding: 12px 14px;
    border-bottom: 1px solid rgba(255,140,0,0.08);
  }
  .ef-recommendation-item:last-child { border-bottom: none; }

  .ef-recommendation-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }

  .ef-recommendation-title {
    font-family: 'Rajdhani', sans-serif;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .ef-priority-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 2px 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-radius: 2px;
  }
  .ef-priority-high   { background: rgba(255,45,45,0.15);  color: var(--accent-red);    border: 1px solid rgba(255,45,45,0.4); }
  .ef-priority-medium { background: rgba(255,140,0,0.15);  color: var(--accent-orange); border: 1px solid rgba(255,140,0,0.4); }
  .ef-priority-low    { background: rgba(0,255,136,0.10);  color: var(--accent-green);  border: 1px solid rgba(0,255,136,0.3); }

  .ef-recommendation-desc {
    font-family: 'Rajdhani', sans-serif;
    font-size: 11px;
    color: var(--text-secondary);
    line-height: 1.5;
  }

  .ef-attachment-safety.safe {
    color: #3e8e41;
  }

  .ef-attachment-safety.suspicious {
    color: #ff9800;
  }

  .ef-attachment-safety.dangerous {
    color: #e51c23;
  }
`;

const EmailForensics: React.FC = () => {
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);

  const handleEmailAnalysis = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    const formData = new FormData();
    formData.append('email', file);

    setAnalyzing(true);
    setError(null);

    try {
      const response = await axios.post('/api/email/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setAnalysis(response.data);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const getRiskClass = (riskLevel: string) => {
    if (!riskLevel) return 'ef-risk-unknown';
    switch (riskLevel.toLowerCase()) {
      case 'low risk': return 'ef-risk-low';
      case 'medium risk': return 'ef-risk-medium';
      case 'high risk': return 'ef-risk-high';
      default: return 'ef-risk-unknown';
    }
  };

  const getPriorityClass = (priority: string) => {
    if (!priority) return 'ef-priority-low';
    switch (priority.toLowerCase()) {
      case 'high': return 'ef-priority-high';
      case 'medium': return 'ef-priority-medium';
      case 'low': return 'ef-priority-low';
      default: return 'ef-priority-low';
    }
  };

  const getSafetyClass = (safety: string) => {
    if (!safety) return 'ef-attachment-safety.suspicious';
    switch (safety.toLowerCase()) {
      case 'safe': return 'ef-attachment-safety.safe';
      case 'suspicious': return 'ef-attachment-safety.suspicious';
      case 'dangerous': return 'ef-attachment-safety.dangerous';
      default: return 'ef-attachment-safety.suspicious';
    }
  };

  return (
    <>
      <style>{styles}</style>
      <div className="ef-root">
        <div className="ef-corner-tl" />
        <div className="ef-corner-tr" />
        <div className="ef-corner-bl" />

        <div className="ef-inner">
          {/* Header */}
          <div className="ef-header">
            <div className="ef-header-icon">✉</div>
            <div>
              <div className="ef-title">Email Forensics</div>
              <div className="ef-subtitle">// Advanced Email Analysis Engine</div>
            </div>
            <div className="ef-status-badge">
              <span className="ef-status-dot" />
              SystemLive
            </div>
          </div>

          {/* Upload area */}
          <div className="ef-upload-area">
            <input
              type="file"
              className="ef-file-input"
              onChange={handleEmailAnalysis}
              disabled={analyzing}
              accept=".eml,.msg"
            />
            <span className="ef-upload-icon">📧</span>
            <div className="ef-upload-text">Drop email file here or click to select</div>
          </div>

          {/* Analyzing animation */}
          {analyzing && (
            <div className="ef-analyzing">
              <div className="ef-spinner" />
              <div className="ef-analyzing-text">Analyzing email headers and content...</div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="ef-alert error">
              <span className="ef-alert-icon">⛔</span>
              {error}
            </div>
          )}

          {/* Analysis Results */}
          {analysis && !analyzing && (
            <div>
              {/* Stats Overview */}
              <div className="ef-stats-grid">
                <div className="ef-stat-card score">
                  <div className="ef-stat-value">{analysis.summary?.securityScore || 0}</div>
                  <div className="ef-stat-label">Security Score</div>
                </div>
                <div className="ef-stat-card risk">
                  <div className="ef-stat-value">{analysis.summary?.riskLevel || 'Unknown'}</div>
                  <div className="ef-stat-label">Risk Level</div>
                </div>
                <div className="ef-stat-card attach">
                  <div className="ef-stat-value">{analysis.summary?.totalAttachments || 0}</div>
                  <div className="ef-stat-label">Attachments</div>
                </div>
                <div className="ef-stat-card threat">
                  <div className="ef-stat-value">{analysis.summary?.suspiciousItemsFound || 0}</div>
                  <div className="ef-stat-label">Threats Found</div>
                </div>
              </div>

              {/* Email Details */}
              <div className="ef-section-header">✉ Email Details</div>
              <div className="ef-info-card">
                <div className="ef-info-card-label">Sender</div>
                <div className="ef-info-card-value">{analysis.emailDetails?.sender || 'Unknown'}</div>
              </div>
              <div className="ef-info-card">
                <div className="ef-info-card-label">Subject</div>
                <div className="ef-info-card-value">{analysis.emailDetails?.subject || 'No Subject'}</div>
              </div>
              <div className="ef-info-card">
                <div className="ef-info-card-label">Recipients</div>
                <div className="ef-info-card-value">{analysis.emailDetails?.recipients || 'Unknown'}</div>
              </div>
              <div className="ef-info-card">
                <div className="ef-info-card-label">Received Date</div>
                <div className="ef-info-card-value">{analysis.emailDetails?.receivedDate || 'Unknown'}</div>
              </div>
              <div className="ef-info-card">
                <div className="ef-info-card-label">Email Size</div>
                <div className="ef-info-card-value">{analysis.emailDetails?.size || 'Unknown'}</div>
              </div>

              {/* Security Check */}
              <div className="ef-section-header">🛡️ Security Verification</div>
              <div className="ef-security-grid">
                <div className="ef-security-card">
                  <div className="ef-security-status">
                    <div className={`ef-security-icon ${analysis.securityCheck?.spfProtection?.status ? 'valid' : 'invalid'}`} />
                    <div className="ef-security-title">SPF Protection</div>
                  </div>
                  <div className="ef-security-desc">
                    {analysis.securityCheck?.spfProtection?.description || 'No SPF information available'}
                  </div>
                </div>
                <div className="ef-security-card">
                  <div className="ef-security-status">
                    <div className={`ef-security-icon ${analysis.securityCheck?.dmarcProtection?.status ? 'valid' : 'invalid'}`} />
                    <div className="ef-security-title">DMARC Protection</div>
                  </div>
                  <div className="ef-security-desc">
                    {analysis.securityCheck?.dmarcProtection?.description || 'No DMARC information available'}
                  </div>
                </div>
                <div className="ef-security-card">
                  <div className="ef-security-status">
                    <div className={`ef-security-icon ${analysis.securityCheck?.returnPath?.status ? 'valid' : 'invalid'}`} />
                    <div className="ef-security-title">Return Path</div>
                  </div>
                  <div className="ef-security-desc">
                    {analysis.securityCheck?.returnPath?.description || 'No return path information available'}
                  </div>
                </div>
              </div>

              {/* Threat Detection */}
              <div className="ef-section-header">⚠️ Threat Detection</div>
              <div className="ef-threat-grid">
                <div className="ef-threat-card">
                  <div className="ef-threat-info">
                    <span className="ef-threat-icon">🔗</span>
                    <span className="ef-threat-label">Suspicious Links</span>
                  </div>
                  <span className={`ef-threat-badge ${analysis.securityCheck?.suspiciousLinks?.count > 0 ? 'warn' : 'safe'}`}>
                    {analysis.securityCheck?.suspiciousLinks?.count || 0} found
                  </span>
                </div>
                <div className="ef-threat-card">
                  <div className="ef-threat-info">
                    <span className="ef-threat-icon">📎</span>
                    <span className="ef-threat-label">Suspicious Attachments</span>
                  </div>
                  <span className={`ef-threat-badge ${analysis.securityCheck?.suspiciousAttachments?.count > 0 ? 'warn' : 'safe'}`}>
                    {analysis.securityCheck?.suspiciousAttachments?.count || 0} found
                  </span>
                </div>
              </div>

              {/* Attachments */}
              {analysis.attachments && analysis.attachments.length > 0 && (
                <>
                  <div className="ef-section-header">📎 Attachments ({analysis.attachments.length})</div>
                  <div className="ef-attachments">
                    <div className="ef-attachments-header">
                      📎 File Attachments
                      <span style={{ marginLeft: 'auto', background: 'rgba(0,200,255,0.2)', padding: '1px 7px', borderRadius: 2 }}>
                        {analysis.attachments.length}
                      </span>
                    </div>
                    {analysis.attachments.map((attachment, index) => (
                      <div className="ef-attachment-item" key={index}>
                        <div className="ef-attachment-name">{attachment.name || 'Unknown'}</div>
                        <div className="ef-attachment-meta">{attachment.type || 'Unknown'} • {attachment.size || 'Unknown'}</div>
                        <span className={getSafetyClass(attachment.safety)}>
                          {attachment.safety || 'Unknown'}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              )}

              {/* Recommendations */}
              <div className="ef-section-header">🚨 Security Recommendations</div>
              <div className="ef-recommendations">
                <div className="ef-recommendations-header">
                  🚨 Recommended Actions
                  <span style={{ marginLeft: 'auto', background: 'rgba(255,140,0,0.2)', padding: '1px 7px', borderRadius: 2 }}>
                    {analysis.recommendations?.length || 0}
                  </span>
                </div>
                {(analysis.recommendations || []).map((rec, index) => (
                  <div className="ef-recommendation-item" key={index}>
                    <div className="ef-recommendation-header">
                      <span className={`ef-priority-badge ${getPriorityClass(rec.priority)}`}>
                        {(rec.priority || 'low').toUpperCase()}
                      </span>
                      <div className="ef-recommendation-title">{rec.title || 'No Title'}</div>
                    </div>
                    <div className="ef-recommendation-desc">
                      {rec.description || 'No description available'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

export default EmailForensics;