import React, { useState } from 'react';

import axios from 'axios';

const API_BASE_URL = 'http://localhost:3000/api/recovery';

interface RecoveryResult {
  filename: string;
  size: number;
  mime_type: string;
  timestamp: string;
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  signatureMatch?: {
    type: string;
    description: string;
    severity: string;
    algorithm: string;
  };
  suspicious_patterns: Array<{
    type: string;
    description: string;
  }>;
  entropy: number;
  file_analysis: {
    suspicious_features: Array<any>;
    metadata: Record<string, any>;
  };
  risk_score: number;
  threats: Array<{
    type: string;
    severity: string;
    details: any;
  }>;
  recommendation: {
    action: string;
    message: string;
    details: string;
  };
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

  .fr-root {
    font-family: 'Rajdhani', sans-serif;
    background: var(--bg-void);
    color: var(--text-primary);
    padding: 24px;
    max-width: 800px;
    margin: 32px auto;
    border: 1px solid var(--border-dim);
    position: relative;
    overflow: hidden;
  }

  /* Scanline overlay */
  .fr-root::before {
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

  /* Corner brats */
  .fr-root::after {
    content: '';
    position: absolute;
    bottom: -1px; right: -1px;
    width: 20px; height: 20px;
    border-bottom: 2px solid var(--accent-cyan);
    border-right: 2px solid var(--accent-cyan);
    pointer-events: none;
  }

  .fr-corner-tl, .fr-corner-tr, .fr-corner-bl {
    position: absolute;
    width: 20px; height: 20px;
    pointer-events: none;
    z-index: 2;
  }
  .fr-corner-tl { top: -1px; left: -1px; border-top: 2px solid var(--accent-cyan); border-left: 2px solid var(--accent-cyan); }
  .fr-corner-tr { top: -1px; right: -1px; border-top: 2px solid var(--accent-cyan); border-right: 2px solid var(--accent-cyan); }
  .fr-corner-bl { bottom: -1px; left: -1px; border-bottom: 2px solid var(--accent-cyan); border-left: 2px solid var(--accent-cyan); }

  .fr-inner { position: relative; z-index: 1; }

  /* Header */
  .fr-header {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border-dim);
  }

  .fr-header-icon {
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

  .fr-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 16px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2.5px;
    text-shadow: var(--glow-cyan);
  }

  .fr-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-secondary);
    letter-spacing: 1.5px;
    margin-top: 2px;
  }

  .fr-status-badge {
    margin-left: auto;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent-green);
    display: flex; align-items: center; gap: 6px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .fr-status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--accent-green);
    box-shadow: var(--glow-green);
    animation: blink 1.4s step-end infinite;
  }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.15} }

  /* Upload area */
  .fr-upload-area {
    border: 1px dashed rgba(0,200,255,0.25);
    background: var(--bg-card);
    padding: 28px 20px;
    text-align: center;
    margin-bottom: 16px;
    transition: border-color 0.2s, background 0.2s;
    cursor: pointer;
    position: relative;
  }
  .fr-upload-area:hover {
    border-color: var(--accent-cyan);
    background: var(--bg-elevated);
  }
  .fr-upload-area.has-file {
    border-color: rgba(0,255,136,0.3);
    border-style: solid;
  }

  .fr-upload-icon {
    font-size: 32px;
    margin-bottom: 8px;
    opacity: 0.6;
    display: block;
  }

  .fr-upload-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text-secondary);
    letter-spacing: 1.5px;
    text-transform: uppercase;
  }

  .fr-file-name {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: var(--accent-green);
    text-shadow: var(--glow-green);
    letter-spacing: 1px;
    margin-top: 6px;
  }

  .fr-file-input {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
    width: 100%;
    height: 100%;
  }

  /* Action row */
  .fr-actions {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
  }

  .fr-btn {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 2px;
    padding: 10px 20px;
    border: 1px solid;
    background: transparent;
    cursor: pointer;
    transition: all 0.2s;
    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
  }

  .fr-btn-primary {
    border-color: var(--accent-cyan);
    color: var(--accent-cyan);
  }
  .fr-btn-primary:hover:not(:disabled) {
    background: rgba(0,200,255,0.1);
    box-shadow: var(--glow-cyan);
  }

  .fr-btn-scan {
    border-color: var(--accent-green);
    color: var(--accent-green);
    flex: 1;
  }
  .fr-btn-scan:hover:not(:disabled) {
    background: rgba(0,255,136,0.08);
    box-shadow: var(--glow-green);
  }

  .fr-btn:disabled {
    opacity: 0.25;
    cursor: not-allowed;
  }

  /* recovering state */
  .fr-recovering {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    padding: 32px 0;
  }

  .fr-spinner {
    width: 48px; height: 48px;
    border: 2px solid rgba(0,200,255,0.12);
    border-top-color: var(--accent-cyan);
    border-right-color: var(--accent-cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    box-shadow: var(--glow-cyan);
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .fr-recovering-text {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--accent-cyan);
    letter-spacing: 3px;
    text-transform: uppercase;
    animation: flir 1.5s ease-in-out infinite;
  }

  @keyframes flir { 0%,100%{opacity:1} 50%{opacity:0.5} }

  /* Alert banners */
  .fr-alert {
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

  .fr-alert.error   { background: rgba(255,45,45,0.08);  border-color: var(--accent-red);    color: #ff6b6b; }
  .fr-alert.warning { background: rgba(255,140,0,0.08);  border-color: var(--accent-orange);  color: #ffaa44; }
  .fr-alert.success { background: rgba(0,255,136,0.07);  border-color: var(--accent-green);   color: #00ff88; }

  .fr-alert-icon { font-size: 16px; flex-shrink: 0; }

  /* Results section */
  .fr-results-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--accent-cyan);
    text-transform: uppercase;
    letter-spacing: 2.5px;
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border-dim);
    opacity: 0.8;
  }

  /* Risk score bar */
  .fr-risk-block {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 16px;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .fr-risk-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1.5px;
    white-space: nowrap;
    min-width: 80px;
  }

  .fr-risk-bar-wrap {
    flex: 1;
    height: 6px;
    background: rgba(255,255,255,0.05);
    border-radius: 0;
    overflow: hidden;
  }

  .fr-risk-bar-fill {
    height: 100%;
    border-radius: 0;
    transition: width 0.8s ease;
  }

  .fr-risk-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 22px;
    min-width: 60px;
    text-align: right;
    line-height: 1;
  }

  .fr-risk-low    .fr-risk-bar-fill { background: var(--accent-green); }
  .fr-risk-low    .fr-risk-value    { color: var(--accent-green); text-shadow: var(--glow-green); }
  .fr-risk-medium .fr-risk-bar-fill { background: var(--accent-orange); }
  .fr-risk-medium .fr-risk-value    { color: var(--accent-orange); text-shadow: var(--glow-orange); }
  .fr-risk-high   .fr-risk-bar-fill { background: var(--accent-red); box-shadow: var(--glow-red); }
  .fr-risk-high   .fr-risk-value    { color: var(--accent-red); text-shadow: var(--glow-red); }

  /* Info grid */
  .fr-info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 12px;
  }

  .fr-info-card {
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    padding: 12px 14px;
    clip-path: polygon(0 0, calc(100% - 6px) 0, 100% 6px, 100% 100%, 6px 100%, 0 calc(100% - 6px));
  }

  .fr-info-card-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 6px;
  }

  .fr-info-card-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    color: var(--text-primary);
    word-break: break-all;
    line-height: 1.5;
  }

  .fr-info-card-value.mono-small {
    font-size: 10px;
    color: var(--text-secondary);
    line-height: 1.8;
  }

  /* Signature match */
  .fr-sig-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(255,45,45,0.1);
    border: 1px solid rgba(255,45,45,0.4);
    color: #ff6b6b;
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    padding: 3px 8px;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 6px;
  }

  /* Threats list */
  .fr-threats {
    background: var(--bg-card);
    border: 1px solid rgba(255,45,45,0.2);
    margin-bottom: 12px;
  }

  .fr-threats-header {
    padding: 10px 14px;
    background: rgba(255,45,45,0.07);
    border-bottom: 1px solid rgba(255,45,45,0.15);
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: #ff6b6b;
    text-transform: uppercase;
    letter-spacing: 2px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .fr-threat-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    border-bottom: 1px solid rgba(255,45,45,0.08);
  }
  .fr-threat-item:last-child { border-bottom: none; }

  .fr-threat-type {
    font-family: 'Rajdhani', sans-serif;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .fr-severity-pill {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    padding: 2px 8px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-radius: 2px;
  }
  .fr-severity-high     { background: rgba(255,45,45,0.15);  color:#ff2d2d; border:1px solid rgba(255,45,45,0.4); }
  .fr-severity-medium   { background: rgba(255,140,0,0.15);  color:#ff8c00; border:1px solid rgba(255,140,0,0.4); }
  .fr-severity-low      { background: rgba(0,255,136,0.10);  color:#00ff88; border:1px solid rgba(0,255,136,0.3); }
  .fr-severity-critical { background: rgba(255,0,80,0.18);   color:#ff0050; border:1px solid rgba(255,0,80,0.5); box-shadow: 0 0 8px rgba(255,0,80,0.3); }
`;

const FileRecovery: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [recovering, setRecovering] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string>('');

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setFile(event.target.files[0]);
      setError('');
      setResult(null);
    }
  };







  const alertIcons: Record<string, string> = { error: '⛔', warning: '⚠', success: '✔' };

  const renderRecoveryResult = (result: any) => (
    <div>
      <div className="fr-results-header">⊞ Scan Results</div>

      {result.recommendation && (() => {
        const type = getAlertType(result.recommendation.action);
        return (
          <div className={`fr-alert ${type}`}>
            <span className="fr-alert-icon">{alertIcons[type]}</span>
            {result.recommendation.message}
          </div>
        );
      })()}

      {/* Risk Score */}
      <div className={`fr-risk-block ${getRiskClass(result.risk_score)}`}>
        <div className="fr-risk-label">Risk Score</div>
        <div className="fr-risk-bar-wrap">
          <div className="fr-risk-bar-fill" style={{ width: `${result.risk_score}%` }} />
        </div>
        <div className="fr-risk-value">{result.risk_score}<span style={{ fontSize: 11, opacity: 0.5 }}>/100</span></div>
      </div>

      {/* File info + hashes */}
      <div className="fr-info-grid">
        <div className="fr-info-card">
          <div className="fr-info-card-label">File Information</div>
          <div className="fr-info-card-value">{result.filename}</div>
          <div className="fr-info-card-value mono-small">{result.size.toLocaleString()} bytes</div>
        </div>
        <div className="fr-info-card">
          <div className="fr-info-card-label">File Hashes</div>
          <div className="fr-info-card-value mono-small">
            MD5: {result.hashes.md5}<br />
            SHA1: {result.hashes.sha1}<br />
            SHA256: {result.hashes.sha256}
          </div>
        </div>
      </div>

      {/* Signature match */}
      {result.signatureMatch && (
        <div className="fr-info-card" style={{ marginBottom: 12 }}>
          <div className="fr-info-card-label">Signature Match</div>
          <div style={{ marginTop: 6 }}>
            <span className="fr-sig-badge">⊗ {result.signatureMatch.type}</span>
          </div>
          <div className="fr-info-card-value" style={{ marginTop: 4 }}>
            {result.signatureMatch.description}
          </div>
        </div>
      )}

      {/* Threats */}
      {result.threats.length > 0 && (
        <div className="fr-threats">
          <div className="fr-threats-header">
            ⊗ Detected Threats
            <span style={{ marginLeft: 'auto', background: 'rgba(255,45,45,0.2)', padding: '1px 7px', borderRadius: 2 }}>
              {result.threats.length}
            </span>
          </div>
          {result.threats.map((threat, index) => (
            <div className="fr-threat-item" key={index}>
              <div className="fr-threat-type">{threat.type}</div>
              <span className={`fr-severity-pill ${getSeverityClass(threat.severity)}`}>
                {threat.severity}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <>
      <style>{styles}</style>
      <div className="fr-root">
        <div className="fr-corner-tl" />
        <div className="fr-corner-tr" />
        <div className="fr-corner-bl" />

        <div className="fr-inner">
          {/* Header */}
          <div className="fr-header">
            <div className="fr-header-icon">⊗</div>
            <div>
              <div className="fr-title">File Recovery</div>
              <div className="fr-subtitle">// Data Reconstruction Engine v2.0</div>
            </div>
            <div className="fr-status-badge">
              <span className="fr-status-dot" />
              Recoveryadow
            </div>
          </div>

          {/* Upload area */}
          <div className={`fr-upload-area ${file ? 'has-file' : ''}`}>
            <input
              type="file"
              className="fr-file-input"
              onChange={handleFileChange}
              disabled={recovering}
            />
            <span className="fr-upload-icon">{file ? '📄' : '⬆'}</span>
            {file ? (
              <div className="fr-file-name">⊕ {file.name}</div>
            ) : (
              <div className="fr-upload-text">Drop corrupted file here or click to select</div>
            )}
          </div>

          {/* Actions */}
          <div className="fr-actions">
            <button
              className="fr-btn fr-btn-primary"
              onClick={handleRecovery}
              disabled={!file || recovering}
            >
              {recovering ? '⟳  recovering...' : '⊗  Scan File'}
            </button>
          </div>

          {/* recovering animation */}
          {recovering && (
            <div className="fr-recovering">
              <div className="fr-spinner" />
              <div className="fr-recovering-text">Analyzing file...</div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="fr-alert error">
              <span className="fr-alert-icon">⛔</span>
              {error}
            </div>
          )}

          {/* Results */}
          {result && renderRecoveryResult(result)}
        </div>
      </div>
    </>
  );
};

export default FileRecovery;














