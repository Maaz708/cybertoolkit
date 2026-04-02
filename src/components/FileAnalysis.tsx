import React, { useState } from 'react';
import {
  Upload,
  Description,
  Security,
  Code,
  Assessment,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Fingerprint,
  Shield,
  BarChart,
  Link,
  ContentCopy,
  FolderOpen,
  BugReport,
} from '@mui/icons-material';
import { CircularProgress, Alert } from '@mui/material';
import axios from 'axios';

interface FileAnalysisResult {
  file_info: {
    filename: string;
    size: number;
    mimeType: string;
    lastModified: string;
    analyzedAt: string;
  };
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  entropy_analysis: {
    entropy: number;
    classification: {
      level: string;
      risk: string;
      description: string;
    };
  };
  pattern_analysis: {
    total: number;
    highRisk: Array<any>;
    mediumRisk: Array<any>;
    lowRisk: Array<any>;
  };
  file_type_validation: {
    detectedMimeType: string;
    isValid: boolean;
    risk: string;
    description: string;
  };
  url_analysis: {
    total: number;
    flagged: Array<any>;
  };
  metadata: any;
  risk_score: {
    score: number;
    riskLevel: {
      level: string;
      color: string;
      description: string;
    };
  };
  verdict: {
    level: string;
    risk: string;
    description: string;
  };
  recommendations: Array<any>;
  summary: {
    riskScore: number;
    riskLevel: string;
    totalFindings: number;
    highRiskFindings: number;
    fileCategory: string;
  };
  timestamp: string;
}

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const getRiskColor = (risk: string) => {
  const r = (risk || '').toLowerCase();
  if (r === 'critical' || r === 'high') return '#ff4d6d';
  if (r === 'medium' || r === 'moderate') return '#fbbf24';
  if (r === 'low' || r === 'safe') return '#00ff88';
  return '#00d4ff';
};

const getRiskBg = (risk: string) => {
  const r = (risk || '').toLowerCase();
  if (r === 'critical' || r === 'high') return 'rgba(255,77,109,0.1)';
  if (r === 'medium' || r === 'moderate') return 'rgba(251,191,36,0.1)';
  if (r === 'low' || r === 'safe') return 'rgba(0,255,136,0.1)';
  return 'rgba(0,212,255,0.1)';
};

const ScoreRing = ({ score }: { score: number }) => {
  const r = 42, circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score > 70 ? '#00ff88' : score > 40 ? '#fbbf24' : '#ff4d6d';
  return (
    <div style={{ position: 'relative', width: 110, height: 110, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <svg width="110" height="110" style={{ position: 'absolute', transform: 'rotate(-90deg)' }}>
        <circle cx="55" cy="55" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle cx="55" cy="55" r={r} fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${color})`, transition: 'stroke-dashoffset 1.2s ease' }} />
      </svg>
      <div style={{ textAlign: 'center', zIndex: 1 }}>
        <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 22, fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: 9, color: '#64748b', letterSpacing: 2, marginTop: 3 }}>RISK</div>
      </div>
    </div>
  );
};

const InfoRow = ({ label, value, mono = false, copyable = false }: { label: string; value: string; mono?: boolean; copyable?: boolean }) => {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
      padding: '11px 0', borderBottom: '1px solid rgba(255,255,255,0.04)', gap: 12,
    }}>
      <span style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, flexShrink: 0, paddingTop: 2 }}>{label.toUpperCase()}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <span style={{
          fontSize: mono ? 11 : 13, color: '#cbd5e1', fontFamily: mono ? "'Courier New', monospace" : 'inherit',
          wordBreak: 'break-all', textAlign: 'right',
          background: mono ? 'rgba(0,212,255,0.06)' : 'transparent',
          padding: mono ? '3px 8px' : '0', borderRadius: mono ? 6 : 0,
        }}>{value}</span>
        {copyable && (
          <button onClick={handleCopy} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, flexShrink: 0 }}>
            <ContentCopy style={{ fontSize: 13, color: copied ? '#00ff88' : '#334155' }} />
          </button>
        )}
      </div>
    </div>
  );
};

const SectionCard = ({ icon: Icon, title, color = '#00d4ff', children }: any) => (
  <div style={{
    background: 'linear-gradient(135deg, #0f1521 0%, #131a2a 100%)',
    border: '1px solid rgba(255,255,255,0.06)',
    borderRadius: 16, overflow: 'hidden',
    boxShadow: '0 4px 24px rgba(0,0,0,0.3)',
    animation: 'fadeInUp 0.5s ease forwards',
  }}>
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />
    </div>
    <div style={{ padding: '20px 22px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <div style={{ width: 34, height: 34, borderRadius: 9, background: `rgba(${color === '#00d4ff' ? '0,212,255' : color === '#00ff88' ? '0,255,136' : color === '#a78bfa' ? '167,139,250' : color === '#fbbf24' ? '251,191,36' : '255,77,109'},0.12)`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon style={{ color, fontSize: 18 }} />
        </div>
        <span style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0', letterSpacing: 0.3 }}>{title}</span>
      </div>
      {children}
    </div>
  </div>
);

const FileAnalysis = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [error, setError] = useState<string>('');
  const [dragOver, setDragOver] = useState(false);

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files[0]) {
      setFile(files[0]);
      await analyzeFile(files[0]);
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) { setFile(dropped); await analyzeFile(dropped); }
  };

  const analyzeFile = async (fileToAnalyze: File) => {
    setAnalyzing(true);
    setError('');
    setResult(null);
    const formData = new FormData();
    formData.append('file', fileToAnalyze);
    try {
      const response = await axios.post('/api/files/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      if (response.data.success) {
        setResult(response.data);
      } else {
        throw new Error(response.data.message || 'Analysis failed');
      }
    } catch (err: any) {
      console.error('Analysis error:', err);
      setError(err.message || 'Failed to analyze file');
    } finally {
      setAnalyzing(false);
    }
  };

  const verdictColor = result?.verdict?.risk ? getRiskColor(result.verdict.risk) : '#00d4ff';
  const verdictBg = result?.verdict ? 'rgba(0,212,255,0.1)' : 'transparent';

  console.log('FileAnalysis rendering');

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 36, animation: 'fadeInUp 0.5s ease' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
            <div style={{ width: 42, height: 42, borderRadius: 12, background: 'linear-gradient(135deg, #0066ff, #00d4ff)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Fingerprint style={{ color: '#fff', fontSize: 22 }} />
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#00d4ff', letterSpacing: 4, fontWeight: 600 }}>FORENSIC MODULE</div>
              <h1 style={{ fontFamily: "'Orbitron', monospace", fontSize: 'clamp(18px, 3vw, 26px)', fontWeight: 900, color: '#f1f5f9', lineHeight: 1.1 }}>
                File <span style={{ color: '#00d4ff' }}>Analysis</span>
              </h1>
            </div>
          </div>
          <p style={{ fontSize: 13, color: '#475569', maxWidth: 480, lineHeight: 1.6 }}>
            Deep forensic inspection — hashes, entropy, pattern detection, file type validation and threat scoring.
          </p>
        </div>

        {/* Error */}
        {error && (
          <div style={{ marginBottom: 24, padding: '14px 18px', borderRadius: 12, background: 'rgba(255,77,109,0.1)', border: '1px solid rgba(255,77,109,0.3)', display: 'flex', alignItems: 'center', gap: 10, animation: 'fadeInUp 0.3s ease' }}>
            <ErrorIcon style={{ color: '#ff4d6d', fontSize: 18 }} />
            <span style={{ fontSize: 13, color: '#ff4d6d' }}>{error}</span>
          </div>
        )}

        {/* Upload Zone */}
        <label htmlFor="file-upload" style={{ display: 'block', marginBottom: 32, cursor: analyzing ? 'not-allowed' : 'pointer' }}>
          <div
            className="upload-zone"
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            style={{
              border: `2px dashed ${dragOver ? 'rgba(0,212,255,0.7)' : 'rgba(255,255,255,0.1)'}`,
              borderRadius: 18,
              padding: '40px 24px',
              textAlign: 'center',
              background: dragOver ? 'rgba(0,212,255,0.06)' : 'rgba(15,21,33,0.8)',
              position: 'relative',
              overflow: 'hidden',
              animation: 'fadeInUp 0.4s ease',
            }}>
            {/* Scanline effect */}
            {analyzing && (
              <div style={{ position: 'absolute', left: 0, right: 0, height: 2, background: 'linear-gradient(90deg, transparent, #00d4ff, transparent)', animation: 'scanline 1.5s linear infinite', zIndex: 2 }} />
            )}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
              {analyzing ? (
                <>
                  <div style={{ width: 56, height: 56, borderRadius: '50%', border: '3px solid rgba(0,212,255,0.2)', borderTopColor: '#00d4ff', animation: 'spin 1s linear infinite' }} />
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>Analyzing File...</div>
                    <div style={{ fontSize: 12, color: '#475569' }}>Running deep forensic inspection</div>
                  </div>
                </>
              ) : (
                <>
                  <div style={{ width: 60, height: 60, borderRadius: 16, background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {file ? <Description style={{ color: '#00d4ff', fontSize: 28 }} /> : <Upload style={{ color: '#00d4ff', fontSize: 28 }} />}
                  </div>
                  <div>
                    {file ? (
                      <>
                        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>{file.name}</div>
                        <div style={{ fontSize: 12, color: '#00d4ff', fontWeight: 600 }}>{formatBytes(file.size)} · Click to replace</div>
                      </>
                    ) : (
                      <>
                        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>Drop file here or click to browse</div>
                        <div style={{ fontSize: 12, color: '#475569' }}>Supports all file types · Max 100MB</div>
                      </>
                    )}
                  </div>
                  <div style={{ padding: '10px 28px', borderRadius: 10, background: 'linear-gradient(135deg, #0066ff, #00d4ff)', fontSize: 13, fontWeight: 700, color: '#fff', letterSpacing: 1 }}>
                    {file ? 'REPLACE FILE' : 'SELECT FILE'}
                  </div>
                </>
              )}
            </div>
            <input id="file-upload" type="file" hidden onChange={handleFileChange} disabled={analyzing} />
          </div>
        </label>

        {/* Results */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20, animation: 'fadeInUp 0.5s ease' }}>

            {/* Verdict Banner */}
            <div style={{
              borderRadius: 16, padding: '20px 24px',
              background: verdictBg,
              border: `1px solid ${verdictColor}30`,
              boxShadow: `0 0 30px ${verdictColor}10`,
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 20, flexWrap: 'wrap',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <ScoreRing score={result?.risk_score?.score || 0} />
                <div>
                  <div style={{ fontSize: 10, color: '#475569', letterSpacing: 3, marginBottom: 6 }}>VERDICT</div>
                  <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 'clamp(18px, 3vw, 24px)', fontWeight: 900, color: verdictColor }}>{result?.verdict?.level || 'Unknown'}</div>
                  <div style={{ fontSize: 12, color: '#64748b', marginTop: 4, maxWidth: 320 }}>{result?.verdict?.description || ''}</div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {[
                  { label: 'Total Findings', val: result?.summary?.totalFindings || 0 },
                  { label: 'High Risk', val: result?.summary?.highRiskFindings || 0, danger: true },
                  { label: 'Flagged URLs', val: result?.url_analysis?.flagged?.length || 0, danger: (result?.url_analysis?.flagged?.length || 0) > 0 },
                ].map((s, i) => (
                  <div key={i} style={{ textAlign: 'center', padding: '10px 18px', borderRadius: 12, background: 'rgba(0,0,0,0.2)', border: `1px solid ${s.danger && s.val > 0 ? 'rgba(255,77,109,0.2)' : 'rgba(255,255,255,0.06)'}` }}>
                    <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 22, fontWeight: 700, color: s.danger && s.val > 0 ? '#ff4d6d' : '#f1f5f9' }}>{s.val}</div>
                    <div style={{ fontSize: 10, color: '#475569', letterSpacing: 1, marginTop: 3 }}>{s.label.toUpperCase()}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Two Column Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>

              {/* Basic Information */}
              <SectionCard icon={FolderOpen} title="Basic Information" color="#00d4ff">
                <InfoRow label="Filename" value={result?.file_info?.filename || 'Unknown'} />
                <InfoRow label="Size" value={formatBytes(result?.file_info?.size || 0)} />
                <InfoRow label="MIME Type" value={result?.file_info?.mimeType || 'Unknown'} mono />
                <InfoRow label="Analyzed At" value={result?.file_info?.analyzedAt ? new Date(result.file_info.analyzedAt).toLocaleString() : 'N/A'} />
                <InfoRow label="Category" value={result?.summary?.fileCategory || 'Unknown'} />
                <InfoRow label="Risk Level" value={result?.risk_score?.riskLevel?.level || 'Unknown'} />
              </SectionCard>

              {/* Security Analysis */}
              <SectionCard icon={Shield} title="Security Analysis" color="#a78bfa">
                <InfoRow label="Entropy" value={(result?.entropy_analysis?.entropy || 0).toFixed(4)} mono />
                <InfoRow label="Entropy Level" value={result?.entropy_analysis?.classification?.level || 'Unknown'} />
                <div style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, marginBottom: 6 }}>ENTROPY RISK</div>
                  <span style={{
                    display: 'inline-block', padding: '3px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, letterSpacing: 1,
                    color: getRiskColor(result?.entropy_analysis?.classification?.risk),
                    background: getRiskBg(result?.entropy_analysis?.classification?.risk),
                    border: `1px solid ${getRiskColor(result?.entropy_analysis?.classification?.risk)}30`,
                  }}>{result?.entropy_analysis?.classification?.risk?.toUpperCase() || 'Unknown'}</span>
                </div>
                <div style={{ padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, marginBottom: 8 }}>PATTERN FINDINGS</div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {[
                      { label: 'High', val: result?.pattern_analysis?.highRisk?.length || 0, color: '#ff4d6d' },
                      { label: 'Medium', val: result?.pattern_analysis?.mediumRisk?.length || 0, color: '#fbbf24' },
                      { label: 'Low', val: result?.pattern_analysis?.lowRisk?.length || 0, color: '#00ff88' },
                    ].map(p => (
                      <div key={p.label} style={{ flex: 1, textAlign: 'center', padding: '8px 4px', borderRadius: 8, background: `${p.color}10`, border: `1px solid ${p.color}20` }}>
                        <div style={{ fontFamily: "'Orbitron', monospace", fontSize: 16, fontWeight: 700, color: p.color }}>{p.val}</div>
                        <div style={{ fontSize: 10, color: '#475569', marginTop: 2 }}>{p.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </SectionCard>

              {/* Hashes */}
              <SectionCard icon={Fingerprint} title="Cryptographic Hashes" color="#00ff88">
                <InfoRow label="MD5" value={result?.hashes?.md5 || 'N/A'} mono copyable />
                <InfoRow label="SHA-1" value={result?.hashes?.sha1 || 'N/A'} mono copyable />
                <InfoRow label="SHA-256" value={result?.hashes?.sha256 || 'N/A'} mono copyable />
              </SectionCard>

              {/* File Type Validation */}
              <SectionCard icon={Assessment} title="File Type Validation" color="#fbbf24">
                <InfoRow label="Declared Type" value={result?.file_info?.mimeType || 'Unknown'} mono />
                <InfoRow label="Detected Type" value={result?.file_type_validation?.detectedMimeType || 'Unknown'} mono />
                <div style={{ padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, marginBottom: 6 }}>VALIDATION STATUS</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {result?.file_type_validation?.isValid
                      ? <CheckCircle style={{ color: '#00ff88', fontSize: 18 }} />
                      : <ErrorIcon style={{ color: '#ff4d6d', fontSize: 18 }} />}
                    <span style={{ fontSize: 13, color: result?.file_type_validation?.isValid ? '#00ff88' : '#ff4d6d', fontWeight: 600 }}>
                      {result?.file_type_validation?.isValid ? 'Type Verified' : 'Type Mismatch Detected'}
                    </span>
                  </div>
                </div>
                <div style={{ padding: '10px 0', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, marginBottom: 6 }}>RISK LEVEL</div>
                  <span style={{
                    display: 'inline-block', padding: '3px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, letterSpacing: 1,
                    color: getRiskColor(result?.file_type_validation?.risk),
                    background: getRiskBg(result?.file_type_validation?.risk),
                    border: `1px solid ${getRiskColor(result?.file_type_validation?.risk)}30`,
                  }}>{result?.file_type_validation?.risk?.toUpperCase() || 'Unknown'}</span>
                </div>
                <div style={{ padding: '10px 0' }}>
                  <div style={{ fontSize: 11, color: '#475569', letterSpacing: 1.5, fontWeight: 600, marginBottom: 6 }}>DESCRIPTION</div>
                  <p style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6 }}>{result?.file_type_validation?.description || 'No description available'}</p>
                </div>
              </SectionCard>
            </div>

            {/* Recommendations */}
            {result?.recommendations && result.recommendations.length > 0 && (
              <SectionCard icon={BugReport} title="Recommendations" color="#ff4d6d">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {result.recommendations.map((rec, index) => (
                    <div key={index} className="rec-item" style={{
                      padding: '14px 16px', borderRadius: 12,
                      background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
                      display: 'flex', gap: 12, alignItems: 'flex-start',
                    }}>
                      <div style={{ width: 26, height: 26, borderRadius: 8, background: 'rgba(255,77,109,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                        <span style={{ fontSize: 11, fontWeight: 800, color: '#ff4d6d' }}>{index + 1}</span>
                      </div>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', marginBottom: 4 }}>{rec.title}</div>
                        <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6 }}>{rec.description}</div>
                        {rec.actions && rec.actions.length > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                            {rec.actions.map((action: string, ai: number) => (
                              <span key={ai} style={{ fontSize: 10, padding: '2px 8px', borderRadius: 6, background: 'rgba(255,77,109,0.08)', border: '1px solid rgba(255,77,109,0.2)', color: '#ff8fa3', letterSpacing: 0.5 }}>
                                {action.replace(/_/g, ' ')}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </SectionCard>
            )}

          </div>
        )}
      </div>
  );
};

export default FileAnalysis;