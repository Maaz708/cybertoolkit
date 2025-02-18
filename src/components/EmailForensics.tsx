import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  CircularProgress,
  Alert,
  Paper,
  Card,
  CardContent,
  Grid,
  List,
  ListItem,
  ListItemText,
  Chip,
  Divider
} from '@mui/material';
import {
  Upload as UploadIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Email as EmailIcon,
  AttachFile as AttachFileIcon,
  Link as LinkIcon
} from '@mui/icons-material';
import axios from 'axios';

interface EmailAnalysis {
  status: string;
  analysis: {
    content: {
      subject: string;
      from: string;
      to: string;
      date: string;
    };
    security: {
      securityScore: number;
      spfRecord: string | null;
      dmarcRecord: string | null;
      returnPathValid: boolean;
      suspiciousLinks: string[];
      suspiciousAttachments: string[];
    };
    attachments: Array<{
      filename: string;
      contentType: string;
      size: number;
      malwareScan: {
        safe: boolean;
        score: number;
      };
    }>;
    metadata: {
      receivedTimestamp: string;
      messageId: string;
      size: number;
    };
  };
}

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

  const getSecurityColor = (score: number) => {
    if (score >= 80) return 'success';
    if (score >= 60) return 'warning';
    return 'error';
  };

  const getStatusIcon = (isValid: boolean) => {
    return isValid ? (
      <CheckCircleIcon color="success" />
    ) : (
      <ErrorIcon color="error" />
    );
  };

  return (
    <Box sx={{ p: 3, maxWidth: 800, margin: '0 auto' }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
        <EmailIcon sx={{ mr: 1 }} />
        Email Forensics Analysis
      </Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ textAlign: 'center' }}>
            <Button
              variant="contained"
              component="label"
              startIcon={<UploadIcon />}
              disabled={analyzing}
            >
              Upload Email File
              <input
                type="file"
                hidden
                onChange={handleEmailAnalysis}
                accept=".eml,.msg"
              />
            </Button>
          </Box>
        </CardContent>
      </Card>

      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          icon={<ErrorIcon />}
        >
          {error}
        </Alert>
      )}

      {analyzing && (
        <Box sx={{ textAlign: 'center', my: 3 }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>Analyzing email...</Typography>
        </Box>
      )}

      {analysis && !analyzing && (
        <Grid container spacing={3}>
          {/* Basic Email Information */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <EmailIcon sx={{ mr: 1 }} />
                  Email Information
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="From"
                      secondary={analysis.analysis.content.from}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Subject"
                      secondary={analysis.analysis.content.subject}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Date"
                      secondary={new Date(analysis.analysis.content.date).toLocaleString()}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Security Analysis */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <SecurityIcon sx={{ mr: 1 }} />
                  Security Analysis
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                        {getStatusIcon(!!analysis.analysis.security.spfRecord)}
                        <Typography sx={{ ml: 1 }}>SPF Record</Typography>
                      </Box>
                      <Chip
                        label={analysis.analysis.security.spfRecord ? 'Valid' : 'Not Found'}
                        color={analysis.analysis.security.spfRecord ? 'success' : 'error'}
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                        {getStatusIcon(!!analysis.analysis.security.dmarcRecord)}
                        <Typography sx={{ ml: 1 }}>DMARC Record</Typography>
                      </Box>
                      <Chip
                        label={analysis.analysis.security.dmarcRecord ? 'Valid' : 'Not Found'}
                        color={analysis.analysis.security.dmarcRecord ? 'success' : 'error'}
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, textAlign: 'center' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                        {getStatusIcon(analysis.analysis.security.returnPathValid)}
                        <Typography sx={{ ml: 1 }}>Return Path</Typography>
                      </Box>
                      <Chip
                        label={analysis.analysis.security.returnPathValid ? 'Valid' : 'Invalid'}
                        color={analysis.analysis.security.returnPathValid ? 'success' : 'error'}
                      />
                    </Paper>
                  </Grid>
                </Grid>

                <Divider sx={{ my: 2 }} />

                {/* Suspicious Elements */}
                <Typography variant="subtitle1" gutterBottom>
                  Suspicious Elements
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <LinkIcon sx={{ mr: 1 }} />
                        <Typography>Suspicious Links</Typography>
                      </Box>
                      <Chip
                        icon={analysis.analysis.security.suspiciousLinks.length ? <WarningIcon /> : <CheckCircleIcon />}
                        label={`${analysis.analysis.security.suspiciousLinks.length} found`}
                        color={analysis.analysis.security.suspiciousLinks.length ? 'warning' : 'success'}
                      />
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                        <AttachFileIcon sx={{ mr: 1 }} />
                        <Typography>Suspicious Attachments</Typography>
                      </Box>
                      <Chip
                        icon={analysis.analysis.security.suspiciousAttachments.length ? <WarningIcon /> : <CheckCircleIcon />}
                        label={`${analysis.analysis.security.suspiciousAttachments.length} found`}
                        color={analysis.analysis.security.suspiciousAttachments.length ? 'warning' : 'success'}
                      />
                    </Paper>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Debug Information (if needed) */}
          {process.env.NODE_ENV === 'development' && (
            <Grid item xs={12}>
              <Paper sx={{ p: 2, bgcolor: 'grey.900' }}>
                <Typography variant="subtitle2" sx={{ color: 'grey.100', mb: 1 }}>
                  Debug Information
                </Typography>
                <Box
                  component="pre"
                  sx={{
                    p: 2,
                    borderRadius: 1,
                    bgcolor: 'grey.900',
                    color: 'grey.100',
                    overflow: 'auto',
                    fontSize: '0.875rem',
                    fontFamily: 'monospace'
                  }}
                >
                  {JSON.stringify({
                    analyzing,
                    hasError: !!error,
                    hasAnalysis: !!analysis,
                    analysisData: analysis
                  }, null, 2)}
                </Box>
              </Paper>
            </Grid>
          )}
        </Grid>
      )}
    </Box>
  );
};

export default EmailForensics;