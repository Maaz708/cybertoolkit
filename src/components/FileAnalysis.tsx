import React, { useState } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Typography,
  CircularProgress,
  Grid,
  Paper,
  List,
  ListItem,
  ListItemText,
  Divider,
  Alert,
  Chip
} from '@mui/material';
import {
  Upload,
  Description,
  Security,
  Code,
  Assessment
} from '@mui/icons-material';
import axios from 'axios';

interface FileAnalysisResult {
  basic_info: {
    filename: string;
    size: number;
    created: string;
    modified: string;
    accessed: string;
    mime_type: string;
    extension: string;
  };
  security: {
    hashes: {
      md5: string;
      sha1: string;
      sha256: string;
    };
    entropy: number;
    suspicious_patterns: {
      executable_code: boolean;
      scripts: boolean;
      base64: boolean;
    };
  };
  content_analysis: {
    file_type: string;
    size_bytes: number;
    text_preview: string | null;
    binary: boolean;
    lines?: number;
    words?: number;
  };
  metadata: {
    file_type: string;
    size: number;
    encoding: string;
  };
  timestamp: string;
}

const FileAnalysis = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [error, setError] = useState<string>('');

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (files && files[0]) {
      setFile(files[0]);
      await analyzeFile(files[0]);
    }
  };

  const analyzeFile = async (fileToAnalyze: File) => {
    setAnalyzing(true);
    setError('');
    setResult(null);

    const formData = new FormData();
    formData.append('file', fileToAnalyze);

    try {
      const response = await axios.post('/api/files/analyze', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        }
      });

      if (response.data.status === 'success') {
        setResult(response.data.data);
      } else {
        throw new Error(response.data.message);
      }
    } catch (err: any) {
      console.error('Analysis error:', err);
      setError(err.message || 'Failed to analyze file');
    } finally {
      setAnalyzing(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        File Analysis
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper sx={{ p: 3, mb: 3 }}>
        <Button
          variant="contained"
          component="label"
          startIcon={<Upload />}
          disabled={analyzing}
        >
          Upload File for Analysis
          <input
            type="file"
            hidden
            onChange={handleFileChange}
          />
        </Button>
        {file && (
          <Typography sx={{ mt: 2 }} color="textSecondary">
            Selected: {file.name}
          </Typography>
        )}
      </Paper>

      {analyzing && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 3 }}>
          <CircularProgress />
        </Box>
      )}

      {result && (
        <Grid container spacing={3}>
          {/* Basic Information */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <Description sx={{ mr: 1 }} />
                  Basic Information
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="Filename"
                      secondary={result.basic_info.filename}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Size"
                      secondary={formatBytes(result.basic_info.size)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Type"
                      secondary={result.basic_info.mime_type}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="Modified"
                      secondary={new Date(result.basic_info.modified).toLocaleString()}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Security Information */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <Security sx={{ mr: 1 }} />
                  Security Analysis
                </Typography>
                <List>
                  <ListItem>
                    <ListItemText
                      primary="Entropy"
                      secondary={result.security.entropy.toFixed(2)}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemText
                      primary="SHA-256"
                      secondary={result.security.hashes.sha256}
                    />
                  </ListItem>
                  <ListItem>
                    <Box sx={{ width: '100%' }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Suspicious Patterns
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                        {Object.entries(result.security.suspicious_patterns).map(([key, value]) => (
                          <Chip
                            key={key}
                            label={key.replace('_', ' ')}
                            color={value ? 'error' : 'success'}
                            size="small"
                          />
                        ))}
                      </Box>
                    </Box>
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Content Preview */}
          {result.content_analysis.text_preview && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                    <Code sx={{ mr: 1 }} />
                    Content Preview
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: 'grey.100' }}>
                    <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
                      {result.content_analysis.text_preview}
                    </pre>
                  </Paper>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      )}
    </Box>
  );
};

export default FileAnalysis;