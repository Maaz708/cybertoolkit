import React, { useState } from 'react';
import {
  Box,
  Button,
  Card,
  Typography,
  LinearProgress,
  Alert,
  Grid,
  Tabs,
  Tab,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Collapse,
  Paper,
} from '@mui/material';
import {
  Cloud,
  Security,
  Storage,
  History,
  ExpandMore,
  ExpandLess,
  Warning,
  CheckCircle,
  Error,
} from '@mui/icons-material';
import axios from 'axios';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

interface CloudAnalysis {
  id: string;
  timestamp: string;
  provider: string;
  summary: {
    buckets?: number;
    containers?: number;
    blobs?: number;
  };
  objects: Array<{
    name: string;
    created: string;
    objects: Array<{
      key: string;
      size: number;
      modified: string;
      owner: string;
    }>;
    permissions: any;
    logging: any;
    encryption: any;
  }>;
  access_logs: Array<{
    timestamp: string;
    action: string;
    resource: string;
    user: string;
    status: string;
  }>;
  security_config: any;
  vulnerabilities: Array<{
    severity: string;
    type: string;
    resource: string;
    description: string;
  }>;
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

const CloudForensics = () => {
  const [provider, setProvider] = useState<string>('');
  const [credentials, setCredentials] = useState<any>({});
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<CloudAnalysis | null>(null);
  const [error, setError] = useState<string>('');
  const [activeTab, setActiveTab] = useState(0);
  const [expandedObject, setExpandedObject] = useState<string | null>(null);

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setError('');
    setAnalysis(null);

    try {
      const response = await axios.post('/api/cloud-forensics/analyze', {
        provider,
        credentials,
      });

      setAnalysis(response.data);
    } catch (error: any) {
      setError(error.response?.data?.error || 'Analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleCredentialsChange = (field: string, value: string) => {
    setCredentials(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const renderCredentialsForm = () => {
    switch (provider) {
      case 'aws':
        return (
          <>
            <TextField
              label="Access Key ID"
              fullWidth
              margin="normal"
              value={credentials.accessKeyId || ''}
              onChange={(e) => handleCredentialsChange('accessKeyId', e.target.value)}
            />
            <TextField
              label="Secret Access Key"
              fullWidth
              margin="normal"
              type="password"
              value={credentials.secretAccessKey || ''}
              onChange={(e) => handleCredentialsChange('secretAccessKey', e.target.value)}
            />
            <TextField
              label="Region"
              fullWidth
              margin="normal"
              value={credentials.region || ''}
              onChange={(e) => handleCredentialsChange('region', e.target.value)}
            />
          </>
        );
      case 'azure':
        return (
          <TextField
            label="Connection String"
            fullWidth
            margin="normal"
            type="password"
            value={credentials.connectionString || ''}
            onChange={(e) => handleCredentialsChange('connectionString', e.target.value)}
          />
        );
      case 'gcloud':
        return (
          <TextField
            label="Service Account Key"
            fullWidth
            margin="normal"
            multiline
            rows={4}
            value={credentials.serviceAccountKey || ''}
            onChange={(e) => handleCredentialsChange('serviceAccountKey', e.target.value)}
          />
        );
      default:
        return null;
    }
  };

  const renderStorageOverview = () => (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <Card sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>Storage Summary</Typography>
          <PieChart width={400} height={300}>
            <Pie
              data={[
                { name: 'Buckets', value: analysis?.summary.buckets || 0 },
                { name: 'Objects', value: analysis?.objects.reduce((acc, obj) => acc + obj.objects.length, 0) || 0 }
              ]}
              cx="50%"
              cy="50%"
              labelLine={false}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {COLORS.map((color, index) => (
                <Cell key={`cell-${index}`} fill={color} />
              ))}
            </Pie>
            <Tooltip />
            <Legend />
          </PieChart>
        </Card>
      </Grid>

      <Grid item xs={12} md={6}>
        <Card sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>Storage Usage</Typography>
          <BarChart
            width={400}
            height={300}
            data={analysis?.objects.map(obj => ({
              name: obj.name,
              size: obj.objects.reduce((acc, o) => acc + o.size, 0) / 1024 / 1024 // Convert to MB
            }))}
          >
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis label={{ value: 'Size (MB)', angle: -90, position: 'insideLeft' }} />
            <Tooltip />
            <Bar dataKey="size" fill="#8884d8" />
          </BarChart>
        </Card>
      </Grid>
    </Grid>
  );

  const renderSecurityAnalysis = () => (
    <Card sx={{ p: 2 }}>
      <Typography variant="h6" gutterBottom>Security Analysis</Typography>
      <Grid container spacing={2}>
        {analysis?.vulnerabilities.map((vuln, index) => (
          <Grid item xs={12} key={index}>
            <Paper sx={{ p: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Chip
                  icon={vuln.severity === 'HIGH' ? <Error /> : <Warning />}
                  label={vuln.severity}
                  color={vuln.severity === 'HIGH' ? 'error' : 'warning'}
                  sx={{ mr: 1 }}
                />
                <Typography variant="subtitle1">{vuln.type}</Typography>
              </Box>
              <Typography color="textSecondary">Resource: {vuln.resource}</Typography>
              <Typography>{vuln.description}</Typography>
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Card>
  );

  const renderAccessLogs = () => (
    <Card sx={{ p: 2 }}>
      <Typography variant="h6" gutterBottom>Access Logs</Typography>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Time</TableCell>
            <TableCell>Action</TableCell>
            <TableCell>Resource</TableCell>
            <TableCell>User</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {analysis?.access_logs.map((log, index) => (
            <TableRow key={index}>
              <TableCell>
                {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}
              </TableCell>
              <TableCell>{log.action}</TableCell>
              <TableCell>{log.resource}</TableCell>
              <TableCell>{log.user}</TableCell>
              <TableCell>
                <Chip
                  size="small"
                  label={log.status}
                  color={log.status === 'success' ? 'success' : 'error'}
                />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  );

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>Cloud Forensics</Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Card sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel>Cloud Provider</InputLabel>
              <Select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                label="Cloud Provider"
              >
                <MenuItem value="aws">Amazon Web Services</MenuItem>
                <MenuItem value="azure">Microsoft Azure</MenuItem>
                <MenuItem value="gcloud">Google Cloud</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={8}>
            {renderCredentialsForm()}
          </Grid>
          <Grid item xs={12}>
            <Button
              variant="contained"
              onClick={handleAnalyze}
              disabled={!provider || analyzing}
              startIcon={<Cloud />}
            >
              Analyze Cloud Storage
            </Button>
          </Grid>
        </Grid>
      </Card>

      {analyzing && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography sx={{ mt: 1 }} align="center">
            Analyzing cloud storage...
          </Typography>
        </Box>
      )}

      {analysis && (
        <Box sx={{ width: '100%' }}>
          <Tabs
            value={activeTab}
            onChange={(_, newValue) => setActiveTab(newValue)}
            sx={{ mb: 2 }}
          >
            <Tab icon={<Storage />} label="Storage Overview" />
            <Tab icon={<Security />} label="Security Analysis" />
            <Tab icon={<History />} label="Access Logs" />
          </Tabs>

          <Box sx={{ mt: 2 }}>
            {activeTab === 0 && renderStorageOverview()}
            {activeTab === 1 && renderSecurityAnalysis()}
            {activeTab === 2 && renderAccessLogs()}
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default CloudForensics;