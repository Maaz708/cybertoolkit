import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Card,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  CircularProgress,
  Alert,
  CardContent,
  Grid,
  Chip,
  LinearProgress,
  Paper,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Tooltip,
  TableContainer,
  ListItemIcon
} from '@mui/material';
import {
  Timeline,
  Speed,
  Security,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  NetworkCheck,
  Language,
  Flag,
  Devices as DevicesIcon,
  Memory as MemoryIcon,
  Block as BlockIcon,
  Security as SecurityScanIcon,
  Assessment as AssessmentIcon,
  PlayArrow,
  Stop
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  ComposedChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  TooltipProps
} from 'recharts';
import axios from 'axios';
import { DatePicker } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import dayjs, { Dayjs } from 'dayjs';
import { NameType, ValueType } from 'recharts/types/component/DefaultTooltipContent';
import './NetworkMonitor.css';

const COLORS = [
  '#0088FE',  // Blue
  '#00C49F',  // Green
  '#FFBB28',  // Yellow
  '#FF8042',  // Orange
  '#8884d8',  // Purple
  '#82ca9d',  // Light Green
  '#ffc658',  // Gold
  '#ff8042',  // Coral
  '#a4de6c',  // Light Green
  '#d0ed57'   // Lime
];

interface NetworkStats {
  timestamp: string;
  interfaces: Array<{
    name: string;
    type: string;
    operstate: string;
    ip4: string;
    ip6: string;
    mac: string;
  }>;
  traffic: Array<{
    interface: string;
    rx_bytes: number;
    tx_bytes: number;
    rx_sec: number;
    tx_sec: number;
    ms: number;
  }>;
  connections: {
    total: number;
    protocols: Record<string, number>;
    details: Array<{
      pid: number;
      process: string;
      localAddress: string;
      localPort: number;
      remoteAddress: string;
      remotePort: number;
      state: string;
      protocol: string;
      timestamp: string;
    }>;
  };
}

interface SecurityAnalysis {
  timestamp: string;
  active_connections: number;
  suspicious_connections: number;
  exposed_ports: PortDetail[];
  interfaces_up: number;
  total_interfaces: number;
}

interface ConnectionDetail {
  pid: number;
  process: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  protocol: string;
  timestamp: string;
}

interface PortDetail {
  port: number;
  service: string;
  process: string;
  state: string;
  risk: 'low' | 'medium' | 'high';
}

interface HistoricalBandwidthData {
  timestamp: string;
  networkStats: {
    bandwidth: {
      averageRxSpeed: number;
      averageTxSpeed: number;
    };
  };
  alerts: Array<{
    severity: 'high' | 'warning';
    message: string;
    timestamp: string;
  }>;
}

const CustomTooltip = ({
  active,
  payload,
  label,
}: TooltipProps<ValueType, NameType>) => {
  if (active && payload && payload.length) {
    return (
      <Paper
        sx={{
          p: 1,
          backgroundColor: 'background.paper',
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
        }}
      >
        <Typography variant="body2" sx={{ mb: 1 }}>
          {dayjs(label).format('YYYY-MM-DD HH:mm:ss')}
        </Typography>
        {payload.map((entry, index) => (
          <Typography
            key={`item-${index}`}
            variant="body2"
            sx={{ color: entry.color }}
          >
            {`${entry.name}: ${Number(entry.value).toFixed(2)} MB/s`}
          </Typography>
        ))}
      </Paper>
    );
  }
  return null;
};

const NetworkMonitor = () => {
  const [networkStats, setNetworkStats] = useState<NetworkStats | null>(null);
  const [securityAnalysis, setSecurityAnalysis] = useState<SecurityAnalysis | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [intervalId, setIntervalId] = useState<NodeJS.Timeout | null>(null);
  const [selectedDate, setSelectedDate] = useState<Dayjs>(dayjs());
  const [historicalData, setHistoricalData] = useState<HistoricalBandwidthData[]>([]);

  const startMonitoring = async () => {
    setIsLoading(true);
    setError(null);
    setIsMonitoring(true);

    try {
      // Initial fetch
      await fetchData();

      // Start periodic updates
      const interval = setInterval(fetchData, 5000); // Update every 5 seconds
      setIntervalId(interval);
    } catch (err) {
      console.error('Failed to start monitoring:', err);
      setError('Failed to start network monitoring');
      setIsMonitoring(false);
    } finally {
      setIsLoading(false);
    }
  };

  const stopMonitoring = () => {
    if (intervalId) {
      clearInterval(intervalId);
      setIntervalId(null);
    }
    setIsMonitoring(false);
    setNetworkStats(null);
    setSecurityAnalysis(null);
  };

  const fetchData = async () => {
    try {
      const [statsResponse, securityResponse] = await Promise.all([
        axios.get('/api/network/stats'),
        axios.get('/api/network/security')
      ]);

      if (statsResponse.data?.data && securityResponse.data?.data) {
        setNetworkStats(statsResponse.data.data);
        setSecurityAnalysis(securityResponse.data.data);
      } else {
        throw new Error('Invalid data received from server');
      }
    } catch (err) {
      console.error('Error fetching network data:', err);
      setError('Failed to fetch network data');
      stopMonitoring();
    }
  };

  const fetchHistoricalData = async (date: Dayjs) => {
    try {
      const response = await axios.get(`/api/network/reports?date=${date.format('YYYY-MM-DD')}`);
      setHistoricalData(response.data.data);
    } catch (error) {
      console.error('Error fetching historical data:', error);
    }
  };

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [intervalId]);

  const renderTrafficChart = (data: NetworkStats['traffic']) => {
    const chartData = data.map(stat => ({
      interface: stat.interface,
      inbound: (stat.rx_sec / 1024 / 1024).toFixed(2), // Convert to MB/s
      outbound: (stat.tx_sec / 1024 / 1024).toFixed(2)
    }));

    return (
      <Box sx={{ height: 300, width: '100%', mb: 3 }}>
        <ResponsiveContainer>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="interface" />
            <YAxis
              label={{
                value: 'MB/s',
                angle: -90,
                position: 'insideLeft'
              }}
            />
            <ChartTooltip formatter={(value) => [`${value} MB/s`]} />
            <Legend />
            <Line
              type="monotone"
              dataKey="inbound"
              stroke={COLORS[0]}
              name="Inbound"
              strokeWidth={2}
            />
            <Line
              type="monotone"
              dataKey="outbound"
              stroke={COLORS[1]}
              name="Outbound"
              strokeWidth={2}
            />
          </LineChart>
        </ResponsiveContainer>
      </Box>
    );
  };

  const renderProtocolDistribution = (protocols: Record<string, number>) => {
    const data = Object.entries(protocols).map(([protocol, count]) => ({
      protocol,
      value: count
    }));

    return (
      <Box sx={{ height: 300, width: '100%', mb: 3 }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="protocol"
              cx="50%"
              cy="50%"
              outerRadius={100}
              fill="#8884d8"
              label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={COLORS[index % COLORS.length]}
                />
              ))}
            </Pie>
            <ChartTooltip formatter={(value) => [`${value} connections`, 'Count']} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      </Box>
    );
  };

  const renderConnectionDetails = () => {
    if (!networkStats?.connections) return null;

    return (
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <DevicesIcon sx={{ mr: 1 }} />
            Active Connections Detail
          </Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Process</TableCell>
                  <TableCell>Local Address</TableCell>
                  <TableCell>Remote Address</TableCell>
                  <TableCell>State</TableCell>
                  <TableCell>Protocol</TableCell>
                  <TableCell>Action</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {networkStats.connections.details?.map((conn: ConnectionDetail, index) => (
                  <TableRow key={index}>
                    <TableCell>
                      <Tooltip title={`PID: ${conn.pid}`}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <MemoryIcon sx={{ mr: 1, fontSize: 'small' }} />
                          {conn.process}
                        </Box>
                      </Tooltip>
                    </TableCell>
                    <TableCell>{`${conn.localAddress}:${conn.localPort}`}</TableCell>
                    <TableCell>{`${conn.remoteAddress}:${conn.remotePort}`}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={conn.state}
                        color={conn.state === 'ESTABLISHED' ? 'success' : 'warning'}
                      />
                    </TableCell>
                    <TableCell>{conn.protocol}</TableCell>
                    <TableCell>
                      <IconButton size="small" color="error" title="Block Connection">
                        <BlockIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  const renderExposedPorts = () => {
    if (!securityAnalysis?.exposed_ports || !Array.isArray(securityAnalysis.exposed_ports)) {
      return null;
    }

    return (
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <SecurityScanIcon sx={{ mr: 1 }} />
            Exposed Ports Analysis
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={8}>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Port</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Process</TableCell>
                      <TableCell>Risk Level</TableCell>
                      <TableCell>Status</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {securityAnalysis.exposed_ports.map((port: PortDetail) => (
                      port && port.port ? (
                        <TableRow key={port.port}>
                          <TableCell>{port.port}</TableCell>
                          <TableCell>{port.service}</TableCell>
                          <TableCell>{port.process}</TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              label={port.risk}
                              color={
                                port.risk === 'high' ? 'error' :
                                  port.risk === 'medium' ? 'warning' : 'success'
                              }
                            />
                          </TableCell>
                          <TableCell>
                            <Chip
                              size="small"
                              label={port.state}
                              color={port.state === 'LISTEN' ? 'primary' : 'default'}
                            />
                          </TableCell>
                        </TableRow>
                      ) : null
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Port Security Summary
                </Typography>
                <List dense>
                  <ListItem>
                    <ListItemIcon>
                      <ErrorIcon color="error" />
                    </ListItemIcon>
                    <ListItemText
                      primary="High Risk Ports"
                      secondary={securityAnalysis.exposed_ports.filter(p => p.risk === 'high').length}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Medium Risk Ports"
                      secondary={securityAnalysis.exposed_ports.filter(p => p.risk === 'medium').length}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Low Risk Ports"
                      secondary={securityAnalysis.exposed_ports.filter(p => p.risk === 'low').length}
                    />
                  </ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  };

  const renderAdvancedNetworkStats = () => {
    if (!networkStats?.traffic) return null;

    return (
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <AssessmentIcon sx={{ mr: 1 }} />
            Advanced Network Statistics
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Bandwidth Utilization
                </Typography>
                <Box sx={{ height: 200 }}>
                  <ResponsiveContainer>
                    <AreaChart data={networkStats.traffic}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <ChartTooltip />
                      <Area
                        type="monotone"
                        dataKey="rx_sec"
                        stackId="1"
                        stroke={COLORS[0]}
                        fill={COLORS[0]}
                        name="Download"
                      />
                      <Area
                        type="monotone"
                        dataKey="tx_sec"
                        stackId="1"
                        stroke={COLORS[1]}
                        fill={COLORS[1]}
                        name="Upload"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Protocol Distribution Over Time
                </Typography>
                <Box sx={{ height: 200 }}>
                  <ResponsiveContainer>
                    <ComposedChart data={networkStats.traffic}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" />
                      <YAxis />
                      <ChartTooltip />
                      <Legend />
                      <Bar dataKey="tcp" fill={COLORS[0]} name="TCP" />
                      <Bar dataKey="udp" fill={COLORS[1]} name="UDP" />
                      <Area
                        type="monotone"
                        dataKey="total"
                        stroke={COLORS[2]}
                        fill={COLORS[2]}
                        name="Total"
                      />
                    </ComposedChart>
                  </ResponsiveContainer>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <NetworkCheck sx={{ mr: 1 }} />
          Network Monitor
        </Box>
        <Button
          variant="contained"
          color={isMonitoring ? "error" : "primary"}
          onClick={isMonitoring ? stopMonitoring : startMonitoring}
          startIcon={isMonitoring ? <Stop /> : <PlayArrow />}
          disabled={isLoading}
        >
          {isMonitoring ? "Stop Monitoring" : "Start Monitoring"}
        </Button>
      </Typography>

      {isLoading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 3 }}>
          <CircularProgress />
        </Box>
      )}

      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          onClose={() => setError(null)}
        >
          {error}
        </Alert>
      )}

      {!isMonitoring && !isLoading && !error && (
        <Alert severity="info" sx={{ mb: 3 }}>
          Click "Start Monitoring" to begin network analysis
        </Alert>
      )}

      {isMonitoring && networkStats && securityAnalysis && !isLoading && (
        <>
          {/* Security Status */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Security sx={{ mr: 1 }} />
                Security Status
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="primary">
                      {securityAnalysis.active_connections}
                    </Typography>
                    <Typography>Active Connections</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography
                      variant="h4"
                      color={securityAnalysis.suspicious_connections > 0 ? 'error' : 'success'}
                    >
                      {securityAnalysis.suspicious_connections}
                    </Typography>
                    <Typography>Suspicious Connections</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="info">
                      {securityAnalysis.exposed_ports.length}
                    </Typography>
                    <Typography>Exposed Ports</Typography>
                  </Paper>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Traffic Overview */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Timeline sx={{ mr: 1 }} />
                Network Traffic
              </Typography>
              {renderTrafficChart(networkStats.traffic)}
            </CardContent>
          </Card>

          {/* Protocol Distribution */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <Language sx={{ mr: 1 }} />
                Protocol Distribution
              </Typography>
              {renderProtocolDistribution(networkStats.connections.protocols)}
            </CardContent>
          </Card>

          {renderConnectionDetails()}
          {renderExposedPorts()}
          {renderAdvancedNetworkStats()}
        </>
      )}

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <AssessmentIcon sx={{ mr: 1 }} />
            Historical Data
          </Typography>

          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <DatePicker
              label="Select Date"
              value={selectedDate}
              onChange={(newValue) => {
                if (newValue) {
                  setSelectedDate(newValue);
                  fetchHistoricalData(newValue);
                }
              }}
              sx={{ mb: 2 }}
            />
          </LocalizationProvider>

          {historicalData.length > 0 ? (
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Historical Bandwidth Usage
                  </Typography>
                  <Box sx={{ height: 300 }}>
                    <ResponsiveContainer>
                      <LineChart data={historicalData}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis
                          dataKey="timestamp"
                          tickFormatter={(value) => dayjs(value).format('HH:mm')}
                        />
                        <YAxis />
                        <Tooltip />
                        <Legend />
                        <Line
                          type="monotone"
                          dataKey="networkStats.bandwidth.averageRxSpeed"
                          name="Avg Download"
                          stroke={COLORS[0]}
                          dot={false}
                        />
                        <Line
                          type="monotone"
                          dataKey="networkStats.bandwidth.averageTxSpeed"
                          name="Avg Upload"
                          stroke={COLORS[1]}
                          dot={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </Box>
                </Paper>
              </Grid>

              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Security Events
                  </Typography>
                  <List dense>
                    {historicalData.map((report, index) => (
                      report.alerts?.map((alert: any, alertIndex: number) => (
                        <ListItem key={`${index}-${alertIndex}`}>
                          <ListItemIcon>
                            {alert.severity === 'high' ? (
                              <ErrorIcon color="error" />
                            ) : (
                              <WarningIcon color="warning" />
                            )}
                          </ListItemIcon>
                          <ListItemText
                            primary={alert.message}
                            secondary={dayjs(alert.timestamp).format('HH:mm:ss')}
                          />
                        </ListItem>
                      )) || []
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          ) : (
            <Alert severity="info">
              Select a date to view historical data
            </Alert>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default NetworkMonitor;