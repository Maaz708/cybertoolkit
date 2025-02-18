const express = require('express');
const router = express.Router();
const os = require('os');
const { exec } = require('child_process');
const si = require('systeminformation');

class NetworkMonitor {
  constructor() {
    this.networkStats = new Map();
    this.lastMeasurement = new Map();
    this.commonPorts = {
      20: { service: 'FTP-DATA', risk: 'high' },
      21: { service: 'FTP', risk: 'high' },
      22: { service: 'SSH', risk: 'medium' },
      23: { service: 'Telnet', risk: 'high' },
      25: { service: 'SMTP', risk: 'medium' },
      53: { service: 'DNS', risk: 'medium' },
      80: { service: 'HTTP', risk: 'medium' },
      443: { service: 'HTTPS', risk: 'medium' },
      445: { service: 'SMB', risk: 'high' },
      3389: { service: 'RDP', risk: 'high' },
      3306: { service: 'MySQL', risk: 'high' },
      5432: { service: 'PostgreSQL', risk: 'high' },
      8080: { service: 'HTTP-ALT', risk: 'medium' }
    };
  }

  async getNetworkStats() {
    try {
      const networkStats = await si.networkStats();
      const interfaces = await si.networkInterfaces();
      const connections = await si.networkConnections();
      const processes = await si.processes();

      // Create a map of PIDs to process names for quick lookup
      const processMap = new Map(processes.list.map(p => [p.pid, p]));

      const connectionDetails = connections.map(conn => ({
        pid: conn.pid,
        process: processMap.get(conn.pid)?.name || 'unknown',
        localAddress: conn.localAddress,
        localPort: conn.localPort,
        remoteAddress: conn.remoteAddress,
        remotePort: conn.remotePort,
        state: conn.state,
        protocol: conn.protocol.toUpperCase(),
        timestamp: new Date().toISOString()
      }));

      const stats = {
        timestamp: new Date().toISOString(),
        interfaces: interfaces.map(iface => ({
          name: iface.iface,
          type: iface.type,
          operstate: iface.operstate,
          ip4: iface.ip4,
          ip6: iface.ip6,
          mac: iface.mac,
          speed: iface.speed,
          dhcp: iface.dhcp,
          dnsSuffix: iface.dnsSuffix
        })),
        traffic: networkStats.map(stat => ({
          interface: stat.iface,
          rx_bytes: stat.rx_bytes,
          tx_bytes: stat.tx_bytes,
          rx_sec: stat.rx_sec,
          tx_sec: stat.tx_sec,
          rx_dropped: stat.rx_dropped,
          tx_dropped: stat.tx_dropped,
          rx_errors: stat.rx_errors,
          tx_errors: stat.tx_errors,
          ms: stat.ms
        })),
        connections: {
          total: connections.length,
          protocols: this.groupByProtocol(connections),
          details: connectionDetails,
          states: this.groupByState(connections)
        }
      };

      return stats;
    } catch (error) {
      console.error('Error getting network stats:', error);
      throw error;
    }
  }

  groupByProtocol(connections) {
    return connections.reduce((acc, conn) => {
      const protocol = conn.protocol.toUpperCase();
      acc[protocol] = (acc[protocol] || 0) + 1;
      return acc;
    }, {});
  }

  groupByState(connections) {
    return connections.reduce((acc, conn) => {
      acc[conn.state] = (acc[conn.state] || 0) + 1;
      return acc;
    }, {});
  }

  determinePortRisk(port, state) {
    const portInfo = this.commonPorts[port] || { service: 'Unknown', risk: 'low' };
    if (state === 'LISTEN') {
      return { ...portInfo, risk: portInfo.risk === 'low' ? 'medium' : portInfo.risk };
    }
    return portInfo;
  }

  async getSecurityAnalysis() {
    try {
      const connections = await si.networkConnections();
      const interfaces = await si.networkInterfaces();
      const processes = await si.processes();

      // Create a map of PIDs to process names
      const processMap = new Map(processes.list.map(p => [p.pid, p]));

      // Enhanced exposed ports analysis
      const exposedPorts = connections
        .filter(conn => conn.state === 'LISTEN')
        .map(conn => {
          const portInfo = this.determinePortRisk(conn.localPort, conn.state);
          return {
            port: conn.localPort,
            service: portInfo.service,
            process: processMap.get(conn.pid)?.name || 'unknown',
            state: conn.state,
            risk: portInfo.risk,
            protocol: conn.protocol.toUpperCase()
          };
        });

      // Analyze suspicious connections
      const suspiciousConnections = connections.filter(conn => {
        const isSuspiciousState = ['SYN_SENT', 'SYN_RECV'].includes(conn.state);
        const isSuspiciousPort = conn.remotePort <= 1024;
        const isUnknownProcess = !processMap.has(conn.pid);
        return isSuspiciousState || (isSuspiciousPort && isUnknownProcess);
      });

      return {
        timestamp: new Date().toISOString(),
        active_connections: connections.length,
        suspicious_connections: suspiciousConnections.length,
        exposed_ports: exposedPorts,
        interfaces_up: interfaces.filter(i => i.operstate === 'up').length,
        total_interfaces: interfaces.length,
        security_metrics: {
          listening_ports: connections.filter(c => c.state === 'LISTEN').length,
          established_connections: connections.filter(c => c.state === 'ESTABLISHED').length,
          unknown_processes: connections.filter(c => !processMap.has(c.pid)).length
        }
      };
    } catch (error) {
      console.error('Error in security analysis:', error);
      throw error;
    }
  }

  async storeNetworkReport(stats, security) {
    const report = {
      timestamp: new Date().toISOString(),
      networkStats: {
        bandwidth: this.calculateBandwidthMetrics(stats.traffic),
        protocols: stats.connections.protocols,
        activeConnections: stats.connections.total,
        interfaceStatus: this.getInterfaceStatus(stats.interfaces)
      },
      securityMetrics: {
        exposedPorts: security.exposed_ports,
        suspiciousConnections: security.suspicious_connections,
        riskAssessment: this.calculateRiskScore(security)
      },
      trafficAnalysis: this.analyzeTrafficPatterns(stats.traffic),
      alerts: this.generateAlerts(stats, security)
    };

    try {
      // Store in a JSON file with timestamp
      const fs = require('fs').promises;
      const reportPath = `./reports/network/${new Date().toISOString().split('T')[0]}`;
      await fs.mkdir(reportPath, { recursive: true });
      await fs.writeFile(
        `${reportPath}/report-${new Date().getTime()}.json`,
        JSON.stringify(report, null, 2)
      );
      return report;
    } catch (error) {
      console.error('Error storing report:', error);
      throw error;
    }
  }

  calculateBandwidthMetrics(traffic) {
    return traffic.reduce((metrics, stat) => {
      metrics.totalRxBytes += stat.rx_bytes;
      metrics.totalTxBytes += stat.tx_bytes;
      metrics.peakRxSpeed = Math.max(metrics.peakRxSpeed, stat.rx_sec);
      metrics.peakTxSpeed = Math.max(metrics.peakTxSpeed, stat.tx_sec);
      metrics.averageRxSpeed = (metrics.averageRxSpeed + stat.rx_sec) / 2;
      metrics.averageTxSpeed = (metrics.averageTxSpeed + stat.tx_sec) / 2;
      return metrics;
    }, {
      totalRxBytes: 0,
      totalTxBytes: 0,
      peakRxSpeed: 0,
      peakTxSpeed: 0,
      averageRxSpeed: 0,
      averageTxSpeed: 0,
      timestamp: new Date().toISOString()
    });
  }

  analyzeTrafficPatterns(traffic) {
    const patterns = {
      timeSeriesData: [],
      trafficSpikes: [],
      unusualPatterns: []
    };

    traffic.forEach((stat, index) => {
      // Add time series data
      patterns.timeSeriesData.push({
        timestamp: new Date().toISOString(),
        rx_mbps: (stat.rx_sec / 1024 / 1024).toFixed(2),
        tx_mbps: (stat.tx_sec / 1024 / 1024).toFixed(2)
      });

      // Detect traffic spikes (sudden increases)
      if (index > 0) {
        const rxDiff = stat.rx_sec - traffic[index - 1].rx_sec;
        const txDiff = stat.tx_sec - traffic[index - 1].tx_sec;

        if (rxDiff > 1000000 || txDiff > 1000000) { // 1 MB/s threshold
          patterns.trafficSpikes.push({
            timestamp: new Date().toISOString(),
            interface: stat.interface,
            rxDiff,
            txDiff
          });
        }
      }
    });

    return patterns;
  }

  generateAlerts(stats, security) {
    const alerts = [];

    // Check for high bandwidth usage
    stats.traffic.forEach(stat => {
      if (stat.rx_sec > 10000000 || stat.tx_sec > 10000000) { // 10 MB/s threshold
        alerts.push({
          type: 'HIGH_BANDWIDTH',
          severity: 'warning',
          message: `High bandwidth usage on ${stat.interface}`,
          timestamp: new Date().toISOString()
        });
      }
    });

    // Check for suspicious connections
    if (security.suspicious_connections > 5) {
      alerts.push({
        type: 'SUSPICIOUS_CONNECTIONS',
        severity: 'high',
        message: `High number of suspicious connections: ${security.suspicious_connections}`,
        timestamp: new Date().toISOString()
      });
    }

    return alerts;
  }

  calculateRiskScore(security) {
    let riskScore = 0;

    // Factor in exposed ports
    riskScore += security.exposed_ports.length * 10;

    // Factor in suspicious connections
    riskScore += security.suspicious_connections * 15;

    // Normalize score to 0-100
    riskScore = Math.min(100, riskScore);

    return {
      score: riskScore,
      level: riskScore > 75 ? 'high' : riskScore > 50 ? 'medium' : 'low',
      timestamp: new Date().toISOString()
    };
  }

  getInterfaceStatus(interfaces) {
    return interfaces.map(iface => ({
      name: iface.name,
      status: iface.operstate,
      speed: iface.speed,
      type: iface.type,
      lastChecked: new Date().toISOString()
    }));
  }
}

const monitor = new NetworkMonitor();

// Routes
router.get('/stats', async (req, res) => {
  try {
    const stats = await monitor.getNetworkStats();
    const security = await monitor.getSecurityAnalysis();

    // Store the report
    await monitor.storeNetworkReport(stats, security);

    res.json({
      status: 'success',
      data: {
        ...stats,
        bandwidth_metrics: monitor.calculateBandwidthMetrics(stats.traffic),
        traffic_patterns: monitor.analyzeTrafficPatterns(stats.traffic),
        alerts: monitor.generateAlerts(stats, security)
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

router.get('/security', async (req, res) => {
  try {
    const analysis = await monitor.getSecurityAnalysis();
    res.json({
      status: 'success',
      data: analysis
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

router.get('/reports', async (req, res) => {
  try {
    const fs = require('fs').promises;
    const { date } = req.query;
    const reportPath = `./reports/network/${date || new Date().toISOString().split('T')[0]}`;

    const files = await fs.readdir(reportPath);
    const reports = await Promise.all(
      files.map(async file => {
        const content = await fs.readFile(`${reportPath}/${file}`, 'utf8');
        return JSON.parse(content);
      })
    );

    res.json({
      status: 'success',
      data: reports
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

module.exports = router;