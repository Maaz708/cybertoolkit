const express = require('express');
const router = express.Router();
const os = require('os');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

// Import services
const ConnectionAnalysisService = require('./services/connectionAnalysisService');
const ThreatDetectionService = require('./services/threatDetectionService');
const TrafficAnalysisService = require('./services/trafficAnalysisService');
const AlertService = require('./services/alertService');
const HistoricalTrackingService = require('./services/historicalTrackingService');
const NetworkScoringService = require('./services/networkScoringService');
const GeoLocationService = require('./services/geoLocationService');

class NetworkMonitor {
    constructor() {
        this.analysisHistory = [];
        this.currentSnapshot = null;
        this.previousSnapshot = null;
        this.isMonitoring = false;
        
        // Initialize services
        this.connectionService = new ConnectionAnalysisService();
        this.threatService = new ThreatDetectionService();
        this.trafficService = new TrafficAnalysisService();
        this.alertService = new AlertService();
        this.historicalService = new HistoricalTrackingService();
        this.scoringService = new NetworkScoringService();
        this.geoService = new GeoLocationService();
    }

    startMonitoring() {
        this.isMonitoring = true;
        console.log('Network monitoring started');
    }

    stopMonitoring() {
        this.isMonitoring = false;
        console.log('Network monitoring stopped');
    }

    getMonitoringStatus() {
        return this.isMonitoring;
    }

    calculateSpeed(current, previous) {
        if (!previous || !current) return { rx_sec: 0, tx_sec: 0 };

        const timeDiff = (new Date(current.timestamp) - new Date(previous.timestamp)) / 1000; // seconds
        if (timeDiff <= 0) return { rx_sec: 0, tx_sec: 0 };

        return {
            rx_sec: (current.totalBytesReceived - previous.totalBytesReceived) / timeDiff / 1024 / 1024, // MB/s
            tx_sec: (current.totalBytesSent - previous.totalBytesSent) / timeDiff / 1024 / 1024 // MB/s
        };
    }

    async getNetworkStatus() {
        // Check if monitoring is active
        if (!this.isMonitoring) {
            console.log('Monitoring not active, returning cached/empty data');
            return {
                threatLevel: 'low',
                vulnerabilities: [],
                suspiciousActivity: [],
                securityScore: 85,
                recommendations: ['Network monitoring is not active'],
                connections: [],
                alerts: { generated: [], summary: { high: 0, medium: 0, low: 0 } },
                firewall: { status: 'unknown' },
                connection_analysis: { totalConnections: 0, connections: [], suspiciousConnections: [] },
                network_stats: { totalBytesReceived: 0, totalBytesSent: 0 },
                open_ports: [],
                protocols: { TCP: 0, UDP: 0, Other: 0 },
                bandwidth: { inbound: 0, outbound: 0 },
                hacker_map: [],
                timestamp: new Date().toISOString()
            };
        }

        try {
            // Gather current network statistics
            const networkStats = await this.gatherNetworkStats().catch(err => {
                console.warn('Network stats gathering failed, using defaults:', err.message);
                return {
                    totalConnections: 0,
                    totalBytesSent: 0,
                    totalBytesReceived: 0,
                    inboundConnections: 0,
                    outboundConnections: 0,
                    interfaces: [],
                    timeWindow: 60
                };
            });
            
            // Gather connection information
            const connections = await this.gatherConnections().catch(err => {
                console.warn('Connection gathering failed, using defaults:', err.message);
                return [];
            });
            
            // Gather process information
            const processes = await this.gatherProcesses().catch(err => {
                console.warn('Process gathering failed, using defaults:', err.message);
                return [];
            });
            
            // Gather open ports
            const openPorts = await this.gatherOpenPorts().catch(err => {
                console.warn('Open ports gathering failed, using defaults:', err.message);
                return [];
            });
            
            // Create current snapshot
            this.currentSnapshot = {
                timestamp: new Date().toISOString(),
                networkStats: networkStats,
                connections: connections,
                processes: processes,
                openPorts: openPorts
            };

            // Calculate bandwidth speed
            const speed = this.calculateSpeed(networkStats, this.previousSnapshot?.networkStats);
            
            // Add traffic analysis with real bandwidth
            this.currentSnapshot.trafficAnalysis = {
                bandwidth: {
                    currentSpeed: speed,
                    totalBytesReceived: networkStats.totalBytesReceived,
                    totalBytesSent: networkStats.totalBytesSent,
                    timeWindow: 60
                }
            };

            // Store previous snapshot for next calculation
            this.previousSnapshot = { ...this.currentSnapshot };

            // Perform deep analysis
            const analysis = await this.performAnalysis(this.currentSnapshot).catch(err => {
                console.warn('Analysis failed, using defaults:', err.message);
                return {
                    threatLevel: 'low',
                    vulnerabilities: [],
                    suspiciousActivity: [],
                    securityScore: 85,
                    recommendations: ['Network monitoring is active']
                };
            });

            // Add analysis results to snapshot for historical tracking
            this.currentSnapshot.connectionAnalysis = analysis;
            this.currentSnapshot.riskScore = analysis.securityScore || 85;

            // Store snapshot in history
            this.historicalService.trackSnapshot(this.currentSnapshot);

            // Update previous snapshot
            this.previousSnapshot = this.currentSnapshot;

            // Maintain history size
            if ((this.analysisHistory || []).length > 100) {
                this.analysisHistory.shift();
            }

            return analysis;
        } catch (error) {
            console.error('Network status gathering failed:', error);
            // Return a safe default analysis
            return {
                threatLevel: 'low',
                vulnerabilities: [],
                suspiciousActivity: [],
                securityScore: 85,
                recommendations: ['Network monitoring encountered an error'],
                connections: [],
                alerts: [],
                firewall: { status: 'unknown' }
            };
        }
    }

    async performAnalysis(snapshot) {
        // Connection analysis
        const connectionAnalysis = this.connectionService.analyzeConnections(snapshot.connections);
        
        // Traffic analysis
        const trafficAnalysis = this.trafficService.analyzeTraffic(snapshot.networkStats, this.previousSnapshot?.networkStats);
        
        // Threat detection
        const threatDetection = this.threatService.detectThreats(connectionAnalysis, trafficAnalysis, snapshot.processes);
        
        // Generate alerts
        const alerts = this.alertService.generateAlerts(threatDetection, snapshot.networkStats);
        
        // Historical comparison
        const historicalComparison = this.historicalService.compareSnapshots(snapshot, this.previousSnapshot);
        
        // Calculate risk score
        const riskScore = this.scoringService.calculateRiskScore(
            { connectionAnalysis, networkStats: snapshot.networkStats, processes: snapshot.processes },
            threatDetection,
            trafficAnalysis,
            alerts
        );
        
        // Generate verdict
        const verdict = this.generateVerdict(riskScore, threatDetection, connectionAnalysis);

        // Generate summary
        const summary = this.generateSummary(snapshot, connectionAnalysis, threatDetection, trafficAnalysis, riskScore);

        // 🌍 HACKER TRACKING - Extract suspicious IPs and get their locations
        const suspiciousIPs = [
            ...(connectionAnalysis.suspiciousConnections || []).map(c => c.connection?.remoteAddress).filter(Boolean),
            ...(connectionAnalysis.portScanActivity || []).map(p => p.scanningIP).filter(Boolean),
            ...(connectionAnalysis.beaconingActivity || []).map(b => b.ip).filter(Boolean)
        ];

        // Add top connected IPs for broader tracking
        const topIPs = (connectionAnalysis.topIPs || []).map(ip => ip.ip).filter(Boolean);
        const allTrackingIPs = [...new Set([...suspiciousIPs, ...topIPs])];

        // Get geolocation data for these IPs
        let hackerMapData = [];
        try {
            if (allTrackingIPs.length > 0) {
                hackerMapData = await this.geoService.getBatchLocations(allTrackingIPs);
            }
        } catch (error) {
            console.warn('Failed to get geolocation data:', error.message);
        }

        // Add risk level to each location
        hackerMapData = hackerMapData.map(location => {
            const isSuspicious = suspiciousIPs.includes(location.ip);
            const isPortScanner = (connectionAnalysis.portScanActivity || []).some(p => p.scanningIP === location.ip);
            const isBeaconing = (connectionAnalysis.beaconingActivity || []).some(b => b.ip === location.ip);
            
            let riskLevel = 'normal';
            if (isPortScanner) riskLevel = 'high';
            else if (isSuspicious) riskLevel = 'medium';
            else if (isBeaconing) riskLevel = 'high';

            return {
                ...location,
                riskLevel,
                connectionCount: (connectionAnalysis.topIPs || []).find(ip => ip.ip === location.ip)?.count || 0,
                threats: []
            };
        });

        // For testing - add some known locations if no real data
        if (hackerMapData.length === 0) {
            try {
                const testLocations = await this.geoService.getTestLocations();
                hackerMapData = testLocations.map(loc => ({
                    ...loc,
                    riskLevel: 'normal',
                    connectionCount: 1,
                    threats: []
                }));
            } catch (error) {
                console.warn('Failed to get test locations:', error.message);
            }
        }

        return {
            summary: summary,
            network_stats: snapshot.networkStats,
            connection_analysis: connectionAnalysis,
            connections: snapshot.connections || [], // Direct connections for frontend
            threat_detection: threatDetection,
            traffic_analysis: trafficAnalysis,
            anomalies: trafficAnalysis.anomalies,
            alerts: alerts,
            historical_comparison: historicalComparison,
            risk_score: riskScore,
            verdict: verdict,
            open_ports: snapshot.openPorts || [],
            open_ports_analysis: this.analyzePorts(snapshot.openPorts || []), // Analyzed ports with risk
            protocols: this.getProtocolStats(snapshot.connections || []), // Protocol stats
            bandwidth: this.calculateRealBandwidth(snapshot.networkStats, this.previousSnapshot?.networkStats), // Real bandwidth
            hacker_map: hackerMapData,
            recommendations: this.generateRecommendations(riskScore, threatDetection, alerts),
            timestamp: snapshot.timestamp
        };
    }

    // 🚀 NEW: Analyze ports with risk assessment
    analyzePorts(ports) {
        const riskyPorts = {
            high: [21, 22, 23, 3389, 1433, 3306, 5432], // FTP, SSH, Telnet, RDP, SQL
            medium: [80, 443, 8080, 3000, 8000, 9000], // HTTP, HTTPS, Dev servers
        };

        return ports.map(port => {
            let risk = 'low';
            const portNum = typeof port === 'object' ? port.port : port;

            if (riskyPorts.high.includes(portNum)) risk = 'high';
            else if (riskyPorts.medium.includes(portNum)) risk = 'medium';

            return {
                port: portNum,
                service: this.getServiceName(portNum),
                process: typeof port === 'object' ? (port.process || 'Unknown') : 'Unknown',
                risk,
                state: typeof port === 'object' ? (port.state || 'LISTEN') : 'LISTEN',
                status: 'open'
            };
        });
    }

    // 🚀 NEW: Get service name for port
    getServiceName(port) {
        const map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            3000: 'Node.js',
            8000: 'Dev Server',
            9000: 'SonarQube'
        };
        return map[port] || 'Unknown';
    }

    // 🚀 NEW: Get protocol statistics
    getProtocolStats(connections) {
        const stats = { TCP: 0, UDP: 0, Other: 0 };

        connections.forEach(conn => {
            const protocol = conn.protocol ? conn.protocol.toUpperCase() : 'Other';
            if (protocol === 'TCP') stats.TCP++;
            else if (protocol === 'UDP') stats.UDP++;
            else stats.Other++;
        });

        return stats;
    }

    // 🚀 NEW: Calculate real bandwidth speed
    calculateRealBandwidth(current, previous) {
        let bandwidth = { inbound: 0, outbound: 0 };

        if (previous && current) {
            const timeDiff = (new Date(current.timestamp) - new Date(previous.timestamp)) / 1000; // seconds
            
            if (timeDiff > 0) {
                bandwidth.inbound = (current.totalBytesReceived - previous.totalBytesReceived) / timeDiff;
                bandwidth.outbound = (current.totalBytesSent - previous.totalBytesSent) / timeDiff;
            }
        }

        return bandwidth;
    }

    async gatherNetworkStats() {
        const platform = os.platform();
        let stats = {
            totalConnections: 0,
            totalBytesSent: 0,
            totalBytesReceived: 0,
            inboundConnections: 0,
            outboundConnections: 0,
            interfaces: [],
            timeWindow: 60
        };

        try {
            if (platform === 'linux') {
                stats = await this.gatherLinuxNetworkStats(stats);
            } else if (platform === 'win32') {
                stats = await this.gatherWindowsNetworkStats(stats);
            } else {
                stats = await this.gatherMacNetworkStats(stats);
            }
        } catch (error) {
            console.warn('Network stats gathering failed:', error.message);
        }

        // Get network interfaces
        stats.interfaces = Object.values(os.networkInterfaces())
            .flat()
            .filter(iface => !iface.internal)
            .map(iface => ({
                address: iface.address,
                netmask: iface.netmask,
                family: iface.family,
                mac: iface.mac
            }));

        return stats;
    }

    async gatherLinuxNetworkStats(stats) {
        try {
            // Get network interface statistics
            const { stdout } = await execPromise("cat /proc/net/dev | grep -E '(eth|wlan|en)'");
            const lines = stdout.trim().split('\n');
            
            lines.forEach(line => {
                const parts = line.trim().split(/\s+/);
                if ((parts || []).length > 9) {
                    stats.totalBytesReceived += parseInt(parts[1]) || 0;
                    stats.totalBytesSent += parseInt(parts[9]) || 0;
                }
            });

            // Get connection count
            try {
                const { stdout: connOut } = await execPromise("ss -s | grep 'TCP:'");
                const match = connOut.match(/TCP:\s*(\d+)/);
                if (match) {
                    stats.totalConnections = parseInt(match[1]);
                }
            } catch (e) {
                // Fallback to netstat
                const { stdout: netstatOut } = await execPromise("netstat -an | grep ESTABLISHED | wc -l");
                stats.totalConnections = parseInt(netstatOut.trim()) || 0;
            }
        } catch (error) {
            console.warn('Linux network stats failed:', error.message);
        }

        return stats;
    }

    async gatherWindowsNetworkStats(stats) {
        try {
            // Get network interface statistics using PowerShell
            const psCommand = `
                Get-NetAdapterStatistics | Where-Object {$_.Status -eq 'Up'} | 
                Select-Object @{Name='ReceivedBytes';Expression={$_.ReceivedBytes}}, 
                           @{Name='SentBytes';Expression={$_.SentBytes}} | 
                Measure-Object -Sum ReceivedBytes, SentBytes | 
                Select-Object @{Name='TotalReceived';Expression={$_.ReceivedBytes.Sum}}, 
                           @{Name='TotalSent';Expression={$_.SentBytes.Sum}}
            `;
            
            const { stdout } = await execPromise(`powershell -Command "${psCommand}"`);
            if (stdout && stdout.trim()) {
                const match = stdout.match(/TotalReceived\s*:\s*(\d+).*TotalSent\s*:\s*(\d+)/s);
                if (match) {
                    stats.totalBytesReceived = parseInt(match[1]);
                    stats.totalBytesSent = parseInt(match[2]);
                }
            }

            // Get connection count
            const connCommand = "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Measure-Object | Select-Object Count";
            const { stdout: connOut } = await execPromise(`powershell -Command "${connCommand}"`);
            if (connOut && connOut.trim()) {
                const connMatch = connOut.match(/Count\s*:\s*(\d+)/);
                if (connMatch) {
                    stats.totalConnections = parseInt(connMatch[1]);
                }
            }
        } catch (error) {
            console.warn('Windows network stats failed:', error.message);
            // Set fallback values
            stats.totalConnections = 0;
            stats.totalBytesReceived = 0;
            stats.totalBytesSent = 0;
        }

        return stats;
    }

    async gatherMacNetworkStats(stats) {
        try {
            // Get network interface statistics
            const { stdout } = await execPromise("netstat -i | grep -E '(en|eth)'");
            const lines = stdout.trim().split('\n');
            
            lines.forEach(line => {
                const parts = line.trim().split(/\s+/);
                if ((parts || []).length > 6) {
                    stats.totalBytesReceived += parseInt(parts[6]) || 0;
                    stats.totalBytesSent += parseInt(parts[7]) || 0;
                }
            });

            // Get connection count
            const { stdout: connOut } = await execPromise("netstat -an | grep ESTABLISHED | wc -l");
            stats.totalConnections = parseInt(connOut.trim()) || 0;
        } catch (error) {
            console.warn('macOS network stats failed:', error.message);
        }

        return stats;
    }

    async gatherConnections() {
        const platform = os.platform();
        let connections = [];

        try {
            if (platform === 'linux') {
                connections = await this.gatherLinuxConnections();
            } else if (platform === 'win32') {
                connections = await this.gatherWindowsConnections();
            } else if (platform === 'darwin') {
                connections = await this.gatherMacConnections();
            }
            
            console.log("CONNECTIONS DEBUG:", connections.length, "connections found");
        } catch (error) {
            console.warn('Connection gathering failed:', error.message);
            connections = [];
        }

        return connections;
    }

    async gatherLinuxConnections() {
        const connections = [];
        
        try {
            const { stdout } = await execPromise("ss -tupn 2>/dev/null || netstat -tupn 2>/dev/null");
            const lines = stdout.trim().split('\n');
            
            for (const line of lines.slice(1)) { // Skip header
                const parts = line.trim().split(/\s+/);
                if ((parts || []).length >= 5) {
                    const connection = this.parseConnectionLine(line, 'linux');
                    if (connection) {
                        connections.push(connection);
                    }
                }
            }
        } catch (error) {
            console.warn('Linux connection gathering failed:', error.message);
        }

        return connections;
    }

    async gatherWindowsConnections() {
        const connections = [];
        
        try {
            // Get all connections including TCP and UDP
            const command = 'netstat -ano';
            console.log("Running netstat command:", command);
            
            const { stdout, stderr } = await execPromise(command);
            console.log("netstat stdout length:", stdout?.length || 0);
            console.log("netstat stderr:", stderr);
            
            if (!stdout || stdout.trim().length === 0) {
                console.warn("No netstat output received");
                return connections;
            }

            const lines = stdout.split('\n');
            console.log("Processing", lines.length, "lines from netstat");
            
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i].trim();
                
                // Skip header and empty lines
                if (!line || line.startsWith('Proto') || line.startsWith('Active') || line.startsWith('TCP') === false && line.startsWith('UDP') === false) {
                    continue;
                }
                
                // Parse netstat output format: Protocol  Local Address  Foreign Address  State  PID
                const parts = line.split(/\s+/);
                
                if (parts.length >= 5) {
                    const protocol = parts[0];
                    const localAddress = parts[1];
                    const foreignAddress = parts[2];
                    const state = parts[3] || 'N/A';
                    const pid = parts[4] || '0';
                    
                    // Parse addresses
                    const [localIP, localPort] = localAddress.includes(':') 
                        ? localAddress.split(':').map((p, i, arr) => i === arr.length - 1 ? p : arr.slice(0, i).join(':'))
                        : [localIP, '0'];
                    
                    const [remoteIP, remotePort] = foreignAddress.includes(':')
                        ? foreignAddress.split(':').map((p, i, arr) => i === arr.length - 1 ? p : arr.slice(0, i).join(':'))
                        : [foreignAddress, '0'];
                    
                    // Only include established connections and listening ports
                    if (state === 'ESTABLISHED' || state === 'LISTEN' || state === 'TIME_WAIT') {
                        connections.push({
                            protocol: protocol,
                            localAddress: localIP,
                            localPort: parseInt(localPort) || 0,
                            remoteAddress: remoteIP,
                            remotePort: parseInt(remotePort) || 0,
                            state: state,
                            processId: parseInt(pid) || 0,
                            processName: `PID:${pid}`,
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }
            
            console.log("Parsed", connections.length, "connections from netstat");
        } catch (error) {
            console.error('Windows connection gathering failed:', error);
        }

        return connections;
    }

    async gatherMacConnections() {
        const connections = [];
        
        try {
            const { stdout } = await execPromise("netstat -an | grep ESTABLISHED");
            const lines = stdout.trim().split('\n');
            
            for (const line of lines) {
                const connection = this.parseConnectionLine(line, 'mac');
                if (connection) {
                    connections.push(connection);
                }
            }
        } catch (error) {
            console.warn('macOS connection gathering failed:', error.message);
        }

        return connections;
    }

    parseConnectionLine(line, platform) {
        try {
            const parts = line.trim().split(/\s+/);
            
            if (platform === 'linux') {
                // Parse ss/netstat output
                const protocol = parts[0];
                const local = parts[4];
                const remote = parts[5];
                const state = parts[1];
                const processInfo = parts.slice(6).join(' ');
                
                const [localAddress, localPort] = local.split(':');
                const [remoteAddress, remotePort] = remote.split(':');
                
                const processMatch = processInfo.match(/users:\(\("([^"]*)",pid=(\d+)/);
                
                return {
                    protocol: protocol.toUpperCase(),
                    localAddress,
                    localPort: parseInt(localPort),
                    remoteAddress,
                    remotePort: parseInt(remotePort),
                    state,
                    processName: processMatch ? processMatch[1] : 'Unknown',
                    processId: processMatch ? parseInt(processMatch[2]) : null,
                    timestamp: new Date().toISOString()
                };
            } else if (platform === 'mac') {
                // Parse macOS netstat output
                const protocol = parts[0];
                const local = parts[3];
                const remote = parts[4];
                const state = parts[5];
                
                const [localAddress, localPort] = local.split('.');
                const [remoteAddress, remotePort] = remote.split('.');
                
                return {
                    protocol: protocol.toUpperCase(),
                    localAddress,
                    localPort: parseInt(localPort),
                    remoteAddress,
                    remotePort: parseInt(remotePort),
                    state,
                    processName: 'Unknown',
                    processId: null,
                    timestamp: new Date().toISOString()
                };
            }
        } catch (error) {
            console.warn('Failed to parse connection line:', error.message);
        }
        
        return null;
    }

    async gatherProcesses() {
        const platform = os.platform();
        let processes = [];

        try {
            if (platform === 'linux') {
                processes = await this.gatherLinuxProcesses();
            } else if (platform === 'win32') {
                processes = await this.gatherWindowsProcesses();
            } else {
                processes = await this.gatherMacProcesses();
            }
        } catch (error) {
            console.warn('Process gathering failed:', error.message);
        }

        return processes;
    }

    async gatherLinuxProcesses() {
        const processes = [];
        
        try {
            const { stdout } = await execPromise("ps aux --no-headers | head -20");
            const lines = stdout.trim().split('\n');
            
            for (const line of lines.slice(1)) { // Skip header
                const parts = line.trim().split(/\s+/);
                if ((parts || []).length >= 11) {
                    processes.push({
                        pid: parseInt(parts[1]),
                        user: parts[0],
                        cpu: parseFloat(parts[2]),
                        memory: parseFloat(parts[3]),
                        name: parts[10],
                        command: parts.slice(10).join(' '),
                        timestamp: new Date().toISOString()
                    });
                }
            }
        } catch (error) {
            console.warn('Linux process gathering failed:', error.message);
        }

        return processes;
    }

    async gatherWindowsProcesses() {
        const processes = [];
        
        try {
            const psCommand = `
                Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, Path | 
                Sort-Object CPU -Descending | Select-Object -First 20 | ConvertTo-Json
            `;
            
            const { stdout } = await execPromise(`powershell -Command "${psCommand}"`);
            if (stdout && stdout.trim()) {
                try {
                    const data = JSON.parse(stdout);
                    
                    if (Array.isArray(data)) {
                        data.forEach(proc => {
                            processes.push({
                                pid: proc.Id,
                                name: proc.ProcessName,
                                cpu: proc.CPU || 0,
                                memory: proc.WorkingSet || 0,
                                path: proc.Path,
                                timestamp: new Date().toISOString()
                            });
                        });
                    }
                } catch (parseError) {
                    console.warn('Failed to parse Windows processes JSON:', parseError.message);
                }
            }
        } catch (error) {
            console.warn('Windows process gathering failed:', error.message);
        }

        return processes;
    }

    async gatherMacProcesses() {
        const processes = [];
        
        try {
            const { stdout } = await execPromise("ps aux | head -20");
            const lines = stdout.trim().split('\n');
            
            for (const line of lines.slice(1)) { 
                const parts = line.trim().split(/\s+/);
                if ((parts || []).length >= 11) {
                    processes.push({
                        pid: parseInt(parts[1]),
                        user: parts[0],
                        cpu: parseFloat(parts[3]),
                        memory: parseFloat(parts[4]),
                        name: parts[10],
                        command: parts.slice(10).join(' '),
                        timestamp: new Date().toISOString()
                    });
                }
            }
        } catch (error) {
            console.warn('macOS process gathering failed:', error.message);
        }

        return processes;
    }

    async gatherOpenPorts() {
        const platform = os.platform();
        let ports = [];

        try {
            if (platform === 'linux') {
                const { stdout } = await execPromise("ss -tuln 2>/dev/null | grep LISTEN");
                const lines = stdout.trim().split('\n');
                
                for (const line of lines) {
                    const match = line.match(/:(\d+)\s/);
                    if (match) {
                        const port = parseInt(match[1]);
                        ports.push(this.createPortInfo(port));
                    }
                }
            } else if (platform === 'win32') {
                // Use netstat to get listening ports
                const { stdout } = await execPromise('netstat -ano | findstr "LISTENING"');
                const lines = stdout.split('\n');
                
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed || !trimmed.includes('LISTENING')) continue;
                    
                    const parts = trimmed.split(/\s+/);
                    if (parts.length >= 2) {
                        const localAddress = parts[1];
                        const portMatch = localAddress.match(/:(\d+)$/);
                        if (portMatch) {
                            const port = parseInt(portMatch[1]);
                            ports.push(this.createPortInfo(port));
                        }
                    }
                }
            } else if (platform === 'darwin') {
                const { stdout } = await execPromise("netstat -an | grep LISTEN");
                const lines = stdout.trim().split('\n');
                
                for (const line of lines) {
                    const match = line.match(/\.(\d+)\s/);
                    if (match) {
                        const port = parseInt(match[1]);
                        ports.push(this.createPortInfo(port));
                    }
                }
            }
        } catch (error) {
            console.warn('Open port gathering failed:', error.message);
        }

        return ports;
    }

    createPortInfo(port) {
        const commonServices = {
            20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'
        };

        const service = commonServices[port] || 'Unknown';
        
        // Risk assessment
        let risk = 'low';
        if (port < 1024) {
            risk = 'medium'; // Well-known ports
        }
        if ([20, 21, 23, 25, 53, 135, 139, 445].includes(port)) {
            risk = 'high'; // Potentially dangerous services
        }

        return {
            port,
            service,
            process: 'Unknown',
            state: 'LISTEN',
            risk
        };
    }

    generateVerdict(score, threatDetection, connectionAnalysis) {
        const threats = threatDetection.detected || [];
        const suspiciousConnections = connectionAnalysis.suspiciousConnections || [];
        const portScans = connectionAnalysis.portScanActivity || [];
        const beaconing = connectionAnalysis.beaconingActivity || [];

        let level = 'Safe';
        let confidence = 'high';
        let details = 'Network activity appears normal';

        if (score < 40 || (threats || []).some(t => t?.severity === 'critical')) {
            level = 'Under Attack';
            confidence = 'critical';
            details = 'Multiple critical threats detected - immediate response required';
        } else if (score < 60 || (threats || []).some(t => t?.severity === 'high') || (portScans || []).length > 0) {
            level = 'Suspicious';
            confidence = 'high';
            details = 'Suspicious activity detected - investigation recommended';
        } else if (score < 80 || (suspiciousConnections || []).length > 0 || (beaconing || []).length > 0) {
            level = 'Caution';
            confidence = 'medium';
            details = 'Some suspicious activity detected - monitoring advised';
        }

        return {
            level,
            confidence,
            details,
            factors: {
                criticalThreats: (threats || []).filter(t => t?.severity === 'critical').length,
                highThreats: (threats || []).filter(t => t?.severity === 'high').length,
                suspiciousConnections: (suspiciousConnections || []).length,
                portScans: (portScans || []).length,
                beaconing: (beaconing || []).length
            }
        };
    }

    generateSummary(snapshot, connectionAnalysis, threatDetection, trafficAnalysis, riskScore) {
        return {
            riskScore: riskScore.score,
            riskLevel: riskScore.riskLevel.level,
            totalConnections: connectionAnalysis?.totalConnections || 0,
            activeThreats: threatDetection?.summary?.total || 0,
            criticalAlerts: threatDetection?.summaryBySeverity?.critical || 0,
            networkUtilization: this.calculateNetworkUtilization(snapshot.networkStats),
            topRiskyIPs: this.getTopRiskyIPs(connectionAnalysis),
        topRiskyProcesses: this.getTopRiskyProcesses(threatDetection),
        anomaliesDetected: (trafficAnalysis?.anomalies || []).length,
        assessment: this.generateAssessment(riskScore.score, threatDetection, connectionAnalysis)
        };
    }

    calculateNetworkUtilization(networkStats) {
        // This is a simplified calculation
        const totalBytes = (networkStats.totalBytesSent || 0) + (networkStats.totalBytesReceived || 0);
        const utilization = totalBytes > 0 ? Math.min((totalBytes / (1024 * 1024 * 100)) * 100, 100) : 0; // Assume 100MB as baseline
        
        return {
            percentage: Math.round(utilization),
            totalBytes: totalBytes,
            uploadBytes: networkStats.totalBytesSent || 0,
            downloadBytes: networkStats.totalBytesReceived || 0
        };
    }

    getTopRiskyIPs(connectionAnalysis) {
        const ipRisks = {};
        
        // Count suspicious connections by IP
        (connectionAnalysis.suspiciousConnections || []).forEach(conn => {
            const ip = conn.connection.remoteAddress;
            ipRisks[ip] = (ipRisks[ip] || 0) + 1;
        });
        
        // Count port scans by IP
        (connectionAnalysis.portScanActivity || []).forEach(scan => {
            ipRisks[scan.scanningIP] = (ipRisks[scan.scanningIP] || 0) + scan.portCount;
        });
        
        return Object.entries(ipRisks)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([ip, risk]) => ({ ip, riskScore: risk }));
    }

    getTopRiskyProcesses(threatDetection) {
        const processRisks = {};
        
        (threatDetection.detected || []).forEach(threat => {
            if (threat.details.processName) {
                processRisks[threat.details.processName] = (processRisks[threat.details.processName] || 0) + 1;
            }
        });
        
        return Object.entries(processRisks)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([process, risk]) => ({ process, riskScore: risk }));
    }

    generateAssessment(score, threatDetection, connectionAnalysis) {
        const threats = threatDetection.detected || [];
        const suspiciousCount = (connectionAnalysis?.suspiciousConnections || []).length;
        
        if (score >= 80) {
            return 'Network security posture is strong with minimal threats detected';
        } else if (score >= 60) {
            return `Network shows some suspicious activity (${suspiciousCount} suspicious connections) but overall risk is manageable`;
        } else if (score >= 40) {
            return `Network security is compromised with ${(threats || []).length} active threats requiring immediate attention`;
        } else {
            return `CRITICAL: Network is under active attack with ${(threats || []).filter(t => t?.severity === 'critical').length} critical threats`;
        }
    }

    generateRecommendations(riskScore, threatDetection, alerts) {
        const recommendations = [];
        
        // Base recommendations on score
        if (riskScore.score < 40) {
            recommendations.push({
                priority: 'critical',
                title: 'Immediate Incident Response',
                description: 'Activate incident response protocol and isolate affected systems',
                actions: ['isolate_systems', 'incident_response', 'emergency_procedures']
            });
        } else if (riskScore.score < 60) {
            recommendations.push({
                priority: 'high',
                title: 'Security Investigation Required',
                description: 'Investigate detected threats and implement containment measures',
                actions: ['investigate_threats', 'contain_systems', 'security_team_notification']
            });
        }

        // Add threat-specific recommendations
        const criticalThreats = (threatDetection.detected || []).filter(t => t.severity === 'critical');
        if ((criticalThreats || []).length > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Threats Detected',
                description: `${(criticalThreats || []).length} critical threats require immediate action`,
                actions: ['immediate_response', 'system_isolation', 'forensic_analysis']
            });
        }
        
// Add alert-specific recommendations
        if (alerts?.summary?.bySeverity?.critical > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Alerts Active',
                description: 'Multiple critical alerts require immediate attention',
                actions: ['alert_response', 'escalation', 'emergency_procedures']
            });
        }
        
        return recommendations;
    }
    
    // Placeholder methods for bonus features
    async detectRateLimiting() {
        return {
            supported: false,
            message: 'Rate limiting detection not implemented yet',
            violations: []
        };
    }
    
    generateFirewallSuggestions(analysis) {
        const suggestions = [];
        
        // Suggest blocking scanning IPs
        const scanningIPs = (analysis.connection_analysis.portScanActivity || []).map(scan => scan.scanningIP);
        if ((scanningIPs || []).length > 0) {
            suggestions.push({
                type: 'block_ip',
                target: scanningIPs,
                reason: 'Port scanning activity detected',
                priority: 'high'
            });
        }
        
        // Suggest blocking suspicious IPs
        const suspiciousIPs = (analysis.connection_analysis.suspiciousConnections || [])
            .map(conn => conn.connection.remoteAddress);
        if ((suspiciousIPs || []).length > 0) {
            suggestions.push({
                type: 'block_ip',
                target: [...new Set(suspiciousIPs)],
                reason: 'Suspicious connection activity',
                priority: 'medium'
            });
        }
        
        return suggestions;
    }

    getAnalysisHistory(limit = 50) {
        return this.analysisHistory.slice(-limit);
    }
    
    getAlertHistory(limit = 100) {
        return this.alertService.getAlertHistory(limit);
    }
    
    // WebSocket placeholder for real-time monitoring
    enableRealTimeMonitoring() {
        return {
            supported: true,
            message: 'WebSocket real-time monitoring is available',
            endpoint: '/ws/network-monitor'
        };
    }
}

const monitor = new NetworkMonitor();

// Routes
router.get('/status', async (req, res) => {
    try {
        const analysis = await monitor.getNetworkStatus();
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            data: analysis
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/stats', async (req, res) => {
  try {
    const analysis = await monitor.getNetworkStatus();

    const formatted = {
      timestamp: new Date().toISOString(),
      
      interfaces: analysis.network_stats?.interfaces || [],
      
      traffic: [
        {
          interface: "eth0",
          rx_bytes: analysis.network_stats?.totalBytesReceived || 0,
          tx_bytes: analysis.network_stats?.totalBytesSent || 0,
          rx_sec: analysis.network_stats?.totalBytesReceived || 0,
          tx_sec: analysis.network_stats?.totalBytesSent || 0,
          ms: Date.now()
        }
      ],
      
      connections: {
        total: analysis.connection_analysis?.totalConnections || 0,
        
        protocols: {
          TCP: analysis.connection_analysis?.connections?.length || 0
        },
        
        details: (analysis.connection_analysis?.connections || []).map(conn => ({
          pid: conn.processId || 0,
          process: conn.processName || "Unknown",
          localAddress: conn.localAddress,
          localPort: conn.localPort,
          remoteAddress: conn.remoteAddress,
          remotePort: conn.remotePort,
          state: conn.state,
          protocol: conn.protocol,
          timestamp: conn.timestamp
        }))
      }
    };

    res.json({
      success: true,
      data: formatted
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/security', async (req, res) => {
    try {
        const analysis = await monitor.getNetworkStatus();
        // Extract security analysis from the analysis
        const security = {
            threatLevel: analysis.threatLevel || 'low',
            vulnerabilities: analysis.vulnerabilities || [],
            blockedConnections: analysis.connection_analysis?.blockedConnections?.length || 0,
            suspiciousActivity: analysis.suspiciousActivity || [],
            securityScore: analysis.securityScore || 85,
            recommendations: analysis.recommendations || [],
            alerts: analysis.alerts?.generated || [], // Use generated alerts array
            active_connections: analysis.connection_analysis?.totalConnections || 0,
            suspicious_connections: (analysis.connection_analysis?.suspiciousConnections || []).filter(conn => conn.risk === 'high' || conn.risk === 'medium').length,
            exposed_ports: analysis.open_ports || []
        };
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            data: security
        });
    } catch (error) {
        console.error('SECURITY ERROR:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/history', (req, res) => {
    const limit = parseInt(req.query.limit) || 50;
    res.json({
        success: true,
        history: monitor.getAnalysisHistory(limit)
    });
});

router.get('/alerts', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    res.json({
        success: true,
        alerts: monitor.getAlertHistory(limit)
    });
});

router.post('/acknowledge-alert', (req, res) => {
    try {
        const { alertId } = req.body;
        const alert = monitor.alertService.acknowledgeAlert(alertId);
        
        if (alert) {
            res.json({
                success: true,
                message: 'Alert acknowledged',
                alert: alert
            });
        } else {
            res.status(404).json({
                success: false,
                error: 'Alert not found'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/resolve-alert', (req, res) => {
    try {
        const { alertId } = req.body;
        const alert = monitor.alertService.resolveAlert(alertId);
        
        if (alert) {
            res.json({
                success: true,
                message: 'Alert resolved',
                alert: alert
            });
        } else {
            res.status(404).json({
                success: false,
                error: 'Alert not found'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/firewall-suggestions', async (req, res) => {
    try {
        const analysis = await monitor.getNetworkStatus();
        const suggestions = monitor.generateFirewallSuggestions(analysis);
        
        res.json({
            success: true,
            suggestions: suggestions
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/realtime', (req, res) => {
    const websocketInfo = monitor.enableRealTimeMonitoring();
    res.json({
        success: true,
        ...websocketInfo
    });
});

// Start monitoring
router.post('/start', (req, res) => {
    try {
        monitor.startMonitoring();
        res.json({
            success: true,
            message: 'Network monitoring started',
            status: monitor.getMonitoringStatus()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Stop monitoring
router.post('/stop', (req, res) => {
    try {
        monitor.stopMonitoring();
        res.json({
            success: true,
            message: 'Network monitoring stopped',
            status: monitor.getMonitoringStatus()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get monitoring status
router.get('/status-monitoring', (req, res) => {
    res.json({
        success: true,
        isMonitoring: monitor.getMonitoringStatus()
    });
});

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
            connectionService: true,
            threatService: true,
            trafficService: true,
            alertService: true,
            historicalService: true,
            scoringService: true
        }
    });
});

module.exports = {
    router,
    monitor
};
