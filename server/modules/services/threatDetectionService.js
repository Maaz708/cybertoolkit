class ThreatDetectionService {
    constructor() {
        this.threatTypes = {
            PORT_SCAN: 'PORT_SCAN',
            SUSPICIOUS_IP: 'SUSPICIOUS_IP',
            MALICIOUS_PROCESS: 'MALICIOUS_PROCESS',
            TRAFFIC_ANOMALY: 'TRAFFIC_ANOMALY',
            DATA_EXFILTRATION: 'DATA_EXFILTRATION',
            BEACONING: 'BEACONING',
            UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS'
        };

        this.severityLevels = {
            LOW: 'low',
            MEDIUM: 'medium',
            HIGH: 'high',
            CRITICAL: 'critical'
        };

        this.maliciousProcesses = [
            'powershell.exe', 'cmd.exe', 'bash', 'sh', 'python.exe', 'python3',
            'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe',
            'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'netcat', 'nc.exe'
        ];

        this.suspiciousProcessPatterns = [
            /powershell.*-enc/i,
            /cmd.*\/c/i,
            /bash.*-c/i,
            /python.*-c/i,
            /wscript.*\.js/i,
            /rundll32.*\.dll/i
        ];
    }

    detectThreats(connectionAnalysis, trafficStats, processList) {
        const threats = {
            detected: [],
            summary: {
                total: 0,
                byType: {},
                bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
                highRiskProcesses: [],
            },
            recommendations: []
        };

        // Initialize threat type counters
        Object.values(this.threatTypes).forEach(type => {
            threats.summary.byType[type] = 0;
        });

        // Detect port scanning threats
        const portScanThreats = this.detectPortScanThreats(connectionAnalysis.portScanActivity);
        threats.detected.push(...portScanThreats);

        // Detect suspicious IP threats
        const suspiciousIPThreats = this.detectSuspiciousIPThreats(connectionAnalysis.suspiciousConnections);
        threats.detected.push(...suspiciousIPThreats);

        // Detect malicious process threats
        const processThreats = this.detectMaliciousProcessThreats(connectionAnalysis, processList);
        threats.detected.push(...processThreats);

        // Detect traffic anomaly threats
        const anomalyThreats = this.detectTrafficAnomalyThreats(trafficStats, connectionAnalysis);
        threats.detected.push(...anomalyThreats);

        // Detect beaconing threats
        const beaconingThreats = this.detectBeaconingThreats(connectionAnalysis.beaconingActivity);
        threats.detected.push(...beaconingThreats);

        // Detect data exfiltration threats
        const exfiltrationThreats = this.detectDataExfiltrationThreats(trafficStats, connectionAnalysis);
        threats.detected.push(...exfiltrationThreats);

        // Calculate summary statistics
        this.calculateThreatSummary(threats);

        // Generate recommendations
        threats.recommendations = this.generateThreatRecommendations(threats);

        return threats;
    }

    detectPortScanThreats(portScanActivity) {
        const threats = [];

        portScanActivity.forEach(scan => {
            const threat = {
                id: this.generateThreatId(),
                type: this.threatTypes.PORT_SCAN,
                severity: this.mapScanSeverityToThreatSeverity(scan.severity),
                title: 'Port Scan Detected',
                description: `IP ${scan.scanningIP} is scanning ${scan.portCount} ports`,
                details: {
                    scanningIP: scan.scanningIP,
                    portsTargeted: scan.portsTargeted,
                    portCount: scan.portCount,
                    connectionCount: scan.connectionCount,
                    timeSpan: scan.timeSpan,
                    processes: scan.processes
                },
                timestamp: new Date().toISOString(),
                recommendations: this.generatePortScanRecommendations(scan)
            };

            threats.push(threat);
        });

        return threats;
    }

    detectSuspiciousIPThreats(suspiciousConnections) {
        const threats = [];
        const ipThreatMap = {};

        suspiciousConnections.forEach(conn => {
            const ip = conn.connection.remoteAddress;
            if (!ipThreatMap[ip]) {
                ipThreatMap[ip] = {
                    ip: ip,
                    reasons: [],
                    connections: [],
                    risk: conn.risk
                };
            }
            ipThreatMap[ip].reasons.push(...conn.reasons);
            ipThreatMap[ip].connections.push(conn.connection);
            if (conn.risk === 'high' && ipThreatMap[ip].risk !== 'high') {
                ipThreatMap[ip].risk = 'high';
            }
        });

        Object.values(ipThreatMap).forEach(ipThreat => {
            const threat = {
                id: this.generateThreatId(),
                type: this.threatTypes.SUSPICIOUS_IP,
                severity: ipThreat.risk === 'high' ? this.severityLevels.HIGH : this.severityLevels.MEDIUM,
                title: 'Suspicious IP Activity',
                description: `Suspicious activity detected from IP ${ipThreat.ip}`,
                details: {
                    ip: ipThreat.ip,
                    reasons: [...new Set(ipThreat.reasons)],
                    connectionCount: ipThreat.connections.length,
                    connections: ipThreat.connections
                },
                timestamp: new Date().toISOString(),
                recommendations: this.generateSuspiciousIPRecommendations(ipThreat)
            };

            threats.push(threat);
        });

        return threats;
    }

    detectMaliciousProcessThreats(connectionAnalysis, processList) {
        const threats = [];
        const processConnections = {};

        // Group connections by process
        connectionAnalysis.suspiciousConnections.forEach(conn => {
            const processName = conn.connection.processName;
            if (processName && this.isMaliciousProcess(processName)) {
                if (!processConnections[processName]) {
                    processConnections[processName] = [];
                }
                processConnections[processName].push(conn);
            }
        });

        // Check process list for suspicious processes
        if (processList) {
            processList.forEach(process => {
                if (this.isMaliciousProcess(process.name)) {
                    if (!processConnections[process.name]) {
                        processConnections[process.name] = [];
                    }
                }
            });
        }

        Object.entries(processConnections).forEach(([processName, connections]) => {
            const threat = {
                id: this.generateThreatId(),
                type: this.threatTypes.MALICIOUS_PROCESS,
                severity: this.severityLevels.HIGH,
                title: 'Malicious Process Detected',
                description: `Suspicious process ${processName} detected with network activity`,
                details: {
                    processName: processName,
                    connectionCount: connections.length,
                    connections: connections.map(c => c.connection),
                    reasons: [...new Set(connections.flatMap(c => c.reasons))]
                },
                timestamp: new Date().toISOString(),
                recommendations: this.generateMaliciousProcessRecommendations(processName, connections)
            };

            threats.push(threat);
        });

        return threats;
    }

    detectTrafficAnomalyThreats(trafficStats, connectionAnalysis) {
        const threats = [];

        // Detect traffic spikes
        if (trafficStats.anomalies && trafficStats.anomalies.length > 0) {
            trafficStats.anomalies.forEach(anomaly => {
                const threat = {
                    id: this.generateThreatId(),
                    type: this.threatTypes.TRAFFIC_ANOMALY,
                    severity: anomaly.severity === 'critical' ? this.severityLevels.CRITICAL : 
                             anomaly.severity === 'high' ? this.severityLevels.HIGH : 
                             this.severityLevels.MEDIUM,
                    title: 'Traffic Anomaly Detected',
                    description: anomaly.description,
                    details: {
                        anomalyType: anomaly.type,
                        currentValue: anomaly.currentValue,
                        expectedValue: anomaly.expectedValue,
                        deviation: anomaly.deviation
                    },
                    timestamp: new Date().toISOString(),
                    recommendations: this.generateTrafficAnomalyRecommendations(anomaly)
                };

                threats.push(threat);
            });
        }

        // Detect abnormal upload/download ratios
        if (trafficStats.uploadDownloadRatio) {
            const ratio = trafficStats.uploadDownloadRatio;
            if (ratio > 10) { // High upload ratio
                threats.push({
                    id: this.generateThreatId(),
                    type: this.threatTypes.DATA_EXFILTRATION,
                    severity: this.severityLevels.HIGH,
                    title: 'Potential Data Exfiltration',
                    description: `Unusual upload/download ratio detected: ${ratio.toFixed(2)}`,
                    details: {
                        ratio: ratio,
                        uploadBytes: trafficStats.totalBytesSent,
                        downloadBytes: trafficStats.totalBytesReceived
                    },
                    timestamp: new Date().toISOString(),
                    recommendations: ['Investigate potential data exfiltration', 'Monitor outbound traffic', 'Check for large file transfers']
                });
            }
        }

        return threats;
    }

    detectBeaconingThreats(beaconingActivity) {
        const threats = [];

        beaconingActivity.forEach(beacon => {
            const threat = {
                id: this.generateThreatId(),
                type: this.threatTypes.BEACONING,
                severity: beacon.risk === 'high' ? this.severityLevels.HIGH : this.severityLevels.MEDIUM,
                title: 'Beaconing Activity Detected',
                description: `Regular beaconing detected to IP ${beacon.ip}`,
                details: {
                    ip: beacon.ip,
                    connectionCount: beacon.connectionCount,
                    averageInterval: beacon.averageInterval,
                    ports: beacon.ports,
                    processes: beacon.processes
                },
                timestamp: new Date().toISOString(),
                recommendations: this.generateBeaconingRecommendations(beacon)
            };

            threats.push(threat);
        });

        return threats;
    }

    detectDataExfiltrationThreats(trafficStats, connectionAnalysis) {
        const threats = [];
        const largeTransfers = [];

        // Check for large outbound transfers
        if (trafficStats.connectionDetails) {
            trafficStats.connectionDetails.forEach(conn => {
                if (conn.bytesSent && conn.bytesSent > 50 * 1024 * 1024) { // > 50MB
                    largeTransfers.push({
                        remoteAddress: conn.remoteAddress,
                        remotePort: conn.remotePort,
                        bytesSent: conn.bytesSent,
                        processName: conn.processName
                    });
                }
            });
        }

        if (largeTransfers.length > 0) {
            threats.push({
                id: this.generateThreatId(),
                type: this.threatTypes.DATA_EXFILTRATION,
                severity: this.severityLevels.HIGH,
                title: 'Large Data Transfers Detected',
                description: `Found ${largeTransfers.length} large outbound transfers`,
                details: {
                    transfers: largeTransfers,
                    totalData: largeTransfers.reduce((sum, t) => sum + t.bytesSent, 0)
                },
                timestamp: new Date().toISOString(),
                recommendations: ['Investigate large file transfers', 'Check for data exfiltration', 'Review user activity']
            });
        }

        return threats;
    }

    calculateThreatSummary(threats) {
        threats.summary.total = threats.detected.length;

        threats.detected.forEach(threat => {
            threats.summary.byType[threat.type]++;
            threats.summary.bySeverity[threat.severity]++;
        });

        // Extract high-risk processes
        const processThreats = threats.detected.filter(t => t.type === this.threatTypes.MALICIOUS_PROCESS);
        threats.summary.highRiskProcesses = [...new Set(processThreats.map(t => t.details.processName))];
    }

    generateThreatRecommendations(threats) {
        const recommendations = [];

        if (threats.summary.bySeverity.critical > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Threats Detected',
                description: 'Immediate action required. Isolate affected systems.',
                action: 'isolate'
            });
        }

        if (threats.summary.bySeverity.high > 0) {
            recommendations.push({
                priority: 'high',
                title: 'High-Risk Threats Detected',
                description: 'Investigate and mitigate high-risk threats immediately.',
                action: 'investigate'
            });
        }

        // Port scan recommendations
        const portScanThreats = threats.detected.filter(t => t.type === this.threatTypes.PORT_SCAN);
        if (portScanThreats.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Port Scanning Activity',
                description: 'Consider blocking scanning IPs and reviewing firewall rules.',
                action: 'block_ip'
            });
        }

        // Process-based recommendations
        if (threats.summary.highRiskProcesses.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Suspicious Processes',
                description: `Monitor or terminate suspicious processes: ${threats.summary.highRiskProcesses.join(', ')}`,
                action: 'monitor_process'
            });
        }

        return recommendations;
    }

    // Helper methods
    generateThreatId() {
        return `THREAT_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    mapScanSeverityToThreatSeverity(scanSeverity) {
        const mapping = {
            'critical': this.severityLevels.CRITICAL,
            'high': this.severityLevels.HIGH,
            'medium': this.severityLevels.MEDIUM,
            'low': this.severityLevels.LOW
        };
        return mapping[scanSeverity] || this.severityLevels.MEDIUM;
    }

    isMaliciousProcess(processName) {
        if (!processName) return false;
        
        const name = processName.toLowerCase();
        return this.maliciousProcesses.some(proc => name.includes(proc.toLowerCase())) ||
               this.suspiciousProcessPatterns.some(pattern => pattern.test(processName));
    }

    generatePortScanRecommendations(scan) {
        return [
            `Block IP ${scan.scanningIP} at firewall`,
            'Review firewall rules',
            'Monitor for additional scanning activity',
            'Consider implementing rate limiting'
        ];
    }

    generateSuspiciousIPRecommendations(ipThreat) {
        return [
            `Investigate IP ${ipThreat.ip} reputation`,
            'Consider blocking if confirmed malicious',
            'Monitor for additional suspicious activity',
            'Check logs for related incidents'
        ];
    }

    generateMaliciousProcessRecommendations(processName, connections) {
        return [
            `Investigate process ${processName}`,
            'Check process arguments and parent process',
            'Consider terminating if confirmed malicious',
            'Scan system for malware'
        ];
    }

    generateTrafficAnomalyRecommendations(anomaly) {
        return [
            'Investigate cause of traffic anomaly',
            'Monitor system performance',
            'Check for potential DDoS or resource exhaustion',
            'Review application logs'
        ];
    }

    generateBeaconingRecommendations(beacon) {
        return [
            `Investigate beaconing to IP ${beacon.ip}`,
            'Check for malware or C2 communication',
            'Monitor process activity',
            'Consider blocking the IP address'
        ];
    }
}

module.exports = ThreatDetectionService;
