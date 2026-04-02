class ConnectionAnalysisService {
    constructor() {
        this.suspiciousPorts = [22, 23, 80, 443, 1433, 3306, 3389, 5432, 6379, 27017];
        this.commonPorts = [80, 443, 53, 25, 587, 993, 995, 465, 110, 143];
        this.privateIPRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./,
            /^::1$/,
            /^fc00:/,
            /^fe80:/
        ];
    }

    analyzeConnections(connections) {
        const analysis = {
            totalConnections: connections.length,
            inboundConnections: 0,
            outboundConnections: 0,
            suspiciousConnections: [],
            beaconingActivity: [],
            portScanActivity: [],
            unusualPorts: [],
            protocolDistribution: {},
            topIPs: [],
            connectionPatterns: {
                topDestinations: {},
                topPorts: {},
                protocols: {}
            }
        };

        // Calculate protocol distribution
        connections.forEach(conn => {
            const protocol = conn.protocol || 'UNKNOWN';
            analysis.protocolDistribution[protocol] = (analysis.protocolDistribution[protocol] || 0) + 1;
        });

        // Calculate top IPs
        const ipCount = {};
        connections.forEach(conn => {
            const ip = conn.remoteAddress;
            if (ip && ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== '::1') {
                ipCount[ip] = (ipCount[ip] || 0) + 1;
            }
        });

        analysis.topIPs = Object.entries(ipCount)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([ip, count]) => ({ ip, count }));

        // Analyze each connection
        connections.forEach(conn => {
            // Classify connection direction
            if (this.isInboundConnection(conn)) {
                analysis.inboundConnections++;
            } else {
                analysis.outboundConnections++;
            }

            // Check for suspicious connections
            const suspicious = this.identifySuspiciousConnection(conn);
            if (suspicious) {
                analysis.suspiciousConnections.push(suspicious);
            }

            // Track connection patterns
            this.trackConnectionPatterns(conn, analysis.connectionPatterns);
        });

        // Detect beaconing activity
        analysis.beaconingActivity = this.detectBeaconing(connections);

        // Detect port scanning
        analysis.portScanActivity = this.detectPortScanning(connections);

        // Identify unusual ports
        analysis.unusualPorts = this.identifyUnusualPorts(connections);

        // Calculate top destinations and ports
        analysis.connectionPatterns.topDestinations = this.getTopItems(
            analysis.connectionPatterns.topDestinations, 10
        );
        analysis.connectionPatterns.topPorts = this.getTopItems(
            analysis.connectionPatterns.topPorts, 10
        );

        return analysis;
    }

    isInboundConnection(conn) {
        // Simplified logic - would need proper interface detection
        return conn.localPort && conn.localPort < 49152 && !this.isPrivateIP(conn.remoteAddress);
    }

    identifySuspiciousConnection(conn) {
        const reasons = [];
        let risk = 'low';

        // Check for private IP misuse
        if (this.isPrivateIP(conn.remoteAddress) && !this.isInboundConnection(conn)) {
            reasons.push('Outbound connection to private IP');
            risk = 'medium';
        }

        // Check for loopback misuse
        if (conn.remoteAddress === '127.0.0.1' || conn.remoteAddress === '::1') {
            if (conn.remotePort !== 0 && conn.remotePort > 1024) {
                reasons.push('Unusual loopback connection');
                risk = 'medium';
            }
        }

        // Check for uncommon ports
        if (!this.commonPorts.includes(conn.remotePort)) {
            reasons.push(`Connection to uncommon port: ${conn.remotePort}`);
            risk = 'medium';
        }

        // Check for high-risk ports
        if (this.suspiciousPorts.includes(conn.remotePort)) {
            reasons.push(`Connection to high-risk port: ${conn.remotePort}`);
            risk = 'high';
        }

        // Check for suspicious process names
        if (conn.processName && this.isSuspiciousProcess(conn.processName)) {
            reasons.push(`Suspicious process: ${conn.processName}`);
            risk = 'high';
        }

        if (reasons.length > 0) {
            return {
                connection: conn,
                reasons: reasons,
                risk: risk,
                timestamp: new Date().toISOString()
            };
        }

        return null;
    }

    detectBeaconing(connections) {
        const beaconing = [];
        const ipConnections = {};

        // Group connections by remote IP
        connections.forEach(conn => {
            const ip = conn.remoteAddress;
            if (!ipConnections[ip]) {
                ipConnections[ip] = [];
            }
            ipConnections[ip].push(conn);
        });

        // Analyze each IP for beaconing patterns
        Object.entries(ipConnections).forEach(([ip, conns]) => {
            if (conns.length < 5) return; // Need minimum connections for pattern analysis

            const timestamps = conns.map(c => new Date(c.timestamp || Date.now()));
            timestamps.sort((a, b) => a - b);

            // Check for regular intervals
            const intervals = [];
            for (let i = 1; i < timestamps.length; i++) {
                intervals.push(timestamps[i] - timestamps[i - 1]);
            }

            // Calculate interval consistency
            if (intervals.length > 2) {
                const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
                const variance = intervals.reduce((sum, interval) => {
                    return sum + Math.pow(interval - avgInterval, 2);
                }, 0) / intervals.length;
                const stdDev = Math.sqrt(variance);

                // If standard deviation is low relative to average, it's likely beaconing
                if (stdDev < avgInterval * 0.2 && avgInterval < 300000) { // Less than 5 minutes
                    beaconing.push({
                        ip: ip,
                        connectionCount: conns.length,
                        averageInterval: Math.round(avgInterval / 1000), // seconds
                        risk: avgInterval < 60000 ? 'high' : 'medium', // Less than 1 minute is high risk
                        ports: [...new Set(conns.map(c => c.remotePort))],
                        processes: [...new Set(conns.map(c => c.processName).filter(Boolean))]
                    });
                }
            }
        });

        return beaconing;
    }

    detectPortScanning(connections) {
        const portScans = [];
        const ipPortMap = {};

        // Map IPs to ports they've tried to connect to
        connections.forEach(conn => {
            const ip = conn.remoteAddress;
            if (!ipPortMap[ip]) {
                ipPortMap[ip] = new Set();
            }
            ipPortMap[ip].add(conn.remotePort);
        });

        // Identify potential port scans
        Object.entries(ipPortMap).forEach(([ip, ports]) => {
            const portArray = Array.from(ports);
            
            // If an IP has tried to connect to many different ports
            if (portArray.length > 10) {
                const ipConnections = connections.filter(c => c.remoteAddress === ip);
                const timeSpan = this.getTimeSpan(ipConnections);

                portScans.push({
                    scanningIP: ip,
                    portsTargeted: portArray.sort((a, b) => a - b),
                    portCount: portArray.length,
                    connectionCount: ipConnections.length,
                    timeSpan: timeSpan,
                    severity: this.calculateScanSeverity(portArray.length, timeSpan),
                    processes: [...new Set(ipConnections.map(c => c.processName).filter(Boolean))]
                });
            }
        });

        return portScans;
    }

    identifyUnusualPorts(connections) {
        const portUsage = {};
        const unusualPorts = [];

        // Count port usage
        connections.forEach(conn => {
            const port = conn.remotePort;
            portUsage[port] = (portUsage[port] || 0) + 1;
        });

        // Identify unusual ports (rarely used but have connections)
        Object.entries(portUsage).forEach(([port, count]) => {
            const portNum = parseInt(port);
            if (!this.commonPorts.includes(portNum) && count < 5) {
                const portConnections = connections.filter(c => c.remotePort === portNum);
                unusualPorts.push({
                    port: portNum,
                    connectionCount: count,
                    remoteIPs: [...new Set(portConnections.map(c => c.remoteAddress))],
                    processes: [...new Set(portConnections.map(c => c.processName).filter(Boolean))],
                    risk: this.suspiciousPorts.includes(portNum) ? 'high' : 'medium'
                });
            }
        });

        return unusualPorts.sort((a, b) => b.connectionCount - a.connectionCount);
    }

    trackConnectionPatterns(conn, patterns) {
        // Track destinations
        const dest = conn.remoteAddress;
        patterns.topDestinations[dest] = (patterns.topDestinations[dest] || 0) + 1;

        // Track ports
        const port = conn.remotePort;
        patterns.topPorts[port] = (patterns.topPorts[port] || 0) + 1;

        // Track protocols
        const protocol = conn.protocol || 'unknown';
        patterns.protocols[protocol] = (patterns.protocols[protocol] || 0) + 1;
    }

    getTopItems(items, limit) {
        return Object.entries(items)
            .sort(([,a], [,b]) => b - a)
            .slice(0, limit)
            .map(([key, value]) => ({ item: key, count: value }));
    }

    getTimeSpan(connections) {
        if (connections.length < 2) return 0;
        
        const timestamps = connections
            .map(c => new Date(c.timestamp || Date.now()))
            .sort((a, b) => a - b);
        
        return timestamps[timestamps.length - 1] - timestamps[0];
    }

    calculateScanSeverity(portCount, timeSpan) {
        const portsPerMinute = (portCount / (timeSpan / 60000)) || 1;
        
        if (portsPerMinute > 50 || portCount > 100) return 'critical';
        if (portsPerMinute > 20 || portCount > 50) return 'high';
        if (portsPerMinute > 10 || portCount > 25) return 'medium';
        return 'low';
    }

    isPrivateIP(ip) {
        return this.privateIPRanges.some(range => range.test(ip));
    }

    isSuspiciousProcess(processName) {
        if (!processName) return false;
        
        const suspiciousProcesses = [
            'powershell.exe', 'cmd.exe', 'bash', 'sh', 'python.exe', 'python3',
            'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'rundll32.exe',
            'mshta.exe', 'certutil.exe', 'bitsadmin.exe'
        ];
        
        return suspiciousProcesses.some(proc => 
            processName.toLowerCase().includes(proc.toLowerCase())
        );
    }

    // Placeholder for external IP reputation checks
    async checkIPReputation(ip) {
        return {
            ip: ip,
            reputation: 'unknown',
            sources: [],
            abuseIPDB: { supported: false, data: null },
            geoIP: { supported: false, data: null }
        };
    }

    generateConnectionScore(analysis) {
        let score = 0;
        const deductions = [];

        // Deduct for suspicious connections
        score -= analysis.suspiciousConnections.length * 10;
        if (analysis.suspiciousConnections.length > 0) {
            deductions.push(`${analysis.suspiciousConnections.length} suspicious connections`);
        }

        // Deduct for beaconing activity
        score -= analysis.beaconingActivity.length * 15;
        if (analysis.beaconingActivity.length > 0) {
            deductions.push(`${analysis.beaconingActivity.length} beaconing activities detected`);
        }

        // Deduct for port scanning
        analysis.portScanActivity.forEach(scan => {
            const deduction = scan.severity === 'critical' ? 30 : 
                             scan.severity === 'high' ? 25 : 
                             scan.severity === 'medium' ? 15 : 10;
            score -= deduction;
            deductions.push(`Port scan from ${scan.scanningIP} (${scan.severity})`);
        });

        // Deduct for unusual ports
        score -= analysis.unusualPorts.filter(p => p.risk === 'high').length * 10;
        score -= analysis.unusualPorts.filter(p => p.risk === 'medium').length * 5;

        return {
            score: Math.max(0, Math.min(100, 100 + score)),
            deductions: deductions
        };
    }
}

module.exports = ConnectionAnalysisService;
