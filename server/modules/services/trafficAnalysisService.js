class TrafficAnalysisService {
    constructor() {
        this.baselineHistory = [];
        this.maxHistorySize = 100;
        this.anomalyThreshold = 2.0; // Standard deviations
        this.beaconingThreshold = 0.8; // Consistency threshold
    }

    analyzeTraffic(currentStats, previousStats = null) {
        const analysis = {
            current: currentStats,
            baseline: previousStats || this.calculateBaseline(currentStats),
            anomalies: [],
            patterns: {
                uploadDownloadRatio: this.calculateUploadDownloadRatio(currentStats),
                protocolDistribution: this.calculateProtocolDistribution(currentStats),
                connectionRate: this.calculateConnectionRate(currentStats),
                dataTransferRate: this.calculateDataTransferRate(currentStats)
            },
            trends: {
                trafficGrowth: this.calculateTrafficGrowth(currentStats, previousStats),
                connectionGrowth: this.calculateConnectionGrowth(currentStats, previousStats),
                protocolChanges: this.calculateProtocolChanges(currentStats, previousStats)
            }
        };

        // Detect anomalies
        analysis.anomalies = this.detectTrafficAnomalies(analysis);

        // Update baseline
        this.updateBaseline(currentStats);

        return analysis;
    }

    detectTrafficAnomalies(analysis) {
        const anomalies = [];
        const current = analysis.current;
        const baseline = analysis.baseline;

        // Traffic volume anomalies
        if (baseline.totalBytes) {
            const volumeDeviation = this.calculateDeviation(current.totalBytes, baseline.totalBytes);
            if (Math.abs(volumeDeviation) > this.anomalyThreshold) {
                anomalies.push({
                    type: 'TRAFFIC_VOLUME',
                    severity: Math.abs(volumeDeviation) > 4 ? 'critical' : 
                             Math.abs(volumeDeviation) > 3 ? 'high' : 'medium',
                    description: `Unusual traffic volume detected: ${volumeDeviation.toFixed(2)}x baseline`,
                    currentValue: current.totalBytes,
                    expectedValue: baseline.totalBytes,
                    deviation: volumeDeviation,
                    direction: volumeDeviation > 0 ? 'increase' : 'decrease'
                });
            }
        }

        // Connection count anomalies
        if (baseline.totalConnections) {
            const connectionDeviation = this.calculateDeviation(current.totalConnections, baseline.totalConnections);
            if (Math.abs(connectionDeviation) > this.anomalyThreshold) {
                anomalies.push({
                    type: 'CONNECTION_COUNT',
                    severity: Math.abs(connectionDeviation) > 3 ? 'high' : 'medium',
                    description: `Unusual connection count: ${connectionDeviation.toFixed(2)}x baseline`,
                    currentValue: current.totalConnections,
                    expectedValue: baseline.totalConnections,
                    deviation: connectionDeviation,
                    direction: connectionDeviation > 0 ? 'increase' : 'decrease'
                });
            }
        }

        // Upload/Download ratio anomalies
        const currentRatio = analysis.patterns.uploadDownloadRatio;
        const baselineRatio = baseline.uploadDownloadRatio || 1.0;
        const ratioDeviation = this.calculateDeviation(currentRatio, baselineRatio);
        
        if (Math.abs(ratioDeviation) > this.anomalyThreshold && currentRatio > 5) {
            anomalies.push({
                type: 'UPLOAD_DOWNLOAD_RATIO',
                severity: currentRatio > 20 ? 'critical' : 'high',
                description: `Unusual upload/download ratio: ${currentRatio.toFixed(2)}`,
                currentValue: currentRatio,
                expectedValue: baselineRatio,
                deviation: ratioDeviation,
                potentialExfiltration: currentRatio > 10
            });
        }

        // Protocol distribution anomalies
        const protocolAnomalies = this.detectProtocolAnomalies(analysis.patterns.protocolDistribution, baseline.protocolDistribution);
        anomalies.push(...protocolAnomalies);

        // Beaconing detection
        const beaconingAnomalies = this.detectBeaconingPatterns(current);
        anomalies.push(...beaconingAnomalies);

        // Data transfer rate anomalies
        const rateAnomalies = this.detectTransferRateAnomalies(analysis.patterns.dataTransferRate, baseline.dataTransferRate);
        anomalies.push(...rateAnomalies);

        return anomalies;
    }

    detectProtocolAnomalies(currentProtocols, baselineProtocols) {
        const anomalies = [];

        if (!baselineProtocols) return anomalies;

        Object.keys(currentProtocols).forEach(protocol => {
            const current = currentProtocols[protocol];
            const baseline = baselineProtocols[protocol] || 0;
            
            if (baseline > 0) {
                const deviation = this.calculateDeviation(current, baseline);
                if (Math.abs(deviation) > this.anomalyThreshold) {
                    anomalies.push({
                        type: 'PROTOCOL_ANOMALY',
                        severity: 'medium',
                        description: `Unusual ${protocol} traffic: ${deviation.toFixed(2)}x baseline`,
                        currentValue: current,
                        expectedValue: baseline,
                        deviation: deviation,
                        protocol: protocol
                    });
                }
            } else if (current > 1000) { // New protocol with significant traffic
                anomalies.push({
                    type: 'NEW_PROTOCOL',
                    severity: 'medium',
                    description: `New protocol detected with significant traffic: ${protocol}`,
                    currentValue: current,
                    expectedValue: 0,
                    deviation: Infinity,
                    protocol: protocol
                });
            }
        });

        return anomalies;
    }

    detectBeaconingPatterns(currentStats) {
        const anomalies = [];

        // Check for consistent low-level traffic patterns
        if (currentStats.connectionDetails && currentStats.connectionDetails.length > 0) {
            const ipTraffic = this.groupTrafficByIP(currentStats.connectionDetails);
            
            Object.entries(ipTraffic).forEach(([ip, connections]) => {
                if (connections.length > 10) {
                    const consistency = this.calculateTrafficConsistency(connections);
                    if (consistency > this.beaconingThreshold) {
                        anomalies.push({
                            type: 'BEACONING',
                            severity: consistency > 0.95 ? 'high' : 'medium',
                            description: `Potential beaconing activity to IP ${ip}`,
                            currentValue: consistency,
                            expectedValue: 0.5,
                            deviation: consistency - 0.5,
                            targetIP: ip,
                            connectionCount: connections.length
                        });
                    }
                }
            });
        }

        return anomalies;
    }

    detectTransferRateAnomalies(currentRates, baselineRates) {
        const anomalies = [];

        if (!baselineRates) return anomalies;

        ['upload', 'download'].forEach(direction => {
            const current = currentRates[direction];
            const baseline = baselineRates[direction];
            
            if (baseline && baseline > 0) {
                const deviation = this.calculateDeviation(current, baseline);
                if (Math.abs(deviation) > this.anomalyThreshold) {
                    anomalies.push({
                        type: 'TRANSFER_RATE_ANOMALY',
                        severity: Math.abs(deviation) > 4 ? 'high' : 'medium',
                        description: `Unusual ${direction} transfer rate: ${deviation.toFixed(2)}x baseline`,
                        currentValue: current,
                        expectedValue: baseline,
                        deviation: deviation,
                        direction: direction
                    });
                }
            }
        });

        return anomalies;
    }

    calculateUploadDownloadRatio(stats) {
        if (!stats.totalBytesReceived || stats.totalBytesReceived === 0) {
            return stats.totalBytesSent > 0 ? Infinity : 0;
        }
        return stats.totalBytesSent / stats.totalBytesReceived;
    }

    calculateProtocolDistribution(stats) {
        const distribution = {};
        
        if (stats.protocolStats) {
            Object.entries(stats.protocolStats).forEach(([protocol, bytes]) => {
                distribution[protocol] = bytes;
            });
        }

        return distribution;
    }

    calculateConnectionRate(stats) {
        // Connections per second over the monitoring period
        const timeWindow = stats.timeWindow || 60; // Default to 60 seconds
        return stats.totalConnections / timeWindow;
    }

    calculateDataTransferRate(stats) {
        const timeWindow = stats.timeWindow || 60;
        return {
            upload: stats.totalBytesSent / timeWindow,
            download: stats.totalBytesReceived / timeWindow,
            total: (stats.totalBytesSent + stats.totalBytesReceived) / timeWindow
        };
    }

    calculateTrafficGrowth(current, previous) {
        if (!previous) return null;
        
        return {
            bytes: this.calculateGrowthRate(current.totalBytes, previous.totalBytes),
            connections: this.calculateGrowthRate(current.totalConnections, previous.totalConnections),
            upload: this.calculateGrowthRate(current.totalBytesSent, previous.totalBytesSent),
            download: this.calculateGrowthRate(current.totalBytesReceived, previous.totalBytesReceived)
        };
    }

    calculateConnectionGrowth(current, previous) {
        if (!previous) return null;
        
        return {
            total: this.calculateGrowthRate(current.totalConnections, previous.totalConnections),
            inbound: this.calculateGrowthRate(current.inboundConnections || 0, previous.inboundConnections || 0),
            outbound: this.calculateGrowthRate(current.outboundConnections || 0, previous.outboundConnections || 0)
        };
    }

    calculateProtocolChanges(current, previous) {
        if (!previous || !previous.protocolStats) return null;
        
        const changes = {};
        const currentProtocols = current.protocolStats || {};
        const previousProtocols = previous.protocolStats || {};
        
        const allProtocols = new Set([...Object.keys(currentProtocols), ...Object.keys(previousProtocols)]);
        
        allProtocols.forEach(protocol => {
            const current = currentProtocols[protocol] || 0;
            const previous = previousProtocols[protocol] || 0;
            
            if (previous > 0) {
                changes[protocol] = this.calculateGrowthRate(current, previous);
            } else if (current > 0) {
                changes[protocol] = Infinity; // New protocol
            }
        });
        
        return changes;
    }

    // Helper methods
    calculateDeviation(current, baseline) {
        if (baseline === 0) return current > 0 ? Infinity : 0;
        return (current - baseline) / baseline;
    }

    calculateGrowthRate(current, previous) {
        if (previous === 0) return current > 0 ? Infinity : 0;
        return ((current - previous) / previous) * 100;
    }

    groupTrafficByIP(connections) {
        const ipGroups = {};
        
        connections.forEach(conn => {
            const ip = conn.remoteAddress;
            if (!ipGroups[ip]) {
                ipGroups[ip] = [];
            }
            ipGroups[ip].push(conn);
        });
        
        return ipGroups;
    }

    calculateTrafficConsistency(connections) {
        if (connections.length < 5) return 0;
        
        // Calculate time intervals between connections
        const timestamps = connections
            .map(c => new Date(c.timestamp || Date.now()))
            .sort((a, b) => a - b);
        
        const intervals = [];
        for (let i = 1; i < timestamps.length; i++) {
            intervals.push(timestamps[i] - timestamps[i - 1]);
        }
        
        if (intervals.length < 2) return 0;
        
        // Calculate coefficient of variation (lower = more consistent)
        const mean = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => {
            return sum + Math.pow(interval - mean, 2);
        }, 0) / intervals.length;
        const stdDev = Math.sqrt(variance);
        
        // Return consistency score (0-1, higher = more consistent)
        return mean > 0 ? Math.max(0, 1 - (stdDev / mean)) : 0;
    }

    calculateBaseline(currentStats) {
        // For initial run, use current stats as baseline
        return {
            totalBytes: currentStats.totalBytes,
            totalBytesSent: currentStats.totalBytesSent,
            totalBytesReceived: currentStats.totalBytesReceived,
            totalConnections: currentStats.totalConnections,
            inboundConnections: currentStats.inboundConnections,
            outboundConnections: currentStats.outboundConnections,
            protocolStats: currentStats.protocolStats,
            uploadDownloadRatio: this.calculateUploadDownloadRatio(currentStats),
            dataTransferRate: this.calculateDataTransferRate(currentStats)
        };
    }

    updateBaseline(currentStats) {
        const newBaseline = this.calculateBaseline(currentStats);
        
        this.baselineHistory.push(newBaseline);
        
        // Keep only recent history
        if (this.baselineHistory.length > this.maxHistorySize) {
            this.baselineHistory.shift();
        }
        
        return newBaseline;
    }

    getAdaptiveBaseline() {
        if (this.baselineHistory.length === 0) return null;
        
        // Calculate moving average of recent baselines
        const recentBaselines = this.baselineHistory.slice(-10); // Last 10 baselines
        const adaptive = {};
        
        // Average each metric
        Object.keys(recentBaselines[0]).forEach(key => {
            const value = recentBaselines[0][key];
            if (typeof value === 'number') {
                adaptive[key] = recentBaselines.reduce((sum, b) => sum + (b[key] || 0), 0) / recentBaselines.length;
            } else if (typeof value === 'object' && value !== null) {
                adaptive[key] = this.averageObject(recentBaselines.map(b => b[key] || {}));
            } else {
                adaptive[key] = value;
            }
        });
        
        return adaptive;
    }

    averageObject(objects) {
        const result = {};
        const allKeys = new Set(objects.flatMap(obj => Object.keys(obj)));
        
        allKeys.forEach(key => {
            const values = objects.map(obj => obj[key] || 0).filter(v => typeof v === 'number');
            if (values.length > 0) {
                result[key] = values.reduce((sum, val) => sum + val, 0) / values.length;
            }
        });
        
        return result;
    }

    generateTrafficScore(analysis) {
        let score = 0;
        const deductions = [];

        // Deduct for each anomaly
        analysis.anomalies.forEach(anomaly => {
            const deduction = anomaly.severity === 'critical' ? 20 :
                             anomaly.severity === 'high' ? 15 :
                             anomaly.severity === 'medium' ? 10 : 5;
            score -= deduction;
            deductions.push(`${anomaly.type}: ${anomaly.description}`);
        });

        // Additional deductions for specific patterns
        if (analysis.patterns.uploadDownloadRatio > 10) {
            score -= 15;
            deductions.push('High upload/download ratio indicates possible exfiltration');
        }

        if (analysis.trends.trafficGrowth && analysis.trends.trafficGrowth.bytes > 200) {
            score -= 10;
            deductions.push('Unusual traffic growth detected');
        }

        return {
            score: Math.max(0, Math.min(100, 100 + score)),
            deductions: deductions
        };
    }
}

module.exports = TrafficAnalysisService;
