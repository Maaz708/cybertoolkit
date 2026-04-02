class HistoricalTrackingService {
    constructor() {
        this.maxHistorySize = 100;
        this.history = [];
        this.comparisonThresholds = {
            connectionSpike: 2.0,      // 2x increase
            trafficSpike: 2.5,         // 2.5x increase
            newProcessThreshold: 5,    // 5+ new processes
            portChangeThreshold: 3     // 3+ new ports
        };
    }

    trackSnapshot(currentSnapshot) {
        const snapshot = {
            timestamp: new Date().toISOString(),
            networkStats: this.normalizeNetworkStats(currentSnapshot.networkStats || {}),
            connectionAnalysis: this.normalizeConnectionAnalysis(currentSnapshot.connectionAnalysis || {}),
            processes: currentSnapshot.processes || [],
            openPorts: currentSnapshot.openPorts || [],
            riskScore: currentSnapshot.riskScore || 100
        };

        // Add to history
        if (!this.history) {
            this.history = [];
        }
        
        this.history.push(snapshot);
        
        // Maintain history size
        if (this.history.length > 1000) {
            this.history.shift();
        }

        return snapshot;
    }

    compareSnapshots(currentSnapshot, previousSnapshot = null) {
        if (!previousSnapshot && this.history.length > 0) {
            previousSnapshot = this.history[this.history.length - 2]; // Second to last
        }

        if (!previousSnapshot) {
            return {
                hasChanges: false,
                changes: [],
                summary: 'No previous data for comparison'
            };
        }

        const comparison = {
            hasChanges: false,
            changes: [],
            summary: '',
            metrics: {
                connectionChanges: this.compareConnections(currentSnapshot, previousSnapshot),
                trafficChanges: this.compareTraffic(currentSnapshot, previousSnapshot),
                processChanges: this.compareProcesses(currentSnapshot, previousSnapshot),
                portChanges: this.comparePorts(currentSnapshot, previousSnapshot),
                riskScoreChanges: this.compareRiskScores(currentSnapshot, previousSnapshot)
            }
        };

        // Analyze changes and generate summary
        this.analyzeChanges(comparison);

        return comparison;
    }

    compareConnections(current, previous) {
        const currentConn = current.connectionAnalysis || {};
        const previousConn = previous.connectionAnalysis || {};

        const changes = {
            totalConnections: {
                current: currentConn.totalConnections || 0,
                previous: previousConn.totalConnections || 0,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            inboundConnections: {
                current: currentConn.inboundConnections || 0,
                previous: previousConn.inboundConnections || 0,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            outboundConnections: {
                current: currentConn.outboundConnections || 0,
                previous: previousConn.outboundConnections || 0,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            suspiciousConnections: {
                current: (currentConn.suspiciousConnections || []).length,
                previous: (previousConn.suspiciousConnections || []).length,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            beaconingActivity: {
                current: (currentConn.beaconingActivity || []).length,
                previous: (previousConn.beaconingActivity || []).length,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            }
        };

        // Calculate changes
        Object.keys(changes).forEach(key => {
            const metric = changes[key];
            metric.change = metric.current - metric.previous;
            metric.percentChange = metric.previous > 0 ? (metric.change / metric.previous) * 100 : 0;
            
            // Determine significance
            if (key === 'totalConnections' && Math.abs(metric.percentChange) > 100) {
                metric.significance = Math.abs(metric.percentChange) > 200 ? 'critical' : 'high';
            } else if (key === 'suspiciousConnections' && metric.change > 0) {
                metric.significance = metric.change > 5 ? 'high' : 'medium';
            } else if (key === 'beaconingActivity' && metric.change > 0) {
                metric.significance = 'high';
            } else if (Math.abs(metric.percentChange) > 50) {
                metric.significance = 'medium';
            }
        });

        return changes;
    }

    compareTraffic(current, previous) {
        const currentNet = current.networkStats || {};
        const previousNet = previous.networkStats || {};

        const changes = {
            totalBytes: {
                current: (currentNet.totalBytesSent || 0) + (currentNet.totalBytesReceived || 0),
                previous: (previousNet.totalBytesSent || 0) + (previousNet.totalBytesReceived || 0),
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            uploadBytes: {
                current: currentNet.totalBytesSent || 0,
                previous: previousNet.totalBytesSent || 0,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            downloadBytes: {
                current: currentNet.totalBytesReceived || 0,
                previous: previousNet.totalBytesReceived || 0,
                change: 0,
                percentChange: 0,
                significance: 'normal'
            },
            uploadDownloadRatio: {
                current: this.calculateRatio(currentNet.totalBytesSent, currentNet.totalBytesReceived),
                previous: this.calculateRatio(previousNet.totalBytesSent, previousNet.totalBytesReceived),
                change: 0,
                significance: 'normal'
            }
        };

        // Calculate changes
        Object.keys(changes).forEach(key => {
            const metric = changes[key];
            if (key === 'uploadDownloadRatio') {
                metric.change = metric.current - metric.previous;
                if (Math.abs(metric.change) > 5) {
                    metric.significance = Math.abs(metric.change) > 10 ? 'critical' : 'high';
                }
            } else {
                metric.change = metric.current - metric.previous;
                metric.percentChange = metric.previous > 0 ? (metric.change / metric.previous) * 100 : 0;
                
                if (Math.abs(metric.percentChange) > 150) {
                    metric.significance = Math.abs(metric.percentChange) > 300 ? 'critical' : 'high';
                } else if (Math.abs(metric.percentChange) > 75) {
                    metric.significance = 'medium';
                }
            }
        });

        return changes;
    }

    compareProcesses(current, previous) {
        const currentProcesses = current.processes || [];
        const previousProcesses = previous.processes || [];

        const currentProcessNames = new Set(currentProcesses.map(p => p.name));
        const previousProcessNames = new Set(previousProcesses.map(p => p.name));

        const newProcesses = [...currentProcessNames].filter(name => !previousProcessNames.has(name));
        const terminatedProcesses = [...previousProcessNames].filter(name => !currentProcessNames.has(name));
        const persistentProcesses = [...currentProcessNames].filter(name => previousProcessNames.has(name));

        const changes = {
            newProcesses: {
                count: newProcesses.length,
                processes: newProcesses,
                significance: newProcesses.length > this.comparisonThresholds.newProcessThreshold ? 'high' : 
                           newProcesses.length > 2 ? 'medium' : 'normal'
            },
            terminatedProcesses: {
                count: terminatedProcesses.length,
                processes: terminatedProcesses,
                significance: 'normal'
            },
            persistentProcesses: {
                count: persistentProcesses.length,
                processes: persistentProcesses,
                significance: 'normal'
            },
            totalProcesses: {
                current: currentProcesses.length,
                previous: previousProcesses.length,
                change: currentProcesses.length - previousProcesses.length,
                significance: 'normal'
            }
        };

        return changes;
    }

    comparePorts(current, previous) {
        const currentPorts = current.openPorts || [];
        const previousPorts = previous.openPorts || [];

        const currentPortSet = new Set(currentPorts);
        const previousPortSet = new Set(previousPorts);

        const newPorts = [...currentPortSet].filter(port => !previousPortSet.has(port));
        const closedPorts = [...previousPortSet].filter(port => !currentPortSet.has(port));
        const persistentPorts = [...currentPortSet].filter(port => previousPortSet.has(port));

        const changes = {
            newPorts: {
                count: newPorts.length,
                ports: newPorts.sort((a, b) => a - b),
                significance: newPorts.length > this.comparisonThresholds.portChangeThreshold ? 'high' :
                           newPorts.length > 1 ? 'medium' : 'normal'
            },
            closedPorts: {
                count: closedPorts.length,
                ports: closedPorts.sort((a, b) => a - b),
                significance: 'normal'
            },
            persistentPorts: {
                count: persistentPorts.length,
                ports: persistentPorts.sort((a, b) => a - b),
                significance: 'normal'
            },
            totalPorts: {
                current: currentPorts.length,
                previous: previousPorts.length,
                change: currentPorts.length - previousPorts.length,
                significance: 'normal'
            }
        };

        return changes;
    }

    compareRiskScores(current, previous) {
        const currentScore = current.riskScore || { score: 100 };
        const previousScore = previous.riskScore || { score: 100 };

        const change = currentScore.score - previousScore.score;
        const significance = Math.abs(change) > 20 ? 'high' :
                           Math.abs(change) > 10 ? 'medium' : 'normal';

        return {
            current: currentScore.score,
            previous: previousScore.score,
            change: change,
            direction: change > 0 ? 'improving' : change < 0 ? 'degrading' : 'stable',
            significance: significance
        };
    }

    analyzeChanges(comparison) {
        const changes = [];
        let hasSignificantChanges = false;

        // Analyze connection changes
        const connChanges = comparison.metrics.connectionChanges;
        if (connChanges.totalConnections.significance !== 'normal') {
            changes.push({
                type: 'connection_spike',
                description: `Connection count changed by ${connChanges.totalConnections.percentChange.toFixed(1)}%`,
                severity: connChanges.totalConnections.significance,
                details: connChanges.totalConnections
            });
            hasSignificantChanges = true;
        }

        if (connChanges.suspiciousConnections.change > 0) {
            changes.push({
                type: 'increased_suspicious_connections',
                description: `${connChanges.suspiciousConnections.change} new suspicious connections detected`,
                severity: connChanges.suspiciousConnections.significance,
                details: connChanges.suspiciousConnections
            });
            hasSignificantChanges = true;
        }

        // Analyze traffic changes
        const trafficChanges = comparison.metrics.trafficChanges;
        if (trafficChanges.totalBytes.significance !== 'normal') {
            changes.push({
                type: 'traffic_spike',
                description: `Traffic volume changed by ${trafficChanges.totalBytes.percentChange.toFixed(1)}%`,
                severity: trafficChanges.totalBytes.significance,
                details: trafficChanges.totalBytes
            });
            hasSignificantChanges = true;
        }

        if (trafficChanges.uploadDownloadRatio.significance !== 'normal') {
            changes.push({
                type: 'ratio_anomaly',
                description: `Upload/download ratio changed significantly`,
                severity: trafficChanges.uploadDownloadRatio.significance,
                details: trafficChanges.uploadDownloadRatio
            });
            hasSignificantChanges = true;
        }

        // Analyze process changes
        const processChanges = comparison.metrics.processChanges;
        if (processChanges.newProcesses.significance !== 'normal') {
            changes.push({
                type: 'new_processes',
                description: `${processChanges.newProcesses.count} new processes detected`,
                severity: processChanges.newProcesses.significance,
                details: processChanges.newProcesses
            });
            hasSignificantChanges = true;
        }

        // Analyze port changes
        const portChanges = comparison.metrics.portChanges;
        if (portChanges.newPorts.significance !== 'normal') {
            changes.push({
                type: 'new_ports',
                description: `${portChanges.newPorts.count} new ports opened`,
                severity: portChanges.newPorts.significance,
                details: portChanges.newPorts
            });
            hasSignificantChanges = true;
        }

        // Analyze risk score changes
        const riskChanges = comparison.metrics.riskScoreChanges;
        if (riskChanges.significance !== 'normal') {
            changes.push({
                type: 'risk_score_change',
                description: `Risk score changed by ${riskChanges.change} points (${riskChanges.direction})`,
                severity: riskChanges.significance,
                details: riskChanges
            });
            hasSignificantChanges = true;
        }

        comparison.hasChanges = hasSignificantChanges;
        comparison.changes = changes;
        
        // Generate summary
        if (hasSignificantChanges) {
            const criticalChanges = changes.filter(c => c.severity === 'critical').length;
            const highChanges = changes.filter(c => c.severity === 'high').length;
            const mediumChanges = changes.filter(c => c.severity === 'medium').length;
            
            comparison.summary = `Detected ${changes.length} significant changes: ${criticalChanges} critical, ${highChanges} high, ${mediumChanges} medium severity`;
        } else {
            comparison.summary = 'No significant changes detected compared to previous snapshot';
        }
    }

    getTrends(snapshots = null) {
        const data = snapshots || this.history || [];
        if (data.length < 2) {
            return {
                hasTrends: false,
                summary: 'Insufficient data for trend analysis'
            };
        }

        const trends = {
            hasTrends: true,
            summary: '',
            connectionTrend: this.calculateTrend(data.map(s => s?.connectionAnalysis?.totalConnections || 0)),
            trafficTrend: this.calculateTrend(data.map(s => (s?.networkStats?.totalBytesSent || 0) + (s?.networkStats?.totalBytesReceived || 0))),
            riskScoreTrend: this.calculateTrend(data.map(s => s?.riskScore?.score || 100)),
            suspiciousConnectionTrend: this.calculateTrend(data.map(s => (s?.connectionAnalysis?.suspiciousConnections || []).length))
        };

        // Generate summary
        const trendDescriptions = [];
        Object.entries(trends).forEach(([key, trend]) => {
            if (key !== 'hasTrends' && key !== 'summary' && trend.direction !== 'stable') {
                trendDescriptions.push(`${key.replace('Trend', '')} is ${trend.direction}`);
            }
        });

        if (trendDescriptions.length > 0) {
            trends.summary = `Trends detected: ${trendDescriptions.join(', ')}`;
        } else {
            trends.summary = 'All metrics appear stable over time';
        }

        return trends;
    }

    calculateTrend(values) {
        if (values.length < 2) {
            return { direction: 'stable', slope: 0, confidence: 0 };
        }

        // Simple linear regression to calculate trend
        const n = values.length;
        const x = Array.from({length: n}, (_, i) => i);
        const y = values;

        const sumX = x.reduce((a, b) => a + b, 0);
        const sumY = y.reduce((a, b) => a + b, 0);
        const sumXY = x.reduce((sum, xi, i) => sum + xi * y[i], 0);
        const sumXX = x.reduce((sum, xi) => sum + xi * xi, 0);

        const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        
        // Determine direction and confidence
        let direction = 'stable';
        let confidence = 0;

        if (Math.abs(slope) > 0.1) {
            direction = slope > 0 ? 'increasing' : 'decreasing';
            confidence = Math.min(Math.abs(slope) / 10, 1);
        }

        return { direction, slope, confidence };
    }

    // Helper methods
    normalizeNetworkStats(stats) {
        return {
            totalConnections: stats.totalConnections || 0,
            totalBytesSent: stats.totalBytesSent || 0,
            totalBytesReceived: stats.totalBytesReceived || 0,
            inboundConnections: stats.inboundConnections || 0,
            outboundConnections: stats.outboundConnections || 0,
            timeWindow: stats.timeWindow || 60
        };
    }

    normalizeConnectionAnalysis(analysis) {
        if (!analysis || typeof analysis !== 'object') {
            return {
                totalConnections: 0,
                inboundConnections: 0,
                outboundConnections: 0,
                suspiciousConnections: [],
                beaconingActivity: [],
                portScanActivity: []
            };
        }
        
        return {
            totalConnections: analysis.totalConnections || 0,
            inboundConnections: analysis.inboundConnections || 0,
            outboundConnections: analysis.outboundConnections || 0,
            suspiciousConnections: analysis.suspiciousConnections || [],
            beaconingActivity: analysis.beaconingActivity || [],
            portScanActivity: analysis.portScanActivity || []
        };
    }

    calculateRatio(upload, download) {
        if (!download || download === 0) {
            return upload > 0 ? Infinity : 0;
        }
        return upload / download;
    }

    getHistory(limit = 50) {
        return (this.history || []).slice(-limit);
    }

    clearHistory() {
        this.history = [];
    }

    getComparisonThresholds() {
        return { ...this.comparisonThresholds };
    }

    setComparisonThresholds(newThresholds) {
        Object.assign(this.comparisonThresholds, newThresholds);
    }
}

module.exports = HistoricalTrackingService;
