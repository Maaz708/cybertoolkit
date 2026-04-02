/**
 * Analytics Module
 * Tracks trends, peaks, and generates insights
 */

const DataTransformer = require('../utils/dataTransformer');

class AnalyticsEngine {
    constructor(options = {}) {
        this.history = [];
        this.trends = new Map();
        this.peaks = new Map();
        
        this.config = {
            historyWindow: options.historyWindow || 24 * 60 * 60 * 1000, // 24 hours
            trendCalculationWindow: options.trendWindow || 10, // Data points
            anomalyThreshold: options.anomalyThreshold || 2.5 // Standard deviations
        };
    }

    /**
     * Add data point to history
     * @param {Object} data - Network data snapshot
     */
    track(data) {
        const snapshot = {
            timestamp: Date.now(),
            connections: data.connections?.length || 0,
            bandwidth: {
                inbound: data.bandwidth?.inbound || 0,
                outbound: data.bandwidth?.outbound || 0
            },
            protocols: data.protocols || { TCP: 0, UDP: 0, Other: 0 },
            riskScore: data.riskScore || 0,
            suspiciousConnections: data.suspiciousConnections?.length || 0
        };

        this.history.push(snapshot);
        this.maintainHistory();
        
        // Update trends
        this.calculateTrends();
        
        // Detect peaks
        this.detectPeaks(snapshot);
        
        return snapshot;
    }

    /**
     * Calculate trends based on historical data
     * @returns {Object} Trend analysis
     */
    calculateTrends() {
        if (this.history.length < 2) {
            return {
                traffic: 'stable',
                connections: 'stable',
                risk: 'stable'
            };
        }

        const recent = this.history.slice(-this.config.trendCalculationWindow);
        
        // Traffic trend
        const trafficTrend = this.calculateDirection(
            recent.map(h => h.bandwidth.inbound + h.bandwidth.outbound)
        );
        
        // Connections trend
        const connectionTrend = this.calculateDirection(
            recent.map(h => h.connections)
        );
        
        // Risk trend
        const riskTrend = this.calculateDirection(
            recent.map(h => h.riskScore)
        );

        const trends = {
            traffic: trafficTrend,
            connections: connectionTrend,
            risk: riskTrend,
            confidence: this.calculateConfidence(recent.length)
        };

        this.trends = trends;
        return trends;
    }

    /**
     * Calculate direction of trend
     * @param {Array} values - Array of values
     * @returns {string} 'up', 'down', or 'stable'
     */
    calculateDirection(values) {
        if (values.length < 2) return 'stable';
        
        // Simple linear regression
        const n = values.length;
        const sumX = values.reduce((sum, _, i) => sum + i, 0);
        const sumY = values.reduce((sum, v) => sum + v, 0);
        const sumXY = values.reduce((sum, v, i) => sum + i * v, 0);
        const sumXX = values.reduce((sum, _, i) => sum + i * i, 0);
        
        const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
        
        // Threshold for considering a trend
        const avg = sumY / n;
        const threshold = avg * 0.1; // 10% change
        
        if (slope > threshold) return 'up';
        if (slope < -threshold) return 'down';
        return 'stable';
    }

    /**
     * Calculate confidence level
     * @param {number} sampleSize - Number of data points
     * @returns {string} Confidence level
     */
    calculateConfidence(sampleSize) {
        if (sampleSize < 3) return 'low';
        if (sampleSize < 10) return 'medium';
        return 'high';
    }

    /**
     * Detect peak usage
     * @param {Object} snapshot - Current snapshot
     */
    detectPeaks(snapshot) {
        const metrics = ['connections', 'inboundBandwidth', 'outboundBandwidth', 'riskScore'];
        
        metrics.forEach(metric => {
            const current = this.getMetricValue(snapshot, metric);
            const history = this.history.map(h => this.getMetricValue(h, metric));
            
            const avg = history.reduce((a, b) => a + b, 0) / history.length;
            const max = Math.max(...history);
            
            // Detect if current is a peak
            if (current > avg * 1.5 || current === max) {
                this.peaks.set(metric, {
                    value: current,
                    timestamp: snapshot.timestamp,
                    isAllTimeHigh: current === max,
                    percentageAboveAvg: ((current - avg) / avg * 100).toFixed(1)
                });
            }
        });
    }

    /**
     * Get metric value from snapshot
     * @param {Object} snapshot - Data snapshot
     * @param {string} metric - Metric name
     * @returns {number} Metric value
     */
    getMetricValue(snapshot, metric) {
        switch (metric) {
            case 'connections': return snapshot.connections || 0;
            case 'inboundBandwidth': return snapshot.bandwidth?.inbound || 0;
            case 'outboundBandwidth': return snapshot.bandwidth?.outbound || 0;
            case 'riskScore': return snapshot.riskScore || 0;
            default: return 0;
        }
    }

    /**
     * Detect anomalies
     * @returns {Array} Detected anomalies
     */
    detectAnomalies() {
        if (this.history.length < 5) return [];

        const anomalies = [];
        const recent = this.history.slice(-5);
        const baseline = this.history.slice(0, -5);
        
        if (baseline.length === 0) return [];

        // Calculate baseline statistics
        const baselineConnections = baseline.map(h => h.connections);
        const baselineBandwidth = baseline.map(h => h.bandwidth.inbound + h.bandwidth.outbound);
        
        const avgConnections = baselineConnections.reduce((a, b) => a + b, 0) / baselineConnections.length;
        const stdConnections = this.calculateStd(baselineConnections, avgConnections);
        
        const avgBandwidth = baselineBandwidth.reduce((a, b) => a + b, 0) / baselineBandwidth.length;
        const stdBandwidth = this.calculateStd(baselineBandwidth, avgBandwidth);

        // Check recent values
        recent.forEach((snapshot, index) => {
            const connAnomaly = Math.abs(snapshot.connections - avgConnections) > (stdConnections * this.config.anomalyThreshold);
            const bwAnomaly = Math.abs((snapshot.bandwidth.inbound + snapshot.bandwidth.outbound) - avgBandwidth) > (stdBandwidth * this.config.anomalyThreshold);
            
            if (connAnomaly || bwAnomaly) {
                anomalies.push({
                    timestamp: snapshot.timestamp,
                    timestampFormatted: DataTransformer.formatTimestamp(new Date(snapshot.timestamp)),
                    type: connAnomaly && bwAnomaly ? 'both' : (connAnomaly ? 'connections' : 'bandwidth'),
                    severity: this.calculateAnomalySeverity(
                        connAnomaly ? snapshot.connections : 0,
                        avgConnections,
                        stdConnections,
                        bwAnomaly ? (snapshot.bandwidth.inbound + snapshot.bandwidth.outbound) : 0,
                        avgBandwidth,
                        stdBandwidth
                    ),
                    confidence: this.calculateAnomalyConfidence(baseline.length),
                    details: {
                        connections: {
                            value: snapshot.connections,
                            expected: Math.round(avgConnections),
                            deviation: stdConnections > 0 ? ((snapshot.connections - avgConnections) / stdConnections).toFixed(2) : 0
                        },
                        bandwidth: {
                            value: snapshot.bandwidth.inbound + snapshot.bandwidth.outbound,
                            expected: Math.round(avgBandwidth),
                            deviation: stdBandwidth > 0 ? (((snapshot.bandwidth.inbound + snapshot.bandwidth.outbound) - avgBandwidth) / stdBandwidth).toFixed(2) : 0
                        }
                    }
                });
            }
        });

        return anomalies;
    }

    /**
     * Calculate standard deviation
     * @param {Array} values - Array of values
     * @param {number} mean - Mean value
     * @returns {number} Standard deviation
     */
    calculateStd(values, mean) {
        const variance = values.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / values.length;
        return Math.sqrt(variance);
    }

    /**
     * Calculate anomaly severity
     * @returns {string} Severity level
     */
    calculateAnomalySeverity(connValue, connAvg, connStd, bwValue, bwAvg, bwStd) {
        const connDeviation = connStd > 0 ? Math.abs(connValue - connAvg) / connStd : 0;
        const bwDeviation = bwStd > 0 ? Math.abs(bwValue - bwAvg) / bwStd : 0;
        const maxDeviation = Math.max(connDeviation, bwDeviation);
        
        if (maxDeviation > 4) return 'critical';
        if (maxDeviation > 3) return 'high';
        if (maxDeviation > 2) return 'medium';
        return 'low';
    }

    /**
     * Calculate anomaly detection confidence
     * @param {number} baselineSize - Size of baseline data
     * @returns {number} Confidence score (0-100)
     */
    calculateAnomalyConfidence(baselineSize) {
        if (baselineSize < 10) return 30;
        if (baselineSize < 50) return 60;
        if (baselineSize < 100) return 80;
        return 95;
    }

    /**
     * Get analytics summary
     * @returns {Object} Analytics summary
     */
    getAnalytics() {
        const trends = this.calculateTrends();
        const anomalies = this.detectAnomalies();
        
        // Convert peaks map to object
        const peaks = {};
        this.peaks.forEach((value, key) => {
            peaks[key] = value;
        });

        return {
            trends: {
                traffic: {
                    direction: trends.traffic,
                    confidence: trends.confidence,
                    description: this.getTrendDescription(trends.traffic, 'traffic')
                },
                connections: {
                    direction: trends.connections,
                    confidence: trends.confidence,
                    description: this.getTrendDescription(trends.connections, 'connections')
                },
                risk: {
                    direction: trends.risk,
                    confidence: trends.confidence,
                    description: this.getTrendDescription(trends.risk, 'risk')
                }
            },
            peaks,
            anomalies: {
                detected: anomalies.length > 0,
                count: anomalies.length,
                recent: anomalies.slice(-5),
                confidence: anomalies.length > 0 ? this.calculateAnomalyConfidence(this.history.length) : 0
            },
            history: {
                dataPoints: this.history.length,
                timeSpan: this.history.length > 0 
                    ? this.history[this.history.length - 1].timestamp - this.history[0].timestamp 
                    : 0
            }
        };
    }

    /**
     * Get human readable trend description
     * @param {string} trend - Trend direction
     * @param {string} metric - Metric name
     * @returns {string} Description
     */
    getTrendDescription(trend, metric) {
        const descriptions = {
            traffic: {
                up: 'Traffic increasing - monitor for spikes',
                down: 'Traffic decreasing',
                stable: 'Traffic levels stable'
            },
            connections: {
                up: 'Connection count rising',
                down: 'Connection count falling',
                stable: 'Connection count stable'
            },
            risk: {
                up: 'Risk level increasing - attention needed',
                down: 'Risk level decreasing',
                stable: 'Risk level stable'
            }
        };
        
        return descriptions[metric]?.[trend] || 'Trend unknown';
    }

    /**
     * Get chart data
     * @param {number} points - Number of data points
     * @returns {Object} Chart-ready data
     */
    getChartData(points = 20) {
        const history = this.history.slice(-points);
        
        return {
            trafficOverTime: history.map(h => ({
                time: DataTransformer.formatTimestamp(new Date(h.timestamp)).chartTime,
                inbound: parseFloat((h.bandwidth.inbound / 1024 / 1024).toFixed(2)),
                outbound: parseFloat((h.bandwidth.outbound / 1024 / 1024).toFixed(2)),
                total: parseFloat(((h.bandwidth.inbound + h.bandwidth.outbound) / 1024 / 1024).toFixed(2))
            })),
            connectionsOverTime: history.map(h => ({
                time: DataTransformer.formatTimestamp(new Date(h.timestamp)).chartTime,
                count: h.connections,
                tcp: h.protocols?.TCP || 0,
                udp: h.protocols?.UDP || 0,
                other: h.protocols?.Other || 0
            })),
            riskOverTime: history.map(h => ({
                time: DataTransformer.formatTimestamp(new Date(h.timestamp)).chartTime,
                score: h.riskScore,
                suspicious: h.suspiciousConnections
            }))
        };
    }

    /**
     * Maintain history size
     */
    maintainHistory() {
        const cutoff = Date.now() - this.config.historyWindow;
        this.history = this.history.filter(h => h.timestamp > cutoff);
    }
}

module.exports = AnalyticsEngine;
