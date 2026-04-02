/**
 * Smart Alert System
 * Enhanced alerts with categories, severity scores, deduplication, auto-expiry
 */

const crypto = require('crypto');
const DataTransformer = require('../utils/dataTransformer');
const logger = require('../utils/logger');

class SmartAlertSystem {
    constructor(options = {}) {
        // Alert storage
        this.alerts = new Map();
        this.alertHistory = [];
        
        // Configuration
        this.config = {
            deduplicationWindow: options.deduplicationWindow || 5 * 60 * 1000, // 5 minutes
            autoExpiryLow: options.autoExpiryLow || 30 * 60 * 1000, // 30 minutes
            autoExpiryMedium: options.autoExpiryMedium || 60 * 60 * 1000, // 1 hour
            autoExpiryHigh: options.autoExpiryHigh || 24 * 60 * 60 * 1000, // 24 hours
            maxAlerts: options.maxAlerts || 1000,
            maxHistory: options.maxHistory || 5000
        };
        
        // Alert categories
        this.categories = {
            SECURITY: 'security',
            PERFORMANCE: 'performance',
            ANOMALY: 'anomaly',
            SYSTEM: 'system'
        };
        
        // Start cleanup interval
        this.startCleanupInterval();
    }

    /**
     * Generate a unique alert
     * @param {Object} alertData - Alert information
     * @returns {Object|null} Generated alert or null if deduplicated
     */
    generateAlert(alertData) {
        const {
            title,
            message,
            severity = 'low',
            category = this.categories.SECURITY,
            source,
            metadata = {},
            recommendations = []
        } = alertData;

        // Calculate severity score (0-100)
        const severityScore = this.calculateSeverityScore(severity, metadata);

        // Create alert object
        const alert = {
            id: this.generateAlertId(),
            title,
            message,
            severity: severity.toLowerCase(),
            severityScore,
            category,
            source,
            metadata,
            recommendations,
            timestamp: new Date().toISOString(),
            timestampFormatted: DataTransformer.formatTimestamp(new Date()),
            status: 'active',
            acknowledged: false,
            acknowledgedAt: null,
            expired: false,
            expiresAt: this.calculateExpiryTime(severity)
        };

        // Check for duplicates
        if (this.isDuplicate(alert)) {
            logger.info('Alert deduplicated', { title: alert.title, severity: alert.severity });
            return null;
        }

        // Store alert
        this.alerts.set(alert.id, alert);
        this.alertHistory.push({ ...alert, action: 'created' });

        // Maintain size limits
        this.maintainSizeLimits();

        logger.info('Alert generated', { 
            alertId: alert.id, 
            title: alert.title, 
            severity: alert.severity,
            category: alert.category 
        });

        return alert;
    }

    /**
     * Calculate severity score (0-100)
     * @param {string} severity - Severity level
     * @param {Object} metadata - Additional context
     * @returns {number} Severity score
     */
    calculateSeverityScore(severity, metadata = {}) {
        const baseScores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30,
            'info': 10
        };

        let score = baseScores[severity.toLowerCase()] || 30;

        // Adjust based on metadata
        if (metadata.impact === ' widespread') score += 10;
        if (metadata.impact === 'multiple_systems') score += 5;
        if (metadata.confidence === 'high') score += 5;
        if (metadata.confidence === 'low') score -= 5;
        
        // Cap at 100
        return Math.min(100, Math.max(0, score));
    }

    /**
     * Calculate expiry time based on severity
     * @param {string} severity - Alert severity
     * @returns {Date} Expiry timestamp
     */
    calculateExpiryTime(severity) {
        const now = Date.now();
        const durations = {
            'critical': this.config.autoExpiryHigh * 2, // Never auto-expire critical
            'high': this.config.autoExpiryHigh,
            'medium': this.config.autoExpiryMedium,
            'low': this.config.autoExpiryLow,
            'info': this.config.autoExpiryLow
        };
        
        return new Date(now + (durations[severity.toLowerCase()] || this.config.autoExpiryLow));
    }

    /**
     * Check if alert is a duplicate
     * @param {Object} alert - New alert
     * @returns {boolean} True if duplicate
     */
    isDuplicate(alert) {
        const window = this.config.deduplicationWindow;
        const now = Date.now();

        for (const [id, existingAlert] of this.alerts) {
            // Check if within deduplication window
            const alertTime = new Date(existingAlert.timestamp).getTime();
            if (now - alertTime > window) continue;

            // Check similarity
            if (this.isSimilarAlert(existingAlert, alert)) {
                // Update existing alert with new occurrence
                existingAlert.occurrenceCount = (existingAlert.occurrenceCount || 1) + 1;
                existingAlert.lastOccurrence = alert.timestamp;
                return true;
            }
        }

        return false;
    }

    /**
     * Check if two alerts are similar
     * @param {Object} alert1 - First alert
     * @param {Object} alert2 - Second alert
     * @returns {boolean} True if similar
     */
    isSimilarAlert(alert1, alert2) {
        // Same title = duplicate
        if (alert1.title === alert2.title) return true;
        
        // Same source and similar message
        if (alert1.source === alert2.source && 
            this.stringSimilarity(alert1.message, alert2.message) > 0.8) {
            return true;
        }

        // Same IP/port combination
        if (alert1.metadata?.ip === alert2.metadata?.ip &&
            alert1.metadata?.port === alert2.metadata?.port) {
            return true;
        }

        return false;
    }

    /**
     * Calculate string similarity (simple implementation)
     * @param {string} str1 - First string
     * @param {string} str2 - Second string
     * @returns {number} Similarity score (0-1)
     */
    stringSimilarity(str1, str2) {
        if (!str1 || !str2) return 0;
        const s1 = str1.toLowerCase();
        const s2 = str2.toLowerCase();
        
        if (s1 === s2) return 1;
        
        // Simple word overlap calculation
        const words1 = new Set(s1.split(/\s+/));
        const words2 = new Set(s2.split(/\s+/));
        const intersection = new Set([...words1].filter(x => words2.has(x)));
        const union = new Set([...words1, ...words2]);
        
        return intersection.size / union.size;
    }

    /**
     * Acknowledge an alert
     * @param {string} alertId - Alert ID
     * @param {string} userId - User acknowledging
     * @returns {Object|null} Updated alert or null
     */
    acknowledgeAlert(alertId, userId) {
        const alert = this.alerts.get(alertId);
        if (!alert) return null;

        alert.acknowledged = true;
        alert.acknowledgedAt = new Date().toISOString();
        alert.acknowledgedBy = userId;
        alert.status = 'acknowledged';

        this.alertHistory.push({ ...alert, action: 'acknowledged', userId });

        logger.info('Alert acknowledged', { alertId, userId });
        return alert;
    }

    /**
     * Resolve an alert
     * @param {string} alertId - Alert ID
     * @param {string} resolution - Resolution notes
     * @returns {Object|null} Updated alert or null
     */
    resolveAlert(alertId, resolution) {
        const alert = this.alerts.get(alertId);
        if (!alert) return null;

        alert.status = 'resolved';
        alert.resolvedAt = new Date().toISOString();
        alert.resolution = resolution;

        this.alertHistory.push({ ...alert, action: 'resolved', resolution });

        logger.info('Alert resolved', { alertId, resolution });
        return alert;
    }

    /**
     * Get all active alerts
     * @param {Object} filters - Filter criteria
     * @returns {Array} Active alerts
     */
    getActiveAlerts(filters = {}) {
        let alerts = Array.from(this.alerts.values()).filter(a => !a.expired);

        if (filters.severity) {
            alerts = alerts.filter(a => a.severity === filters.severity);
        }
        if (filters.category) {
            alerts = alerts.filter(a => a.category === filters.category);
        }
        if (filters.acknowledged !== undefined) {
            alerts = alerts.filter(a => a.acknowledged === filters.acknowledged);
        }

        // Sort by severity score (descending)
        return alerts.sort((a, b) => b.severityScore - a.severityScore);
    }

    /**
     * Get alert summary
     * @returns {Object} Alert summary
     */
    getAlertSummary() {
        const active = this.getActiveAlerts();
        
        return {
            total: active.length,
            critical: active.filter(a => a.severity === 'critical').length,
            high: active.filter(a => a.severity === 'high').length,
            medium: active.filter(a => a.severity === 'medium').length,
            low: active.filter(a => a.severity === 'low').length,
            acknowledged: active.filter(a => a.acknowledged).length,
            unacknowledged: active.filter(a => !a.acknowledged).length,
            byCategory: {
                security: active.filter(a => a.category === this.categories.SECURITY).length,
                performance: active.filter(a => a.category === this.categories.PERFORMANCE).length,
                anomaly: active.filter(a => a.category === this.categories.ANOMALY).length,
                system: active.filter(a => a.category === this.categories.SYSTEM).length
            }
        };
    }

    /**
     * Generate insights based on current state
     * @param {Object} networkData - Current network data
     * @returns {Array} Generated insights
     */
    generateInsights(networkData) {
        const insights = [];
        const { connections, bandwidth, threats, historicalData } = networkData;

        // Traffic spike detection
        if (bandwidth && historicalData) {
            const avgInbound = historicalData.reduce((sum, h) => sum + (h.bandwidth?.inbound || 0), 0) / historicalData.length;
            if (bandwidth.inbound > avgInbound * 2) {
                insights.push({
                    message: 'Unusual spike in inbound traffic detected',
                    severity: bandwidth.inbound > avgInbound * 3 ? 'high' : 'medium',
                    recommendation: 'Review recent network activity and check for DDoS attempts',
                    category: this.categories.ANOMALY,
                    type: 'traffic_spike'
                });
            }
        }

        // Port scanning detection
        if (threats?.portScanActivity?.length > 0) {
            insights.push({
                message: 'Possible port scanning attack detected',
                severity: 'high',
                recommendation: 'Review firewall rules and consider blocking suspicious IPs',
                category: this.categories.SECURITY,
                type: 'port_scan',
                affectedIPs: threats.portScanActivity.map(p => p.scanningIP)
            });
        }

        // Suspicious connections
        if (threats?.suspiciousConnections?.length > 5) {
            insights.push({
                message: 'High number of suspicious connections detected',
                severity: 'medium',
                recommendation: 'Investigate these connections and verify their legitimacy',
                category: this.categories.SECURITY,
                type: 'suspicious_connections',
                count: threats.suspiciousConnections.length
            });
        }

        // Beaconing detection
        if (threats?.beaconingActivity?.length > 0) {
            insights.push({
                message: 'Potential C2 beaconing activity detected',
                severity: 'critical',
                recommendation: 'Immediate investigation required - check for compromised systems',
                category: this.categories.SECURITY,
                type: 'beaconing',
                affectedIPs: threats.beaconingActivity.map(b => b.ip)
            });
        }

        // Connection trend
        if (connections && historicalData) {
            const avgConnections = historicalData.reduce((sum, h) => sum + (h.connections?.length || 0), 0) / historicalData.length;
            if (connections.length > avgConnections * 1.5) {
                insights.push({
                    message: 'Connection count significantly above baseline',
                    severity: 'low',
                    recommendation: 'Monitor for unusual connection patterns',
                    category: this.categories.ANOMALY,
                    type: 'connection_spike'
                });
            }
        }

        return insights;
    }

    /**
     * Start cleanup interval for expired alerts
     */
    startCleanupInterval() {
        setInterval(() => {
            this.cleanupExpiredAlerts();
        }, 60 * 1000); // Run every minute
    }

    /**
     * Clean up expired alerts
     */
    cleanupExpiredAlerts() {
        const now = Date.now();
        let cleaned = 0;

        for (const [id, alert] of this.alerts) {
            if (alert.expiresAt && new Date(alert.expiresAt).getTime() < now) {
                if (alert.severity !== 'critical') { // Never expire critical
                    alert.expired = true;
                    alert.status = 'expired';
                    this.alertHistory.push({ ...alert, action: 'expired' });
                    this.alerts.delete(id);
                    cleaned++;
                }
            }
        }

        if (cleaned > 0) {
            logger.info('Cleaned up expired alerts', { count: cleaned });
        }
    }

    /**
     * Maintain size limits for alerts and history
     */
    maintainSizeLimits() {
        // Clean up old alerts if limit reached
        if (this.alerts.size > this.config.maxAlerts) {
            const sorted = Array.from(this.alerts.values())
                .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const toRemove = sorted.slice(0, this.alerts.size - this.config.maxAlerts);
            toRemove.forEach(alert => this.alerts.delete(alert.id));
        }

        // Clean up history if limit reached
        if (this.alertHistory.length > this.config.maxHistory) {
            this.alertHistory = this.alertHistory.slice(-this.config.maxHistory);
        }
    }

    /**
     * Generate alert ID
     * @returns {string} Unique alert ID
     */
    generateAlertId() {
        return `alert_${crypto.randomBytes(8).toString('hex')}_${Date.now()}`;
    }
}

module.exports = SmartAlertSystem;
