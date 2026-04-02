class AlertService {
    constructor() {
        this.alertHistory = [];
        this.maxHistorySize = 1000;
        this.alertRules = {
            PORT_SCAN: {
                enabled: true,
                minSeverity: 'medium',
                cooldown: 300000, // 5 minutes
                maxPerHour: 10
            },
            SUSPICIOUS_IP: {
                enabled: true,
                minSeverity: 'medium',
                cooldown: 600000, // 10 minutes
                maxPerHour: 20
            },
            MALICIOUS_PROCESS: {
                enabled: true,
                minSeverity: 'high',
                cooldown: 180000, // 3 minutes
                maxPerHour: 15
            },
            TRAFFIC_ANOMALY: {
                enabled: true,
                minSeverity: 'medium',
                cooldown: 600000, // 10 minutes
                maxPerHour: 8
            },
            DATA_EXFILTRATION: {
                enabled: true,
                minSeverity: 'high',
                cooldown: 120000, // 2 minutes
                maxPerHour: 5
            },
            BEACONING: {
                enabled: true,
                minSeverity: 'medium',
                cooldown: 900000, // 15 minutes
                maxPerHour: 6
            }
        };
        
        this.severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
    }

    generateAlerts(threats, networkStats) {
        const alerts = {
            generated: [],
            summary: {
                total: 0,
                bySeverity: { low: 0, medium: 0, high: 0, critical: 0 },
                byType: {},
                suppressed: 0
            },
            recommendations: []
        };

        // Initialize type counters
        Object.keys(this.alertRules).forEach(type => {
            alerts.summary.byType[type] = 0;
        });

        // Process each threat and generate alerts
        threats.detected.forEach(threat => {
            const alert = this.createAlertFromThreat(threat);
            
            if (alert && this.shouldGenerateAlert(alert)) {
                alerts.generated.push(alert);
                alerts.summary.total++;
                alerts.summary.bySeverity[alert.severity]++;
                alerts.summary.byType[threat.type]++;
            } else if (alert) {
                alerts.summary.suppressed++;
            }
        });

        // Generate system-level alerts based on network stats
        const systemAlerts = this.generateSystemAlerts(networkStats, threats);
        alerts.generated.push(...systemAlerts);
        
        // Update summary for system alerts
        systemAlerts.forEach(alert => {
            alerts.summary.total++;
            alerts.summary.bySeverity[alert.severity]++;
        });

        // Sort alerts by severity and timestamp
        alerts.generated.sort((a, b) => {
            const severityDiff = this.severityOrder[b.severity] - this.severityOrder[a.severity];
            if (severityDiff !== 0) return severityDiff;
            return new Date(b.timestamp) - new Date(a.timestamp);
        });

        // Store alerts in history
        this.storeAlerts(alerts.generated);

        // Generate recommendations
        alerts.recommendations = this.generateAlertRecommendations(alerts);

        return alerts;
    }

    createAlertFromThreat(threat) {
        const rule = this.alertRules[threat.type];
        if (!rule || !rule.enabled) return null;

        if (this.compareSeverity(threat.severity, rule.minSeverity) < 0) {
            return null; // Severity below threshold
        }

        const alert = {
            id: this.generateAlertId(),
            type: threat.type,
            severity: threat.severity,
            title: threat.title,
            description: threat.description,
            details: threat.details,
            timestamp: threat.timestamp,
            source: 'threat_detection',
            status: 'active',
            actions: this.generateAlertActions(threat),
            escalation: this.calculateEscalation(threat),
            context: this.extractAlertContext(threat)
        };

        return alert;
    }

    generateSystemAlerts(networkStats, threats) {
        const alerts = [];

        // High connection count alert
        if (networkStats.totalConnections > 1000) {
            alerts.push({
                id: this.generateAlertId(),
                type: 'SYSTEM_PERFORMANCE',
                severity: networkStats.totalConnections > 5000 ? 'critical' : 'high',
                title: 'High Connection Count',
                description: `Unusually high number of connections: ${networkStats.totalConnections}`,
                details: {
                    connectionCount: networkStats.totalConnections,
                    threshold: 1000,
                    timeWindow: networkStats.timeWindow || 60
                },
                timestamp: new Date().toISOString(),
                source: 'system_monitor',
                status: 'active',
                actions: ['investigate_system', 'check_resources', 'monitor_performance'],
                escalation: this.calculateSystemEscalation(networkStats.totalConnections, 1000),
                context: { systemLoad: 'high' }
            });
        }

        // High bandwidth usage alert
        const totalBandwidth = (networkStats.totalBytesSent || 0) + (networkStats.totalBytesReceived || 0);
        if (totalBandwidth > 1024 * 1024 * 1024) { // > 1GB
            alerts.push({
                id: this.generateAlertId(),
                type: 'SYSTEM_PERFORMANCE',
                severity: totalBandwidth > 10 * 1024 * 1024 * 1024 ? 'critical' : 'high',
                title: 'High Bandwidth Usage',
                description: `Unusually high bandwidth usage: ${this.formatBytes(totalBandwidth)}`,
                details: {
                    bandwidthUsed: totalBandwidth,
                    threshold: 1024 * 1024 * 1024,
                    upload: networkStats.totalBytesSent,
                    download: networkStats.totalBytesReceived
                },
                timestamp: new Date().toISOString(),
                source: 'system_monitor',
                status: 'active',
                actions: ['investigate_bandwidth', 'check_large_transfers', 'monitor_network'],
                escalation: this.calculateSystemEscalation(totalBandwidth, 1024 * 1024 * 1024),
                context: { bandwidthUsage: 'high' }
            });
        }

        // Multiple critical threats alert
        const criticalThreats = threats.detected.filter(t => t.severity === 'critical');
        if (criticalThreats.length > 1) {
            alerts.push({
                id: this.generateAlertId(),
                type: 'MULTIPLE_THREATS',
                severity: 'critical',
                title: 'Multiple Critical Threats Detected',
                description: `${criticalThreats.length} critical threats detected simultaneously`,
                details: {
                    threatCount: criticalThreats.length,
                    threats: criticalThreats.map(t => ({ type: t.type, id: t.id }))
                },
                timestamp: new Date().toISOString(),
                source: 'system_monitor',
                status: 'active',
                actions: ['immediate_response', 'isolate_systems', 'incident_response'],
                escalation: { level: 'critical', autoEscalate: true },
                context: { threatLevel: 'critical' }
            });
        }

        return alerts;
    }

    shouldGenerateAlert(alert) {
        // Check cooldown period
        if (this.isInCooldown(alert)) {
            return false;
        }

        // Check hourly limit
        if (this.exceedsHourlyLimit(alert)) {
            return false;
        }

        // Check for duplicate alerts
        if (this.isDuplicateAlert(alert)) {
            return false;
        }

        return true;
    }

    isInCooldown(alert) {
        const rule = this.alertRules[alert.type];
        if (!rule || !rule.cooldown) return false;

        const now = Date.now();
        const recentAlerts = this.alertHistory.filter(a => 
            a.type === alert.type && 
            (now - new Date(a.timestamp).getTime()) < rule.cooldown
        );

        return recentAlerts.length > 0;
    }

    exceedsHourlyLimit(alert) {
        const rule = this.alertRules[alert.type];
        if (!rule || !rule.maxPerHour) return false;

        const now = Date.now();
        const hourAgo = now - (60 * 60 * 1000);
        const hourlyAlerts = this.alertHistory.filter(a => 
            a.type === alert.type && 
            new Date(a.timestamp).getTime() > hourAgo
        );

        return hourlyAlerts.length >= rule.maxPerHour;
    }

    isDuplicateAlert(alert) {
        const recentAlerts = this.alertHistory.slice(-50); // Check last 50 alerts
        
        return recentAlerts.some(existing => {
            if (existing.type !== alert.type) return false;
            if (existing.severity !== alert.severity) return false;
            
            // Check if details are similar
            return this.areDetailsSimilar(existing.details, alert.details);
        });
    }

    areDetailsSimilar(details1, details2) {
        if (!details1 || !details2) return false;
        
        // Check for common identifying fields
        const identifyingFields = ['scanningIP', 'ip', 'processName', 'targetIP'];
        
        return identifyingFields.some(field => {
            const value1 = details1[field];
            const value2 = details2[field];
            return value1 && value2 && value1 === value2;
        });
    }

    generateAlertActions(threat) {
        const actions = [];

        switch (threat.type) {
            case 'PORT_SCAN':
                actions.push('block_ip', 'update_firewall', 'monitor_network');
                break;
            case 'SUSPICIOUS_IP':
                actions.push('investigate_ip', 'check_reputation', 'monitor_connections');
                break;
            case 'MALICIOUS_PROCESS':
                actions.push('investigate_process', 'terminate_process', 'scan_malware');
                break;
            case 'TRAFFIC_ANOMALY':
                actions.push('investigate_traffic', 'check_performance', 'monitor_system');
                break;
            case 'DATA_EXFILTRATION':
                actions.push('block_uploads', 'investigate_transfers', 'check_permissions');
                break;
            case 'BEACONING':
                actions.push('block_ip', 'investigate_malware', 'monitor_processes');
                break;
            default:
                actions.push('investigate', 'monitor', 'log_incident');
        }

        return actions;
    }

    calculateEscalation(threat) {
        const escalation = {
            level: 'normal',
            autoEscalate: false,
            notifyLevel: 'standard'
        };

        if (threat.severity === 'critical') {
            escalation.level = 'critical';
            escalation.autoEscalate = true;
            escalation.notifyLevel = 'immediate';
        } else if (threat.severity === 'high') {
            escalation.level = 'high';
            escalation.autoEscalate = threat.type === 'MALICIOUS_PROCESS' || threat.type === 'DATA_EXFILTRATION';
            escalation.notifyLevel = 'urgent';
        }

        return escalation;
    }

    calculateSystemEscalation(currentValue, threshold) {
        const ratio = currentValue / threshold;
        
        if (ratio > 10) {
            return { level: 'critical', autoEscalate: true, notifyLevel: 'immediate' };
        } else if (ratio > 5) {
            return { level: 'high', autoEscalate: true, notifyLevel: 'urgent' };
        } else if (ratio > 2) {
            return { level: 'medium', autoEscalate: false, notifyLevel: 'standard' };
        }
        
        return { level: 'normal', autoEscalate: false, notifyLevel: 'standard' };
    }

    extractAlertContext(threat) {
        const context = {
            threatId: threat.id,
            detectionTime: threat.timestamp,
            systemLoad: 'normal'
        };

        // Add specific context based on threat type
        if (threat.details.processName) {
            context.processActivity = 'suspicious';
        }
        
        if (threat.details.scanningIP || threat.details.ip) {
            context.networkActivity = 'suspicious';
        }

        return context;
    }

    generateAlertRecommendations(alerts) {
        const recommendations = [];

        // Critical alerts recommendations
        if (alerts.summary.bySeverity.critical > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Alerts Require Immediate Action',
                description: `${alerts.summary.bySeverity.critical} critical alerts detected. Immediate response required.`,
                actions: ['isolate_affected_systems', 'incident_response', 'emergency_procedures']
            });
        }

        // High severity alerts recommendations
        if (alerts.summary.bySeverity.high > 2) {
            recommendations.push({
                priority: 'high',
                title: 'Multiple High-Severity Alerts',
                description: `${alerts.summary.bySeverity.high} high-severity alerts detected. Investigate urgently.`,
                actions: ['prioritize_investigation', 'allocate_resources', 'escalate_if_needed']
            });
        }

        // Port scan specific recommendations
        if (alerts.summary.byType.PORT_SCAN > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Port Scanning Activity Detected',
                description: 'Implement automatic IP blocking for scanning activities.',
                actions: ['configure_firewall', 'implement_rate_limiting', 'update_security_rules']
            });
        }

        // Process-based recommendations
        const processAlerts = alerts.generated.filter(a => a.type === 'MALICIOUS_PROCESS');
        if (processAlerts.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Suspicious Process Activity',
                description: 'Monitor or terminate suspicious processes and scan for malware.',
                actions: ['process_monitoring', 'malware_scan', 'system_hardening']
            });
        }

        // System performance recommendations
        const performanceAlerts = alerts.generated.filter(a => a.type === 'SYSTEM_PERFORMANCE');
        if (performanceAlerts.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'System Performance Issues',
                description: 'Investigate system resource usage and optimize performance.',
                actions: ['resource_optimization', 'capacity_planning', 'performance_monitoring']
            });
        }

        return recommendations;
    }

    // Helper methods
    generateAlertId() {
        return `ALERT_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    compareSeverity(severity1, severity2) {
        return this.severityOrder[severity1] - this.severityOrder[severity2];
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    storeAlerts(alerts) {
        alerts.forEach(alert => {
            this.alertHistory.push(alert);
        });

        // Keep only recent alerts
        if (this.alertHistory.length > this.maxHistorySize) {
            this.alertHistory = this.alertHistory.slice(-this.maxHistorySize);
        }
    }

    getAlertHistory(limit = 100) {
        return this.alertHistory.slice(-limit).reverse();
    }

    getActiveAlerts() {
        return this.alertHistory.filter(alert => alert.status === 'active');
    }

    acknowledgeAlert(alertId) {
        const alert = this.alertHistory.find(a => a.id === alertId);
        if (alert) {
            alert.status = 'acknowledged';
            alert.acknowledgedAt = new Date().toISOString();
        }
        return alert;
    }

    resolveAlert(alertId) {
        const alert = this.alertHistory.find(a => a.id === alertId);
        if (alert) {
            alert.status = 'resolved';
            alert.resolvedAt = new Date().toISOString();
        }
        return alert;
    }

    updateAlertRules(newRules) {
        Object.assign(this.alertRules, newRules);
    }
}

module.exports = AlertService;
