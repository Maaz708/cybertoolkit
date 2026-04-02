class NetworkScoringService {
    constructor() {
        this.baseScore = 100;
        this.weights = {
            suspiciousConnection: 10,
            portScanning: 25,
            highRiskOpenPort: 10,
            unknownProcess: 15,
            trafficAnomaly: 10,
            suspiciousIP: 15,
            beaconing: 20,
            dataExfiltration: 30,
            maliciousProcess: 25,
            criticalThreat: 35
        };
    }

    calculateRiskScore(analysis, threatDetection, trafficAnalysis, historicalComparison) {
        let score = this.baseScore;
        const deductions = [];
        const bonuses = [];

        // Connection analysis deductions
        const connectionScore = this.calculateConnectionScore(analysis.connectionAnalysis);
        score += connectionScore.score;
        deductions.push(...connectionScore.deductions);

        // Threat detection deductions
        const threatScore = this.calculateThreatScore(threatDetection);
        score += threatScore.score;
        deductions.push(...threatScore.deductions);

        // Traffic analysis deductions
        const trafficScore = this.calculateTrafficScore(trafficAnalysis);
        score += trafficScore.score;
        deductions.push(...trafficScore.deductions);

        // Historical comparison deductions
        const historicalScore = this.calculateHistoricalScore(historicalComparison);
        score += historicalScore.score;
        deductions.push(...historicalScore.deductions);

        // Apply bonuses for good security practices
        const bonusScore = this.calculateSecurityBonuses(analysis, threatDetection);
        score += bonusScore.score;
        bonuses.push(...bonusScore.bonuses);

        // Clamp score between 0-100
        score = Math.max(0, Math.min(100, score));

        return {
            score: score,
            baseScore: this.baseScore,
            deductions: deductions,
            bonuses: bonuses,
            totalDeductions: this.baseScore + bonusScore.score - score,
            riskLevel: this.classifyRiskLevel(score),
            scoreBreakdown: {
                connections: connectionScore.score,
                threats: threatScore.score,
                traffic: trafficScore.score,
                historical: historicalScore.score,
                bonuses: bonusScore.score
            }
        };
    }

    calculateConnectionScore(connectionAnalysis) {
        let score = 0;
        const deductions = [];

        // Suspicious connections
        const suspiciousCount = (connectionAnalysis.suspiciousConnections || []).length;
        if (suspiciousCount > 0) {
            const deduction = suspiciousCount * this.weights.suspiciousConnection;
            score -= deduction;
            deductions.push(`${suspiciousCount} suspicious connections (-${deduction})`);
        }

        // Port scanning activity
        const portScanCount = (connectionAnalysis.portScanActivity || []).length;
        if (portScanCount > 0) {
            connectionAnalysis.portScanActivity.forEach(scan => {
                const deduction = scan.severity === 'critical' ? this.weights.portScanning * 2 :
                                 scan.severity === 'high' ? this.weights.portScanning :
                                 scan.severity === 'medium' ? Math.floor(this.weights.portScanning / 2) :
                                 Math.floor(this.weights.portScanning / 4);
                score -= deduction;
                deductions.push(`Port scan from ${scan.scanningIP} (${scan.severity}) (-${deduction})`);
            });
        }

        // Beaconing activity
        const beaconingCount = (connectionAnalysis.beaconingActivity || []).length;
        if (beaconingCount > 0) {
            const deduction = beaconingCount * this.weights.beaconing;
            score -= deduction;
            deductions.push(`${beaconingCount} beaconing activities (-${deduction})`);
        }

        // Unusual ports
        const unusualPorts = (connectionAnalysis.unusualPorts || []).filter(p => p.risk === 'high');
        if (unusualPorts.length > 0) {
            const deduction = unusualPorts.length * this.weights.highRiskOpenPort;
            score -= deduction;
            deductions.push(`${unusualPorts.length} high-risk unusual ports (-${deduction})`);
        }

        return { score, deductions };
    }

    calculateThreatScore(threatDetection) {
        let score = 0;
        const deductions = [];

        if (!threatDetection || !threatDetection.detected) {
            return { score, deductions };
        }

        threatDetection.detected.forEach(threat => {
            let deduction = 0;

            switch (threat.type) {
                case 'PORT_SCAN':
                    deduction = threat.severity === 'critical' ? this.weights.portScanning * 2 :
                             threat.severity === 'high' ? this.weights.portScanning :
                             Math.floor(this.weights.portScanning / 2);
                    break;
                case 'SUSPICIOUS_IP':
                    deduction = this.weights.suspiciousIP;
                    break;
                case 'MALICIOUS_PROCESS':
                    deduction = this.weights.maliciousProcess;
                    break;
                case 'TRAFFIC_ANOMALY':
                    deduction = threat.severity === 'critical' ? this.weights.trafficAnomaly * 2 :
                             threat.severity === 'high' ? this.weights.trafficAnomaly :
                             Math.floor(this.weights.trafficAnomaly / 2);
                    break;
                case 'DATA_EXFILTRATION':
                    deduction = this.weights.dataExfiltration;
                    break;
                case 'BEACONING':
                    deduction = this.weights.beaconing;
                    break;
                default:
                    deduction = 5;
            }

            score -= deduction;
            deductions.push(`${threat.type}: ${threat.title} (-${deduction})`);
        });

        // Additional deduction for multiple critical threats
        const criticalThreats = threatDetection.detected.filter(t => t.severity === 'critical');
        if (criticalThreats.length > 1) {
            const deduction = (criticalThreats.length - 1) * this.weights.criticalThreat;
            score -= deduction;
            deductions.push(`Multiple critical threats (-${deduction})`);
        }

        return { score, deductions };
    }

    calculateTrafficScore(trafficAnalysis) {
        let score = 0;
        const deductions = [];

        if (!trafficAnalysis || !trafficAnalysis.anomalies) {
            return { score, deductions };
        }

        trafficAnalysis.anomalies.forEach(anomaly => {
            let deduction = 0;

            switch (anomaly.type) {
                case 'TRAFFIC_VOLUME':
                case 'UPLOAD_DOWNLOAD_RATIO':
                    deduction = anomaly.severity === 'critical' ? this.weights.trafficAnomaly * 2 :
                             anomaly.severity === 'high' ? this.weights.trafficAnomaly :
                             Math.floor(this.weights.trafficAnomaly / 2);
                    break;
                case 'BEACONING':
                    deduction = this.weights.beaconing;
                    break;
                case 'TRANSFER_RATE_ANOMALY':
                    deduction = this.weights.trafficAnomaly;
                    break;
                default:
                    deduction = Math.floor(this.weights.trafficAnomaly / 2);
            }

            score -= deduction;
            deductions.push(`${anomaly.type}: ${anomaly.description} (-${deduction})`);
        });

        // Check for unusual upload/download ratio
        if (trafficAnalysis.patterns && trafficAnalysis.patterns.uploadDownloadRatio > 10) {
            const deduction = Math.floor(this.weights.dataExfiltration * 0.7);
            score -= deduction;
            deductions.push(`High upload/download ratio (-${deduction})`);
        }

        return { score, deductions };
    }

    calculateHistoricalScore(historicalComparison) {
        let score = 0;
        const deductions = [];

        if (!historicalComparison || !historicalComparison.hasChanges) {
            return { score, deductions };
        }

        historicalComparison.changes.forEach(change => {
            let deduction = 0;

            switch (change.type) {
                case 'connection_spike':
                    deduction = change.severity === 'critical' ? this.weights.trafficAnomaly * 2 :
                             change.severity === 'high' ? this.weights.trafficAnomaly :
                             Math.floor(this.weights.trafficAnomaly / 2);
                    break;
                case 'traffic_spike':
                    deduction = change.severity === 'critical' ? this.weights.trafficAnomaly * 2 :
                             change.severity === 'high' ? this.weights.trafficAnomaly :
                             Math.floor(this.weights.trafficAnomaly / 2);
                    break;
                case 'new_processes':
                    deduction = change.severity === 'high' ? this.weights.unknownProcess :
                             change.severity === 'medium' ? Math.floor(this.weights.unknownProcess / 2) :
                             Math.floor(this.weights.unknownProcess / 4);
                    break;
                case 'risk_score_change':
                    if (change.details.direction === 'degrading') {
                        deduction = Math.floor(Math.abs(change.details.change) / 2);
                    }
                    break;
                default:
                    deduction = 5;
            }

            if (deduction > 0) {
                score -= deduction;
                deductions.push(`${change.type}: ${change.description} (-${deduction})`);
            }
        });

        return { score, deductions };
    }

    calculateSecurityBonuses(analysis, threatDetection) {
        let score = 0;
        const bonuses = [];

        // Bonus for low suspicious connections
        const suspiciousCount = (analysis.connectionAnalysis?.suspiciousConnections || []).length;
        if (suspiciousCount === 0 && (analysis.connectionAnalysis?.totalConnections || 0) > 10) {
            score += 5;
            bonuses.push('No suspicious connections detected (+5)');
        }

        // Bonus for no threats detected
        if (threatDetection && threatDetection.detected && threatDetection.detected.length === 0) {
            score += 10;
            bonuses.push('No threats detected (+10)');
        }

        // Bonus for balanced traffic (upload/download ratio between 0.5 and 2)
        if (analysis.networkStats) {
            const upload = analysis.networkStats.totalBytesSent || 0;
            const download = analysis.networkStats.totalBytesReceived || 0;
            if (upload > 0 && download > 0) {
                const ratio = upload / download;
                if (ratio >= 0.5 && ratio <= 2.0) {
                    score += 3;
                    bonuses.push('Balanced traffic patterns (+3)');
                }
            }
        }

        // Bonus for no port scanning activity
        const portScanCount = (analysis.connectionAnalysis?.portScanActivity || []).length;
        if (portScanCount === 0 && (analysis.connectionAnalysis?.totalConnections || 0) > 50) {
            score += 5;
            bonuses.push('No port scanning activity (+5)');
        }

        // Bonus for no beaconing
        const beaconingCount = (analysis.connectionAnalysis?.beaconingActivity || []).length;
        if (beaconingCount === 0 && (analysis.connectionAnalysis?.totalConnections || 0) > 20) {
            score += 5;
            bonuses.push('No beaconing activity (+5)');
        }

        return { score, bonuses };
    }

    classifyRiskLevel(score) {
        if (score >= 80) {
            return {
                level: 'Safe',
                color: 'green',
                description: 'Network appears secure with minimal threats',
                confidence: 'high'
            };
        } else if (score >= 60) {
            return {
                level: 'Suspicious',
                color: 'orange',
                description: 'Some suspicious activity detected - monitor closely',
                confidence: 'medium'
            };
        } else if (score >= 40) {
            return {
                level: 'Under Attack',
                color: 'red',
                description: 'Multiple threats detected - immediate action recommended',
                confidence: 'high'
            };
        } else {
            return {
                level: 'Compromised',
                color: 'darkred',
                description: 'System likely compromised - emergency response required',
                confidence: 'critical'
            };
        }
    }

    generateDetailedReport(scoreAnalysis, analysis, threatDetection, trafficAnalysis) {
        const report = {
            ...scoreAnalysis,
            recommendations: this.generateScoreBasedRecommendations(scoreAnalysis.score, analysis, threatDetection),
            securityPosture: this.assessSecurityPosture(scoreAnalysis, analysis, threatDetection),
            keyMetrics: this.extractKeyMetrics(analysis, threatDetection, trafficAnalysis),
            trending: this.assessTrends(scoreAnalysis)
        };

        return report;
    }

    generateScoreBasedRecommendations(score, analysis, threatDetection) {
        const recommendations = [];

        if (score < 40) {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Security Situation',
                description: 'Network is under active attack or compromised. Immediate incident response required.',
                actions: ['isolate_affected_systems', 'incident_response', 'emergency_procedures', 'contact_security_team']
            });
        } else if (score < 60) {
            recommendations.push({
                priority: 'high',
                title: 'High Risk Network Activity',
                description: 'Multiple security threats detected. Investigate and mitigate immediately.',
                actions: ['investigate_threats', 'block_malicious_ips', 'monitor_processes', 'update_firewall']
            });
        } else if (score < 80) {
            recommendations.push({
                priority: 'medium',
                title: 'Suspicious Network Activity',
                description: 'Some suspicious activity detected. Continue monitoring and investigate.',
                actions: ['monitor_activity', 'review_logs', 'update_security_rules', 'user_awareness']
            });
        } else {
            recommendations.push({
                priority: 'low',
                title: 'Network Security Good',
                description: 'Network appears secure. Continue monitoring and maintain security practices.',
                actions: ['continue_monitoring', 'regular_updates', 'security_training', 'policy_review']
            });
        }

        // Specific recommendations based on analysis
        if (analysis.connectionAnalysis?.suspiciousConnections?.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Investigate Suspicious Connections',
                description: `${analysis.connectionAnalysis.suspiciousConnections.length} suspicious connections require investigation.`,
                actions: ['investigate_connections', 'check_process_activity', 'ip_reputation_check']
            });
        }

        if (threatDetection?.detected?.some(t => t.type === 'MALICIOUS_PROCESS')) {
            recommendations.push({
                priority: 'high',
                title: 'Malicious Process Activity',
                description: 'Suspicious processes making network connections detected.',
                actions: ['process_analysis', 'malware_scan', 'terminate_suspicious_processes']
            });
        }

        if (analysis.connectionAnalysis?.portScanActivity?.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Port Scanning Detected',
                description: 'Active port scanning detected. Consider implementing rate limiting.',
                actions: ['block_scanning_ips', 'implement_rate_limiting', 'firewall_rules_update']
            });
        }

        return recommendations;
    }

    assessSecurityPosture(scoreAnalysis, analysis, threatDetection) {
        const posture = {
            overall: 'unknown',
            strengths: [],
            weaknesses: [],
            riskFactors: []
        };

        // Determine overall posture
        if (scoreAnalysis.score >= 80) {
            posture.overall = 'strong';
        } else if (scoreAnalysis.score >= 60) {
            posture.overall = 'moderate';
        } else if (scoreAnalysis.score >= 40) {
            posture.overall = 'weak';
        } else {
            posture.overall = 'critical';
        }

        // Identify strengths
        if ((analysis.connectionAnalysis?.suspiciousConnections || []).length === 0) {
            posture.strengths.push('Low suspicious connection activity');
        }

        if (!threatDetection?.detected || threatDetection.detected.length === 0) {
            posture.strengths.push('No active threats detected');
        }

        if ((analysis.connectionAnalysis?.beaconingActivity || []).length === 0) {
            posture.strengths.push('No beaconing activity detected');
        }

        // Identify weaknesses
        if ((analysis.connectionAnalysis?.suspiciousConnections || []).length > 5) {
            posture.weaknesses.push('High number of suspicious connections');
        }

        if (threatDetection?.detected?.some(t => t.severity === 'critical')) {
            posture.weaknesses.push('Critical threats present');
        }

        if ((analysis.connectionAnalysis?.portScanActivity || []).length > 0) {
            posture.weaknesses.push('Active port scanning detected');
        }

        // Identify risk factors
        if (analysis.connectionAnalysis?.beaconingActivity?.length > 0) {
            posture.riskFactors.push('Potential C2 communication');
        }

        if (threatDetection?.detected?.some(t => t.type === 'MALICIOUS_PROCESS')) {
            posture.riskFactors.push('Malicious process activity');
        }

        return posture;
    }

    extractKeyMetrics(analysis, threatDetection, trafficAnalysis) {
        return {
            totalConnections: analysis.connectionAnalysis?.totalConnections || 0,
            suspiciousConnections: (analysis.connectionAnalysis?.suspiciousConnections || []).length,
            activeThreats: (threatDetection?.detected || []).length,
            criticalThreats: (threatDetection?.detected?.filter(t => t.severity === 'critical') || []).length,
            trafficAnomalies: (trafficAnalysis?.anomalies || []).length,
            beaconingActivities: (analysis.connectionAnalysis?.beaconingActivity || []).length,
            portScanAttempts: (analysis.connectionAnalysis?.portScanActivity || []).length,
            riskScore: analysis.riskScore?.score || 100
        };
    }

    assessTrends(scoreAnalysis) {
        // This would integrate with historical data to assess trends
        // For now, return basic trend assessment
        return {
            direction: 'stable',
            confidence: 'medium',
            description: 'Score appears stable based on current analysis'
        };
    }

    // Utility methods
    updateWeights(newWeights) {
        Object.assign(this.weights, newWeights);
    }

    getWeights() {
        return { ...this.weights };
    }

    resetWeights() {
        this.weights = {
            suspiciousConnection: 10,
            portScanning: 25,
            highRiskOpenPort: 10,
            unknownProcess: 15,
            trafficAnomaly: 10,
            suspiciousIP: 15,
            beaconing: 20,
            dataExfiltration: 30,
            maliciousProcess: 25,
            criticalThreat: 35
        };
    }
}

module.exports = NetworkScoringService;
