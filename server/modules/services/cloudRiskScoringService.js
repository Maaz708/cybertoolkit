class CloudRiskScoringService {
    constructor() {
        this.baseScore = 100;
        this.maxScore = 100;
        
        this.weights = {
            publicAccess: 30,
            noEncryption: 20,
            weakIAM: 15,
            noLogging: 10,
            dataExposure: 25,
            unusualAccess: 8,
            failedAttempts: 5,
            unknownRegions: 12
        };

        this.thresholds = {
            low: { min: 80, max: 100 },
            medium: { min: 60, max: 79 },
            high: { min: 40, max: 59 },
            critical: { min: 0, max: 39 }
        };
    }

    calculateRiskScore(analysisResults) {
        let score = this.baseScore;
        const deductions = [];
        const breakdown = {};

        // Storage analysis scoring
        if (analysisResults.storageAnalysis) {
            const storageScore = this.scoreStorageAnalysis(analysisResults.storageAnalysis);
            score += storageScore.score;
            deductions.push(...storageScore.deductions);
            breakdown.storage = storageScore.score;
        }

        // Audit logs scoring
        if (analysisResults.auditLogs) {
            const logsScore = this.scoreAuditLogs(analysisResults.auditLogs);
            score += logsScore.score;
            deductions.push(...logsScore.deductions);
            breakdown.auditLogs = logsScore.score;
        }

        // Threat intelligence scoring
        if (analysisResults.threatIntelligence) {
            const threatScore = this.scoreThreatIntelligence(analysisResults.threatIntelligence);
            score += threatScore.score;
            deductions.push(...threatScore.deductions);
            breakdown.threatIntel = threatScore.score;
        }

        // Data exposure scoring
        if (analysisResults.storageAnalysis) {
            const dataExposureScore = this.scoreDataExposure(analysisResults.storageAnalysis);
            score += dataExposureScore.score;
            deductions.push(...dataExposureScore.deductions);
            breakdown.dataExposure = dataExposureScore.score;
        }

        // Clamp score
        score = Math.max(0, Math.min(this.maxScore, score));

        const classification = this.classifyRiskLevel(score);
        const recommendations = this.generateRecommendations(score, classification, analysisResults);

        return {
            score: score,
            baseScore: this.baseScore,
            maxScore: this.maxScore,
            classification: classification,
            recommendations: recommendations,
            breakdown: breakdown,
            deductions: deductions,
            confidence: this.calculateConfidence(score, analysisResults),
            riskFactors: this.identifyRiskFactors(analysisResults),
            mitigation: this.generateMitigationAdvice(classification, analysisResults)
        };
    }

    scoreStorageAnalysis(storageAnalysis) {
        let score = 0;
        const deductions = [];

        storageAnalysis.vulnerabilities.forEach(vulnerability => {
            let deduction = 0;

            switch (vulnerability.type) {
                case 'public_access':
                    deduction = this.weights.publicAccess;
                    break;
                case 'no_encryption':
                    deduction = this.weights.noEncryption;
                    break;
                case 'weak_iam':
                    deduction = this.weights.weakIAM;
                    break;
                case 'no_logging':
                    deduction = this.weights.noLogging;
                    break;
                case 'data_exposure':
                    deduction = this.weights.dataExposure;
                    break;
                case 'analysis_error':
                    deduction = 5; // Minor deduction for analysis errors
                    break;
                default:
                    deduction = 3;
            }

            score -= deduction;
            deductions.push(`${vulnerability.type}: ${vulnerability.description} (-${deduction})`);
        });

        return { score, deductions };
    }

    scoreAuditLogs(auditLogs) {
        let score = 0;
        const deductions = [];

        // Score based on anomalies
        auditLogs.anomalies.forEach(anomaly => {
            let deduction = 0;

            switch (anomaly.type) {
                case 'unusual_access':
                    deduction = this.weights.unusualAccess;
                    break;
                case 'failed_attempts':
                    deduction = this.weights.failedAttempts;
                    break;
                case 'unknown_region':
                    deduction = this.weights.unknownRegions;
                    break;
                case 'log_analysis_error':
                    deduction = 3;
                    break;
                default:
                    deduction = 2;
            }

            score -= deduction;
            deductions.push(`${anomaly.type}: ${anomaly.description} (-${deduction})`);
        });

        return { score, deductions };
    }

    scoreThreatIntelligence(threatIntelligence) {
        let score = 0;
        const deductions = [];

        // Check for active threat findings
        Object.values(threatIntelligence.services).forEach(service => {
            if (service.findings && service.findings.length > 0) {
                const deduction = service.findings.length * 5;
                score -= deduction;
                deductions.push(`${service.status}: ${service.findings.length} findings (-${deduction})`);
            }
        });

        return { score, deductions };
    }

    scoreDataExposure(storageAnalysis) {
        let score = 0;
        const deductions = [];

        const dataExposureVulns = storageAnalysis.vulnerabilities.filter(v => v.type === 'data_exposure');
        if (dataExposureVulns.length > 0) {
            const deduction = dataExposureVulns.length * 8;
            score -= deduction;
            deductions.push(`Data exposure: ${dataExposureVulns.length} suspicious files (-${deduction})`);
        }

        return { score, deductions };
    }

    classifyRiskLevel(score) {
        if (score >= this.thresholds.low.min && score <= this.thresholds.low.max) {
            return {
                level: 'low',
                color: 'green',
                description: 'Cloud environment appears secure with minimal risks',
                confidence: 'high'
            };
        } else if (score >= this.thresholds.medium.min && score <= this.thresholds.medium.max) {
            return {
                level: 'medium',
                color: 'orange',
                description: 'Cloud environment has some security risks that should be addressed',
                confidence: 'medium'
            };
        } else if (score >= this.thresholds.high.min && score <= this.thresholds.high.max) {
            return {
                level: 'high',
                color: 'red',
                description: 'Cloud environment has significant security risks requiring immediate attention',
                confidence: 'high'
            };
        } else {
            return {
                level: 'critical',
                color: 'darkred',
                description: 'Cloud environment is at critical risk with multiple severe vulnerabilities',
                confidence: 'critical'
            };
        }
    }

    generateRecommendations(score, classification, analysisResults) {
        const recommendations = {
            action: 'MONITOR',
            priority: 'low',
            reason: '',
            followUp: []
        };

        if (classification.level === 'critical') {
            recommendations.action = 'IMMEDIATE_ACTION';
            recommendations.priority = 'critical';
            recommendations.reason = 'Critical security risks detected - immediate remediation required';
            recommendations.followUp = [
                'Immediately restrict public access to resources',
                'Enable encryption on all storage resources',
                'Review and tighten IAM permissions',
                'Enable comprehensive logging and monitoring',
                'Investigate unusual access patterns'
            ];
        } else if (classification.level === 'high') {
            recommendations.action = 'REMEDIATE';
            recommendations.priority = 'high';
            recommendations.reason = 'High-risk security issues detected - remediation required';
            recommendations.followUp = [
                'Restrict public access where found',
                'Enable encryption on unencrypted resources',
                'Review and update IAM policies',
                'Enable logging and monitoring',
                'Monitor for suspicious activity'
            ];
        } else if (classification.level === 'medium') {
            recommendations.action = 'REVIEW';
            recommendations.priority = 'medium';
            recommendations.reason = 'Medium security risks detected - review and address';
            recommendations.followUp = [
                'Review security configurations',
                'Enable missing logging',
                'Consider implementing additional security measures',
                'Monitor for changes',
                'Schedule regular security reviews'
            ];
        } else {
            recommendations.action = 'MONITOR';
            recommendations.priority = 'low';
            recommendations.reason = 'Cloud environment appears secure - continue monitoring';
            recommendations.followUp = [
                'Continue regular security monitoring',
                'Maintain current security practices',
                'Schedule periodic security assessments',
                'Stay updated on security best practices'
            ];
        }

        // Add specific recommendations based on findings
        if (analysisResults.storageAnalysis) {
            const publicResources = analysisResults.storageAnalysis.resources.filter(r => r.publicAccess);
            if (publicResources.length > 0) {
                recommendations.followUp.unshift(`Restrict public access to ${publicResources.length} resources`);
            }

            const unencryptedResources = analysisResults.storageAnalysis.resources.filter(r => !r.encrypted);
            if (unencryptedResources.length > 0) {
                recommendations.followUp.unshift(`Enable encryption on ${unencryptedResources.length} resources`);
            }
        }

        return recommendations;
    }

    calculateConfidence(score, analysisResults) {
        let confidence = 'medium';
        let confidenceScore = 50;

        // Higher confidence with more comprehensive analysis
        if (analysisResults.storageAnalysis && analysisResults.auditLogs && analysisResults.threatIntelligence) {
            confidenceScore += 30;
        }

        // Higher confidence with lower scores (more issues found)
        if (score < 70) {
            confidenceScore += 20;
        }

        // Determine confidence level
        if (confidenceScore >= 80) {
            confidence = 'high';
        } else if (confidenceScore >= 60) {
            confidence = 'medium';
        } else {
            confidence = 'low';
        }

        return {
            level: confidence,
            score: confidenceScore,
            factors: {
                comprehensiveAnalysis: !!(analysisResults.storageAnalysis && analysisResults.auditLogs && analysisResults.threatIntelligence),
                multipleIssues: score < 70,
                providerCoverage: analysisResults.storageAnalysis ? 'single' : 'multiple'
            }
        };
    }

    identifyRiskFactors(analysisResults) {
        const riskFactors = [];

        if (analysisResults.storageAnalysis) {
            const publicResources = analysisResults.storageAnalysis.resources.filter(r => r.publicAccess);
            if (publicResources.length > 0) {
                riskFactors.push({
                    factor: 'Public Resource Access',
                    severity: 'critical',
                    description: `${publicResources.length} resources are publicly accessible`,
                    affectedResources: publicResources.map(r => r.name)
                });
            }

            const unencryptedResources = analysisResults.storageAnalysis.resources.filter(r => !r.encrypted);
            if (unencryptedResources.length > 0) {
                riskFactors.push({
                    factor: 'Unencrypted Storage',
                    severity: 'high',
                    description: `${unencryptedResources.length} resources lack encryption`,
                    affectedResources: unencryptedResources.map(r => r.name)
                });
            }
        }

        if (analysisResults.auditLogs && analysisResults.auditLogs.anomalies.length > 0) {
            riskFactors.push({
                factor: 'Suspicious Activity',
                severity: 'medium',
                description: `${analysisResults.auditLogs.anomalies.length} anomalies detected in audit logs`,
                affectedResources: analysisResults.auditLogs.anomalies.map(a => a.resource)
            });
        }

        if (analysisResults.threatIntelligence) {
            const activeThreats = Object.values(analysisResults.threatIntelligence.services)
                .filter(service => service.findings && service.findings.length > 0);
            
            if (activeThreats.length > 0) {
                riskFactors.push({
                    factor: 'Active Threat Intelligence',
                    severity: 'high',
                    description: `${activeThreats.length} threat detection services have findings`,
                    affectedResources: activeThreats.map(service => service.status)
                });
            }
        }

        return riskFactors;
    }

    generateMitigationAdvice(classification, analysisResults) {
        const advice = {
            immediate: [],
            shortTerm: [],
            longTerm: []
        };

        if (classification.level === 'critical') {
            advice.immediate = [
                'Immediately restrict all public access to cloud resources',
                'Enable encryption on all storage resources',
                'Review and revoke unnecessary IAM permissions',
                'Enable comprehensive logging and monitoring',
                'Isolate affected resources if possible'
            ];

            advice.shortTerm = [
                'Conduct thorough security audit',
                'Implement network security controls',
                'Review and update security policies',
                'Train staff on cloud security best practices'
            ];

            advice.longTerm = [
                'Implement automated security monitoring',
                'Establish regular security assessment schedule',
                'Implement zero-trust security model',
                'Create incident response procedures'
            ];
        } else if (classification.level === 'high') {
            advice.immediate = [
                'Restrict public access to identified resources',
                'Enable encryption on unencrypted resources',
                'Review and tighten IAM policies',
                'Enable comprehensive logging'
            ];

            advice.shortTerm = [
                'Conduct security assessment of all resources',
                'Implement additional security controls',
                'Review access patterns and logs',
                'Update security configurations'
            ];

            advice.longTerm = [
                'Implement automated security scanning',
                'Establish security monitoring procedures',
                'Regular security training and awareness',
                'Create security governance framework'
            ];
        } else if (classification.level === 'medium') {
            advice.immediate = [
                'Review identified security issues',
                'Enable missing logging and monitoring',
                'Update security configurations'
            ];

            advice.shortTerm = [
                'Conduct comprehensive security review',
                'Implement additional security measures',
                'Schedule regular security assessments'
            ];

            advice.longTerm = [
                'Implement automated security monitoring',
                'Establish security best practices',
                'Regular security training',
                'Continuous security improvement'
            ];
        } else {
            advice.immediate = [
                'Continue current security monitoring',
                'Maintain existing security controls'
            ];

            advice.shortTerm = [
                'Schedule periodic security assessments',
                'Stay updated on security best practices'
            ];

            advice.longTerm = [
                'Implement advanced security monitoring',
                'Continuous security improvement program',
                'Security awareness training'
            ];
        }

        return advice;
    }

    // Configuration methods
    updateWeights(newWeights) {
        Object.assign(this.weights, newWeights);
    }

    updateThresholds(newThresholds) {
        Object.assign(this.thresholds, newThresholds);
    }

    getWeights() {
        return { ...this.weights };
    }

    getThresholds() {
        return { ...this.thresholds };
    }

    resetToDefaults() {
        this.weights = {
            publicAccess: 30,
            noEncryption: 20,
            weakIAM: 15,
            noLogging: 10,
            dataExposure: 25,
            unusualAccess: 8,
            failedAttempts: 5,
            unknownRegions: 12
        };

        this.thresholds = {
            low: { min: 80, max: 100 },
            medium: { min: 60, max: 79 },
            high: { min: 40, max: 59 },
            critical: { min: 0, max: 39 }
        };
    }

    // Advanced scoring methods
    calculateContextualScore(baseScore, contextFactors) {
        let adjustedScore = baseScore;

        // Adjust based on provider
        if (contextFactors.provider === 'aws') {
            adjustedScore += 2; // AWS has mature security features
        } else if (contextFactors.provider === 'azure') {
            adjustedScore += 1; // Azure has good security features
        } else if (contextFactors.provider === 'gcp') {
            adjustedScore += 1; // GCP has good security features
        }

        // Adjust based on environment
        if (contextFactors.environment === 'production') {
            adjustedScore -= 5; // Production environments need stricter security
        } else if (contextFactors.environment === 'development') {
            adjustedScore += 3; // Development environments have more tolerance
        }

        // Adjust based on compliance requirements
        if (contextFactors.compliance === 'hipaa' || contextFactors.compliance === 'pci') {
            adjustedScore -= 10; // Compliance requirements increase risk
        }

        return Math.max(0, Math.min(100, adjustedScore));
    }

    generateDetailedScoreReport(scoringResult) {
        return {
            summary: {
                finalScore: scoringResult.score,
                classification: scoringResult.classification.level,
                confidence: scoringResult.confidence.level,
                recommendation: scoringResult.recommendations.action
            },
            breakdown: scoringResult.breakdown,
            riskFactors: scoringResult.riskFactors,
            mitigation: scoringResult.mitigation,
            analysis: {
                totalDeductions: scoringResult.deductions.length,
                scoringFactors: Object.keys(scoringResult.breakdown).length,
                riskLevel: scoringResult.classification.level
            }
        };
    }
}

module.exports = CloudRiskScoringService;
