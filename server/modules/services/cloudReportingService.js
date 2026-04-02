const fs = require('fs');
const path = require('path');

class CloudReportingService {
    constructor() {
        this.reportsDir = path.join(__dirname, '../../reports/cloud');
        this.ensureReportsDirectory();
    }

    ensureReportsDirectory() {
        try {
            if (!fs.existsSync(this.reportsDir)) {
                fs.mkdirSync(this.reportsDir, { recursive: true });
            }
        } catch (error) {
            console.error('Failed to create reports directory:', error.message);
        }
    }

    async saveReport(userId, analysisResult) {
        try {
            const userReportsDir = path.join(this.reportsDir, userId);
            
            // Create user directory if it doesn't exist
            if (!fs.existsSync(userReportsDir)) {
                fs.mkdirSync(userReportsDir, { recursive: true });
            }

            // Generate report filename with timestamp
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const reportId = `cloud-analysis-${timestamp}`;
            const reportPath = path.join(userReportsDir, `${reportId}.json`);

            // Prepare report data
            const reportData = {
                reportId: reportId,
                userId: userId,
                timestamp: new Date().toISOString(),
                provider: analysisResult.provider,
                summary: analysisResult.summary,
                resources: analysisResult.resources,
                vulnerabilities: analysisResult.vulnerabilities,
                riskScore: analysisResult.riskScore,
                threatIntelligence: analysisResult.threatIntelligence,
                auditLogs: analysisResult.auditLogs,
                recommendations: analysisResult.recommendations,
                metadata: {
                    analysisDuration: analysisResult.analysisDuration || 0,
                    resourceCount: analysisResult.resources?.length || 0,
                    vulnerabilityCount: analysisResult.vulnerabilities?.length || 0,
                    riskLevel: analysisResult.riskScore?.classification?.level || 'unknown'
                }
            };

            // Save report to file
            fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2));

            // Update user index
            await this.updateUserIndex(userId, reportData);

            return {
                success: true,
                reportId: reportId,
                reportPath: reportPath,
                timestamp: reportData.timestamp
            };

        } catch (error) {
            throw new Error(`Failed to save report: ${error.message}`);
        }
    }

    async updateUserIndex(userId, reportData) {
        try {
            const indexPath = path.join(this.reportsDir, userId, 'index.json');
            let index = [];

            // Load existing index if it exists
            if (fs.existsSync(indexPath)) {
                const indexData = fs.readFileSync(indexPath, 'utf8');
                index = JSON.parse(indexData);
            }

            // Add new report to index
            index.push({
                reportId: reportData.reportId,
                timestamp: reportData.timestamp,
                provider: reportData.provider,
                riskScore: reportData.riskScore.score,
                riskLevel: reportData.riskScore.classification.level,
                resourceCount: reportData.metadata.resourceCount,
                vulnerabilityCount: reportData.metadata.vulnerabilityCount
            });

            // Sort by timestamp (newest first)
            index.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

            // Keep only last 100 reports per user
            if (index.length > 100) {
                index = index.slice(0, 100);
            }

            // Save updated index
            fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));

        } catch (error) {
            console.error('Failed to update user index:', error.message);
        }
    }

    async getReport(userId, reportId) {
        try {
            const reportPath = path.join(this.reportsDir, userId, `${reportId}.json`);
            
            if (!fs.existsSync(reportPath)) {
                throw new Error('Report not found');
            }

            const reportData = fs.readFileSync(reportPath, 'utf8');
            return JSON.parse(reportData);

        } catch (error) {
            throw new Error(`Failed to get report: ${error.message}`);
        }
    }

    async getUserReports(userId, limit = 50) {
        try {
            const indexPath = path.join(this.reportsDir, userId, 'index.json');
            
            if (!fs.existsSync(indexPath)) {
                return [];
            }

            const indexData = fs.readFileSync(indexPath, 'utf8');
            const index = JSON.parse(indexData);

            // Return limited number of reports
            return index.slice(0, limit);

        } catch (error) {
            throw new Error(`Failed to get user reports: ${error.message}`);
        }
    }

    async getUserStatistics(userId) {
        try {
            const reports = await this.getUserReports(userId, 1000); // Get all reports for stats
            
            const stats = {
                totalReports: reports.length,
                providerBreakdown: {},
                riskLevelBreakdown: {
                    low: 0,
                    medium: 0,
                    high: 0,
                    critical: 0
                },
                averageRiskScore: 0,
                totalResources: 0,
                totalVulnerabilities: 0,
                lastAnalysis: null,
                trendData: []
            };

            if (reports.length === 0) {
                return stats;
            }

            // Calculate statistics
            let totalRiskScore = 0;
            
            reports.forEach(report => {
                // Provider breakdown
                stats.providerBreakdown[report.provider] = (stats.providerBreakdown[report.provider] || 0) + 1;
                
                // Risk level breakdown
                stats.riskLevelBreakdown[report.riskLevel]++;
                
                // Risk score
                totalRiskScore += report.riskScore;
                
                // Resources and vulnerabilities
                stats.totalResources += report.resourceCount;
                stats.totalVulnerabilities += report.vulnerabilityCount;
            });

            stats.averageRiskScore = totalRiskScore / reports.length;
            stats.lastAnalysis = reports[0].timestamp;

            // Generate trend data (last 10 reports)
            stats.trendData = reports.slice(0, 10).reverse().map(report => ({
                timestamp: report.timestamp,
                riskScore: report.riskScore,
                riskLevel: report.riskLevel,
                vulnerabilityCount: report.vulnerabilityCount
            }));

            return stats;

        } catch (error) {
            throw new Error(`Failed to get user statistics: ${error.message}`);
        }
    }

    async getGlobalStatistics() {
        try {
            const globalStats = {
                totalUsers: 0,
                totalReports: 0,
                providerBreakdown: {},
                riskLevelBreakdown: {
                    low: 0,
                    medium: 0,
                    high: 0,
                    critical: 0
                },
                averageRiskScore: 0,
                topRiskyUsers: [],
                recentReports: []
            };

            // Get all user directories
            if (!fs.existsSync(this.reportsDir)) {
                return globalStats;
            }

            const userDirs = fs.readdirSync(this.reportsDir)
                .filter(dir => {
                    const dirPath = path.join(this.reportsDir, dir);
                    return fs.statSync(dirPath).isDirectory();
                });

            globalStats.totalUsers = userDirs.length;

            let totalRiskScore = 0;
            let totalReports = 0;
            const userRiskScores = [];

            // Process each user
            for (const userId of userDirs) {
                try {
                    const userStats = await this.getUserStatistics(userId);
                    
                    totalReports += userStats.totalReports;
                    totalRiskScore += userStats.averageRiskScore * userStats.totalReports;
                    
                    userRiskScores.push({
                        userId: userId,
                        averageRiskScore: userStats.averageRiskScore,
                        totalReports: userStats.totalReports,
                        lastAnalysis: userStats.lastAnalysis
                    });

                    // Add to provider breakdown
                    Object.entries(userStats.providerBreakdown).forEach(([provider, count]) => {
                        globalStats.providerBreakdown[provider] = (globalStats.providerBreakdown[provider] || 0) + count;
                    });

                    // Add to risk level breakdown
                    Object.entries(userStats.riskLevelBreakdown).forEach(([level, count]) => {
                        globalStats.riskLevelBreakdown[level] += count;
                    });

                } catch (error) {
                    // Skip user if there's an error
                    continue;
                }
            }

            globalStats.totalReports = totalReports;
            globalStats.averageRiskScore = totalReports > 0 ? totalRiskScore / totalReports : 0;

            // Get top risky users
            globalStats.topRiskyUsers = userRiskScores
                .sort((a, b) => b.averageRiskScore - a.averageRiskScore)
                .slice(0, 10);

            // Get recent reports (simplified - would need more complex logic)
            globalStats.recentReports = userRiskScores
                .sort((a, b) => new Date(b.lastAnalysis) - new Date(a.lastAnalysis))
                .slice(0, 5)
                .map(user => ({
                    userId: user.userId,
                    timestamp: user.lastAnalysis,
                    averageRiskScore: user.averageRiskScore
                }));

            return globalStats;

        } catch (error) {
            throw new Error(`Failed to get global statistics: ${error.message}`);
        }
    }

    async deleteReport(userId, reportId) {
        try {
            const reportPath = path.join(this.reportsDir, userId, `${reportId}.json`);
            
            if (!fs.existsSync(reportPath)) {
                throw new Error('Report not found');
            }

            // Delete report file
            fs.unlinkSync(reportPath);

            // Update user index
            await this.removeReportFromIndex(userId, reportId);

            return { success: true, message: 'Report deleted successfully' };

        } catch (error) {
            throw new Error(`Failed to delete report: ${error.message}`);
        }
    }

    async removeReportFromIndex(userId, reportId) {
        try {
            const indexPath = path.join(this.reportsDir, userId, 'index.json');
            
            if (!fs.existsSync(indexPath)) {
                return;
            }

            const indexData = fs.readFileSync(indexPath, 'utf8');
            const index = JSON.parse(indexData);

            // Remove report from index
            const updatedIndex = index.filter(report => report.reportId !== reportId);

            // Save updated index
            fs.writeFileSync(indexPath, JSON.stringify(updatedIndex, null, 2));

        } catch (error) {
            console.error('Failed to remove report from index:', error.message);
        }
    }

    async exportReports(userId, format = 'json') {
        try {
            const reports = await this.getUserReports(userId, 1000);
            const exportData = {
                userId: userId,
                exportTimestamp: new Date().toISOString(),
                totalReports: reports.length,
                reports: []
            };

            // Load full report data for each report
            for (const reportInfo of reports) {
                try {
                    const fullReport = await this.getReport(userId, reportInfo.reportId);
                    exportData.reports.push(fullReport);
                } catch (error) {
                    console.error(`Failed to load report ${reportInfo.reportId}:`, error.message);
                }
            }

            switch (format.toLowerCase()) {
                case 'json':
                    return JSON.stringify(exportData, null, 2);
                case 'csv':
                    return this.exportToCSV(exportData);
                default:
                    return JSON.stringify(exportData, null, 2);
            }

        } catch (error) {
            throw new Error(`Failed to export reports: ${error.message}`);
        }
    }

    exportToCSV(exportData) {
        const csvLines = [
            'Report ID,Timestamp,Provider,Risk Score,Risk Level,Resource Count,Vulnerability Count'
        ];

        exportData.reports.forEach(report => {
            const line = [
                report.reportId,
                report.timestamp,
                report.provider,
                report.riskScore.score,
                report.riskScore.classification.level,
                report.metadata.resourceCount,
                report.metadata.vulnerabilityCount
            ];
            csvLines.push(line.join(','));
        });

        return csvLines.join('\n');
    }

    async generateSummaryReport(userId) {
        try {
            const stats = await this.getUserStatistics(userId);
            const reports = await this.getUserReports(userId, 10);

            const summary = {
                userId: userId,
                generatedAt: new Date().toISOString(),
                statistics: stats,
                recentAnalyses: reports,
                recommendations: this.generateUserRecommendations(stats),
                complianceStatus: this.assessComplianceStatus(stats)
            };

            return summary;

        } catch (error) {
            throw new Error(`Failed to generate summary report: ${error.message}`);
        }
    }

    generateUserRecommendations(stats) {
        const recommendations = [];

        if (stats.averageRiskScore < 60) {
            recommendations.push({
                priority: 'high',
                title: 'High Security Risk Detected',
                description: 'Your cloud environment has significant security risks that require immediate attention',
                actions: ['Review all public resources', 'Enable encryption', 'Tighten IAM policies']
            });
        } else if (stats.averageRiskScore < 80) {
            recommendations.push({
                priority: 'medium',
                title: 'Moderate Security Risks',
                description: 'Your cloud environment has some security risks that should be addressed',
                actions: ['Review security configurations', 'Enable missing logging', 'Monitor for changes']
            });
        } else {
            recommendations.push({
                priority: 'low',
                title: 'Good Security Posture',
                description: 'Your cloud environment appears to be well-secured',
                actions: ['Continue monitoring', 'Regular security reviews', 'Stay updated on best practices']
            });
        }

        return recommendations;
    }

    assessComplianceStatus(stats) {
        const compliance = {
            overall: 'compliant',
            issues: [],
            score: 100
        };

        // Check for compliance issues
        if (stats.riskLevelBreakdown.critical > 0) {
            compliance.issues.push('Critical security risks detected');
            compliance.score -= 40;
        }

        if (stats.riskLevelBreakdown.high > 2) {
            compliance.issues.push('Multiple high-risk issues');
            compliance.score -= 20;
        }

        if (stats.averageRiskScore < 70) {
            compliance.issues.push('Average risk score below acceptable threshold');
            compliance.score -= 15;
        }

        if (stats.totalVulnerabilities > 10) {
            compliance.issues.push('High number of vulnerabilities');
            compliance.score -= 10;
        }

        if (compliance.score < 80) {
            compliance.overall = 'non-compliant';
        } else if (compliance.score < 95) {
            compliance.overall = 'partially-compliant';
        }

        return compliance;
    }

    // Cleanup old reports
    async cleanupOldReports(userId, daysToKeep = 90) {
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

            const reports = await this.getUserReports(userId, 1000);
            const reportsToDelete = [];

            for (const report of reports) {
                const reportDate = new Date(report.timestamp);
                if (reportDate < cutoffDate) {
                    reportsToDelete.push(report.reportId);
                }
            }

            // Delete old reports
            for (const reportId of reportsToDelete) {
                await this.deleteReport(userId, reportId);
            }

            return {
                success: true,
                deletedCount: reportsToDelete.length,
                message: `Deleted ${reportsToDelete.length} old reports`
            };

        } catch (error) {
            throw new Error(`Failed to cleanup old reports: ${error.message}`);
        }
    }
}

module.exports = CloudReportingService;
