const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// Import services
const AWSService = require('./services/aws.service');
const AzureService = require('./services/azure.service');
const GCPService = require('./services/gcp.service');
const CloudRiskScoringService = require('./services/cloudRiskScoringService');
const CloudReportingService = require('./services/cloudReportingService');

class CloudForensics {
    constructor() {
        this.awsService = new AWSService();
        this.azureService = new AzureService();
        this.gcpService = new GCPService();
        this.riskScoringService = new CloudRiskScoringService();
        this.reportingService = new CloudReportingService();
        
        // In-memory analysis cache
        this.analysisCache = new Map();
        this.maxCacheSize = 1000;
    }

    async analyzeCloud(provider, credentials, userId) {
        try {
            const analysisId = this.generateAnalysisId();
            const startTime = Date.now();

            // Validate inputs
            if (!provider || !credentials || !userId) {
                throw new Error('Provider, credentials, and userId are required');
            }

            // Get appropriate service
            const service = this.getService(provider);
            if (!service) {
                throw new Error(`Unsupported provider: ${provider}`);
            }

            // Perform storage analysis
            const storageAnalysis = await service.analyzeStorage(credentials, userId);

            // Perform audit log analysis
            const auditLogs = await service.analyzeAuditLogs(credentials, userId);

            // Get threat intelligence
            const threatIntelligence = await service.getThreatIntelligence(credentials);

            // Calculate risk score
            const riskScore = this.riskScoringService.calculateRiskScore({
                storageAnalysis: storageAnalysis,
                auditLogs: auditLogs,
                threatIntelligence: threatIntelligence
            });

            // Create comprehensive analysis result
            const analysisResult = {
                analysisId: analysisId,
                userId: userId,
                provider: provider,
                timestamp: new Date().toISOString(),
                analysisDuration: Date.now() - startTime,
                summary: this.generateSummary(storageAnalysis, auditLogs, riskScore),
                resources: storageAnalysis.resources,
                vulnerabilities: storageAnalysis.vulnerabilities,
                riskScore: riskScore,
                threatIntelligence: threatIntelligence,
                auditLogs: auditLogs,
                recommendations: riskScore.recommendations
            };

            // Save report
            const reportResult = await this.reportingService.saveReport(userId, analysisResult);

            // Cache the analysis
            this.cacheAnalysis(analysisId, analysisResult);

            return {
                success: true,
                analysisId: analysisId,
                reportId: reportResult.reportId,
                ...analysisResult
            };

        } catch (error) {
            throw new Error(`Cloud analysis failed: ${error.message}`);
        }
    }

    getService(provider) {
        switch (provider.toLowerCase()) {
            case 'aws':
                return this.awsService;
            case 'azure':
                return this.azureService;
            case 'gcp':
                return this.gcpService;
            default:
                return null;
        }
    }

    generateSummary(storageAnalysis, auditLogs, riskScore) {
        return {
            totalResources: storageAnalysis.resources.length,
            totalVulnerabilities: storageAnalysis.vulnerabilities.length,
            riskScore: riskScore.score,
            riskLevel: riskScore.classification.level,
            confidence: riskScore.confidence.level,
            provider: storageAnalysis.provider,
            auditEvents: auditLogs.summary.totalEvents,
            anomalies: auditLogs.anomalies.length
        };
    }

    generateAnalysisId() {
        return `cloud-analysis-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    }

    cacheAnalysis(analysisId, analysisResult) {
        // Add to cache
        this.analysisCache.set(analysisId, analysisResult);

        // Maintain cache size
        if (this.analysisCache.size > this.maxCacheSize) {
            const firstKey = this.analysisCache.keys().next().value;
            this.analysisCache.delete(firstKey);
        }
    }

    getCachedAnalysis(analysisId) {
        return this.analysisCache.get(analysisId);
    }

    async getAnalysis(userId, analysisId) {
        try {
            // Check cache first
            const cached = this.getCachedAnalysis(analysisId);
            if (cached && cached.userId === userId) {
                return {
                    success: true,
                    fromCache: true,
                    ...cached
                };
            }

            // Get from storage
            const report = await this.reportingService.getReport(userId, analysisId);
            
            return {
                success: true,
                fromCache: false,
                ...report
            };

        } catch (error) {
            throw new Error(`Failed to get analysis: ${error.message}`);
        }
    }

    async getUserReports(userId, limit = 50) {
        try {
            const reports = await this.reportingService.getUserReports(userId, limit);
            
            return {
                success: true,
                userId: userId,
                reports: reports,
                total: reports.length
            };

        } catch (error) {
            throw new Error(`Failed to get user reports: ${error.message}`);
        }
    }

    async getUserStatistics(userId) {
        try {
            const stats = await this.reportingService.getUserStatistics(userId);
            
            return {
                success: true,
                userId: userId,
                statistics: stats
            };

        } catch (error) {
            throw new Error(`Failed to get user statistics: ${error.message}`);
        }
    }

    async getGlobalStatistics() {
        try {
            const stats = await this.reportingService.getGlobalStatistics();
            
            return {
                success: true,
                statistics: stats
            };

        } catch (error) {
            throw new Error(`Failed to get global statistics: ${error.message}`);
        }
    }

    async deleteReport(userId, reportId) {
        try {
            const result = await this.reportingService.deleteReport(userId, reportId);
            
            // Remove from cache if exists
            this.analysisCache.delete(reportId);
            
            return result;

        } catch (error) {
            throw new Error(`Failed to delete report: ${error.message}`);
        }
    }

    async exportReports(userId, format = 'json') {
        try {
            const exportData = await this.reportingService.exportReports(userId, format);
            
            return {
                success: true,
                userId: userId,
                format: format,
                data: exportData
            };

        } catch (error) {
            throw new Error(`Failed to export reports: ${error.message}`);
        }
    }

    async generateSummaryReport(userId) {
        try {
            const summary = await this.reportingService.generateSummaryReport(userId);
            
            return {
                success: true,
                userId: userId,
                summary: summary
            };

        } catch (error) {
            throw new Error(`Failed to generate summary report: ${error.message}`);
        }
    }

    async cleanupOldReports(userId, daysToKeep = 90) {
        try {
            const result = await this.reportingService.cleanupOldReports(userId, daysToKeep);
            
            return result;

        } catch (error) {
            throw new Error(`Failed to cleanup old reports: ${error.message}`);
        }
    }

    // Multi-provider batch analysis
    async analyzeMultipleProviders(configurations, userId) {
        try {
            const results = [];
            
            for (const config of configurations) {
                try {
                    const result = await this.analyzeCloud(
                        config.provider,
                        config.credentials,
                        userId
                    );
                    results.push(result);
                } catch (error) {
                    results.push({
                        success: false,
                        provider: config.provider,
                        error: error.message
                    });
                }
            }

            // Generate combined summary
            const combinedSummary = this.generateCombinedSummary(results);

            return {
                success: true,
                batchId: this.generateAnalysisId(),
                userId: userId,
                timestamp: new Date().toISOString(),
                results: results,
                summary: combinedSummary
            };

        } catch (error) {
            throw new Error(`Multi-provider analysis failed: ${error.message}`);
        }
    }

    generateCombinedSummary(results) {
        const summary = {
            totalProviders: results.length,
            successfulAnalyses: results.filter(r => r.success).length,
            failedAnalyses: results.filter(r => !r.success).length,
            totalResources: 0,
            totalVulnerabilities: 0,
            averageRiskScore: 0,
            riskLevelBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
            providerBreakdown: {}
        };

        let totalRiskScore = 0;
        let riskScoreCount = 0;

        results.forEach(result => {
            if (result.success) {
                summary.totalResources += result.summary.totalResources;
                summary.totalVulnerabilities += result.summary.totalVulnerabilities;
                
                if (result.riskScore) {
                    totalRiskScore += result.riskScore.score;
                    riskScoreCount++;
                    
                    const level = result.riskScore.classification.level;
                    summary.riskLevelBreakdown[level] = (summary.riskLevelBreakdown[level] || 0) + 1;
                }

                const provider = result.provider;
                summary.providerBreakdown[provider] = (summary.providerBreakdown[provider] || 0) + 1;
            }
        });

        summary.averageRiskScore = riskScoreCount > 0 ? totalRiskScore / riskScoreCount : 0;

        return summary;
    }

    // Health check
    async getHealthStatus() {
        try {
            const globalStats = await this.reportingService.getGlobalStatistics();
            
            return {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                services: {
                    awsService: true,
                    azureService: true,
                    gcpService: true,
                    riskScoringService: true,
                    reportingService: true
                },
                statistics: {
                    totalUsers: globalStats.totalUsers,
                    totalReports: globalStats.totalReports,
                    cacheSize: this.analysisCache.size
                }
            };

        } catch (error) {
            return {
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: error.message
            };
        }
    }
}

const cloudForensics = new CloudForensics();

// Middleware for API key validation
const validateApiKey = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const validApiKeys = process.env.CLOUD_API_KEYS ? process.env.CLOUD_API_KEYS.split(',') : [];
    
    if (!apiKey || !validApiKeys.includes(apiKey)) {
        return res.status(401).json({
            success: false,
            error: 'Invalid or missing API key'
        });
    }
    
    next();
};

// Rate limiting middleware (simple implementation)
const rateLimit = new Map();
const rateLimitMiddleware = (req, res, next) => {
    const clientId = req.ip;
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxRequests = 100;
    
    if (!rateLimit.has(clientId)) {
        rateLimit.set(clientId, { count: 1, resetTime: now + windowMs });
        return next();
    }
    
    const client = rateLimit.get(clientId);
    
    if (now > client.resetTime) {
        client.count = 1;
        client.resetTime = now + windowMs;
        return next();
    }
    
    if (client.count >= maxRequests) {
        return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded'
        });
    }
    
    client.count++;
    next();
};

// Routes
router.post('/analyze-cloud', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const { provider, credentials, userId } = req.body;
        
        const result = await cloudForensics.analyzeCloud(provider, credentials, userId);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.post('/analyze-batch', validateApiKey, rateLimitMiddleware, async (req, res) => {
    try {
        const { configurations, userId } = req.body;
        
        if (!Array.isArray(configurations)) {
            return res.status(400).json({
                success: false,
                error: 'Configurations must be an array'
            });
        }
        
        const result = await cloudForensics.analyzeMultipleProviders(configurations, userId);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/analysis/:id', validateApiKey, async (req, res) => {
    try {
        const { id } = req.params;
        const { userId } = req.query;
        
        if (!userId) {
            return res.status(400).json({
                success: false,
                error: 'userId parameter is required'
            });
        }
        
        const result = await cloudForensics.getAnalysis(userId, id);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/reports/:userId', validateApiKey, async (req, res) => {
    try {
        const { userId } = req.params;
        const { limit } = req.query;
        
        const result = await cloudForensics.getUserReports(userId, parseInt(limit) || 50);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/statistics/:userId', validateApiKey, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const result = await cloudForensics.getUserStatistics(userId);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/statistics', validateApiKey, async (req, res) => {
    try {
        const result = await cloudForensics.getGlobalStatistics();
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.delete('/reports/:userId/:reportId', validateApiKey, async (req, res) => {
    try {
        const { userId, reportId } = req.params;
        
        const result = await cloudForensics.deleteReport(userId, reportId);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/export/:userId', validateApiKey, async (req, res) => {
    try {
        const { userId } = req.params;
        const { format } = req.query;
        
        const result = await cloudForensics.exportReports(userId, format || 'json');
        
        if (format === 'csv') {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="cloud-reports-${userId}.csv"`);
        } else {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Disposition', `attachment; filename="cloud-reports-${userId}.json"`);
        }
        
        res.send(result.data);

    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/summary/:userId', validateApiKey, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const result = await cloudForensics.generateSummaryReport(userId);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.post('/cleanup/:userId', validateApiKey, async (req, res) => {
    try {
        const { userId } = req.params;
        const { daysToKeep } = req.body;
        
        const result = await cloudForensics.cleanupOldReports(userId, daysToKeep || 90);
        
        res.json({
            success: true,
            timestamp: new Date().toISOString(),
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

router.get('/health', async (req, res) => {
    try {
        const status = await cloudForensics.getHealthStatus();
        
        res.json(status);
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Webhook placeholder for alerts
router.post('/webhook/alert', validateApiKey, (req, res) => {
    // Placeholder for webhook alert handling
    res.json({
        success: true,
        message: 'Webhook alert placeholder - not implemented',
        timestamp: new Date().toISOString()
    });
});

module.exports = router;
