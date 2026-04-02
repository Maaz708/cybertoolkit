const express = require('express');
const { simpleParser } = require('mailparser');
const router = express.Router();

// Import services
const VirusTotalService = require('./services/virusTotalService');
const AuthenticationService = require('./services/authenticationService');
const HeaderAnalysisService = require('./services/headerAnalysisService');
const LinkAnalysisService = require('./services/linkAnalysisService');
const AttachmentAnalysisService = require('./services/attachmentAnalysisService');
const PhishingAnalysisService = require('./services/phishingAnalysisService');
const ScoringService = require('./services/scoringService');
const RecommendationService = require('./services/recommendationService');

class EmailForensicAnalyzer {
    constructor() {
        // Initialize VirusTotal service if API key is available
        const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
        this.virusTotalService = virusTotalApiKey ? new VirusTotalService(virusTotalApiKey) : null;
        
        // Initialize analysis services
        this.authService = new AuthenticationService();
        this.headerService = new HeaderAnalysisService();
        this.linkService = new LinkAnalysisService(this.virusTotalService);
        this.attachmentService = new AttachmentAnalysisService(this.virusTotalService);
        this.phishingService = new PhishingAnalysisService();
        this.scoringService = new ScoringService();
        this.recommendationService = new RecommendationService();
    }

    async analyzeEmail(emailFile) {
        try {
            const emailContent = emailFile.data.toString('utf8');
            const parsed = await simpleParser(emailContent);
            
            const analysis = {
                summary: {},
                authentication: this.authService.analyzeAuthentication(parsed),
                headerAnalysis: this.headerService.analyzeHeaders(parsed),
                links: await this.linkService.analyzeLinks(parsed),
                attachments: await this.attachmentService.analyzeAttachments(parsed),
                phishingAnalysis: this.phishingService.analyzePhishing(parsed),
                verdict: {},
                recommendations: [],
                // Add emailDetails for the frontend
                emailDetails: {
                    sender: parsed.from?.value?.[0]?.address || 'Unknown',
                    subject: parsed.subject || 'No Subject',
                    recipients: parsed.to?.value?.map((addr) => addr.address).join(', ') || 'Unknown',
                    receivedDate: parsed.date ? new Date(parsed.date).toLocaleString() : 'Unknown',
                    size: `${((emailFile.size || 0) / 1024).toFixed(1)} KB`
                }
            };
            
            analysis.summary = this.scoringService.generateSummary(analysis);
            analysis.verdict = this.scoringService.generateVerdict(analysis.summary.riskScore);
            analysis.recommendations = this.recommendationService.generateRecommendations(analysis);
            
            return analysis;
        } catch (error) {
            throw new Error(`Email analysis failed: ${error.message}`);
        }
    }
}

const analyzer = new EmailForensicAnalyzer();

router.post('/analyze', async (req, res) => {
    try {
        if (!req.files?.email) {
            return res.status(400).json({
                success: false,
                error: 'No email file uploaded'
            });
        }
        
        const emailFile = req.files.email;
        const result = await analyzer.analyzeEmail(emailFile);
        
        const response = {
            success: true,
            timestamp: new Date().toISOString(),
            emailInfo: {
                subject: emailFile.name,
                size: `${((emailFile.size || 0) / 1024).toFixed(1)} KB`
            },
            virusTotalEnabled: !!analyzer.virusTotalService,
            ...result
        };
        
        res.json(response);
    } catch (error) {
        console.error('Email analysis error:', error.message);
        res.status(500).json({
            success: false,
            error: 'Failed to analyze email',
            details: error.message
        });
    }
});

// Health check endpoint
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        virusTotalEnabled: !!analyzer.virusTotalService
    });
});

module.exports = router;