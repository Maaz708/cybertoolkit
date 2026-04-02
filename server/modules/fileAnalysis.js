const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mime = require('mime-types');

// Import services
const FileHashService = require('./services/fileHashService');
const PatternDetectionService = require('./services/patternDetectionService');
const FileTypeService = require('./services/fileTypeService');
const PEAnalysisService = require('./services/peAnalysisService');
const URLExtractionService = require('./services/urlExtractionService');
const MetadataService = require('./services/metadataService');
const FileScoringService = require('./services/fileScoringService');

class FileAnalyzer {
    constructor() {
        this.analysisHistory = [];
        
        // Initialize services
        this.hashService = new FileHashService();
        this.patternService = new PatternDetectionService();
        this.fileTypeService = new FileTypeService();
        this.peService = new PEAnalysisService();
        this.urlService = new URLExtractionService();
        this.metadataService = new MetadataService();
        this.scoringService = new FileScoringService();
    }

    async analyzeFile(fileBuffer, filename) {
        try {
            const fileStats = {
                size: fileBuffer.length,
                lastModified: new Date().toISOString()
            };
            const mimeType = mime.lookup(filename) || 'application/octet-stream';

            const analysis = {
                summary: {},
                file_info: {
                    filename: filename,
                    size: fileStats.size,
                    mimeType: mimeType,
                    lastModified: fileStats.lastModified,
                    analyzedAt: new Date().toISOString()
                },
                hashes: this.hashService.calculateHashes(fileBuffer),
                entropy_analysis: this.analyzeEntropy(fileBuffer),
                pattern_analysis: this.patternService.detectPatterns(fileBuffer, filename),
                file_type_validation: this.fileTypeService.validateFileType(fileBuffer, filename),
                url_analysis: this.urlService.extractURLs(fileBuffer),
                metadata: this.metadataService.extractMetadata(filename, fileBuffer),
                pe_analysis: null,
                risk_score: {},
                verdict: {},
                recommendations: []
            };

            // Add script-specific pattern analysis
            const specificPatterns = this.patternService.detectFileTypeSpecificPatterns(fileBuffer, filename);
            if (specificPatterns.length > 0) {
                analysis.pattern_analysis.specificFindings = specificPatterns;
            }

            // PE analysis for executable files
            if (this.fileTypeService.isExecutable(analysis.file_type_validation?.detectedMimeType)) {
                analysis.pe_analysis = this.peService.analyzePEFile(fileBuffer);
            }

            // Calculate risk score and generate verdict
            console.log("Analysis object before scoring:", {
                file_info: analysis.file_info,
                file_type_validation: analysis.file_type_validation,
                entropy_analysis: analysis.entropy_analysis
            });
            
            analysis.risk_score = this.scoringService.calculateRiskScore(analysis);
            console.log("RISK SCORE DEBUG:", analysis.risk_score);
            
            // Safe verdict assignment with fallback
            analysis.verdict = analysis.risk_score?.riskLevel || {
                level: 'unknown',
                risk: 'low',
                description: 'No classification available'
            };
            
            analysis.recommendations = analysis.risk_score?.deductions?.length > 0 ? 
                this.scoringService.generateScoreBasedRecommendations(analysis.risk_score.score, analysis) : 
                [{ priority: 'low', title: 'File appears safe', description: 'No significant threats detected' }];

            // Generate summary
            analysis.summary = this.generateSummary(analysis);

            // Store in history
            this.analysisHistory.push({
                filename: analysis.file_info.filename,
                timestamp: analysis.file_info.analyzedAt,
                score: analysis.risk_score?.score || 0,
                verdict: analysis.verdict?.level || 'unknown'
            });

            return analysis;
        } catch (error) {
            throw new Error(`File analysis failed: ${error.message}`);
        }
    }

    analyzeEntropy(buffer) {
        try {
            const entropy = this.hashService?.calculateEntropy?.(buffer) || 0;
            const classification = this.hashService?.classifyEntropy?.(entropy) || {
                level: 'normal',
                risk: 'low',
                description: 'Normal file entropy'
            };

            return {
                entropy: entropy,
                classification: classification,
                distribution: this.calculateByteDistribution?.(buffer) || []
            };
        } catch (error) {
            console.error('Error in analyzeEntropy:', error);
            return {
                entropy: 0,
                classification: {
                    level: 'normal',
                    risk: 'low',
                    description: 'Error calculating entropy'
                },
                distribution: []
            };
        }
    }

    calculateByteDistribution(buffer) {
        const distribution = new Array(256).fill(0);
        
        for (let i = 0; i < buffer.length; i++) {
            distribution[buffer[i]]++;
        }

        // Calculate statistics
        const nonZeroBytes = distribution.filter(count => count > 0).length;
        const maxFrequency = Math.max(...distribution);
        const minFrequency = Math.min(...distribution.filter(count => count > 0));

        return {
            uniqueBytes: nonZeroBytes,
            totalBytes: 256,
            maxFrequency: maxFrequency,
            minFrequency: minFrequency,
            uniformity: nonZeroBytes / 256
        };
    }

    generateSummary(analysis) {
        const summary = {
            riskScore: analysis.risk_score?.score || 0,
            riskLevel: analysis.verdict?.level || 'unknown',
            totalFindings: 0,
            highRiskFindings: 0,
            fileCategory: this.categorizeFile(analysis),
            analysisCompleteness: this.assessAnalysisCompleteness(analysis)
        };

        // Count findings
        summary.totalFindings = analysis.pattern_analysis?.total || 0;
        summary.highRiskFindings = analysis.pattern_analysis?.highRisk?.length || 0;

        // Add URL findings
        if (analysis.url_analysis?.flagged) {
            summary.totalFindings += analysis.url_analysis.flagged.length;
        }

        // Add PE findings
        if (analysis.pe_analysis?.suspiciousSections?.length > 0) {
            summary.totalFindings += analysis.pe_analysis.suspiciousSections.length;
            summary.highRiskFindings += analysis.pe_analysis.suspiciousSections.filter(s => s.risk === 'high').length;
        }

        return summary;
    }

    categorizeFile(analysis) {
        const mimeType = analysis.file_type_validation?.detectedMimeType || 'application/octet-stream';
        
        if (this.fileTypeService.isExecutable(mimeType)) {
            return 'Executable';
        } else if (this.fileTypeService.isScript(mimeType)) {
            return 'Script';
        } else if (this.fileTypeService.isArchive(mimeType)) {
            return 'Archive';
        } else if (mimeType.startsWith('image/')) {
            return 'Image';
        } else if (mimeType.startsWith('text/')) {
            return 'Document';
        } else {
            return 'Other';
        }
    }

    assessAnalysisCompleteness(analysis) {
        const completeness = {
            entropy: !!analysis.entropy_analysis,
            patterns: !!analysis.pattern_analysis,
            fileType: !!analysis.file_type_validation,
            urls: !!analysis.url_analysis,
            metadata: !!analysis.metadata,
            peAnalysis: !!analysis.pe_analysis,
            scriptAnalysis: !!analysis.pattern_analysis?.specificFindings,
            overall: 0
        };

        const completedAreas = Object.values(completeness).filter(v => v === true).length - 1; // Exclude overall
        completeness.overall = Math.round((completedAreas / 6) * 100);

        return completeness;
    }

    getAnalysisHistory() {
        return this.analysisHistory.slice(-50); // Return last 50 analyses
    }

    // Placeholder for YARA rule support
    async scanWithYARA(filePath) {
        return {
            supported: false,
            message: 'YARA rule scanning not implemented yet',
            rules: []
        };
    }

    // Placeholder for sandbox analysis
    async submitToSandbox(filePath) {
        return {
            supported: false,
            message: 'Sandbox analysis not implemented yet',
            submissionId: null
        };
    }

    // Placeholder for threat intelligence integration
    async checkThreatIntelligence(hashes) {
        return {
            supported: false,
            message: 'Threat intelligence integration not implemented yet',
            sources: [],
            matches: []
        };
    }
}

const analyzer = new FileAnalyzer();

// Routes
router.post('/analyze', async (req, res) => {
    try {
        console.log('File upload request received');
        console.log('req.files:', req.files);
        console.log('req.body:', req.body);
        
        if (!req.files?.file) {
            console.error('No file found in req.files');
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }

        const file = req.files.file;
        const tempPath = path.join(__dirname, '../../temp', file.name);
        
        // Ensure temp directory exists
        const tempDir = path.dirname(tempPath);
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }

        // Save file temporarily
        file.mv(tempPath, async (err) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    error: 'Failed to save file'
                });
            }

            try {
                // Read the file buffer
                const fileBuffer = fs.readFileSync(tempPath);
                console.log('Starting file analysis for:', file.name);
                
                const analysis = await analyzer.analyzeFile(fileBuffer, file.name);
                console.log('Analysis completed successfully');
                
                // Clean up temp file
                fs.unlinkSync(tempPath);

                res.json({
                    success: true,
                    timestamp: new Date().toISOString(),
                    ...analysis
                });
            } catch (analysisError) {
                console.error('File analysis error:', analysisError);
                console.error('Error stack:', analysisError.stack);
                // Clean up temp file on error
                try { fs.unlinkSync(tempPath); } catch (e) {}
                
                res.status(500).json({
                    success: false,
                    error: analysisError.message
                });
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/history', (req, res) => {
    res.json({
        success: true,
        history: analyzer.getAnalysisHistory()
    });
});

router.post('/yara-scan', async (req, res) => {
    try {
        const { filePath } = req.body;
        const result = await analyzer.scanWithYARA(filePath);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/sandbox-submit', async (req, res) => {
    try {
        const { filePath } = req.body;
        const result = await analyzer.submitToSandbox(filePath);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/threat-intel', async (req, res) => {
    try {
        const { hashes } = req.body;
        const result = await analyzer.checkThreatIntelligence(hashes);
        res.json({
            success: true,
            ...result
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
            hashService: true,
            patternService: true,
            fileTypeService: true,
            peService: true,
            urlService: true,
            metadataService: true,
            scoringService: true
        }
    });
});

module.exports = router;
