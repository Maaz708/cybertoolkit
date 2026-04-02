class FileScoringService {
    constructor() {
        this.baseScore = 100;
        this.weights = {
            highEntropy: 20,
            suspiciousPattern: 10,
            dangerousFileType: 25,
            extensionMismatch: 20,
            suspiciousURL: 10,
            suspiciousSection: 15,
            noImports: 10,
            packedFile: 30
        };
    }

    calculateRiskScore(analysis) {
        let score = this.baseScore;
        const deductions = [];

        // Check for common document formats that are naturally ZIP-based
        const isCommonDocument = this.isCommonDocumentFormat(analysis.file_info?.mimeType, analysis.file_info?.filename);
        console.log('Document format check:', isCommonDocument, 'MIME:', analysis.file_info?.mimeType, 'Filename:', analysis.file_info?.filename);
        
        // Entropy-based deductions - be less aggressive for documents
        if (isCommonDocument) {
            // Documents naturally have higher entropy - reduce penalty
            if (analysis.entropy_analysis?.classification?.risk === 'high') {
                score -= Math.floor(this.weights.highEntropy * 0.3); // Only 30% of penalty
                deductions.push('High entropy in document format (normal for .docx, .xlsx, etc.)');
            }
        } else {
            // Full penalty for non-documents
            if (analysis.entropy_analysis && analysis.entropy_analysis.classification && analysis.entropy_analysis.classification.risk === 'high') {
                score -= this.weights.highEntropy;
                deductions.push('High entropy - likely packed or encrypted');
            } else if (analysis.entropy_analysis && analysis.entropy_analysis.classification && analysis.entropy_analysis.classification.risk === 'medium') {
                score -= Math.floor(this.weights.highEntropy / 2);
                deductions.push('Elevated entropy - possible obfuscation');
            }
        }

        // Pattern detection deductions
        const patternFindings = analysis.pattern_analysis;
        if (patternFindings && patternFindings.highRisk) {
            patternFindings.highRisk.forEach(pattern => {
                score -= this.weights.suspiciousPattern;
                deductions.push(`High-risk pattern: ${pattern.pattern}`);
            });
        }

        if (patternFindings && patternFindings.mediumRisk) {
            patternFindings.mediumRisk.forEach(pattern => {
                score -= Math.floor(this.weights.suspiciousPattern / 2);
                deductions.push(`Medium-risk pattern: ${pattern.pattern}`);
            });
        }

        // File type deductions
        if (analysis.file_type_validation && analysis.file_type_validation.risk === 'critical') {
            score -= this.weights.dangerousFileType * 2;
            deductions.push('Critical: Executable disguised as safe file type');
        } else if (analysis.file_type_validation && analysis.file_type_validation.risk === 'high') {
            score -= this.weights.dangerousFileType;
            deductions.push('High-risk file type detected');
        }

        // Extension mismatch deductions
        if (analysis.file_type_validation && !analysis.file_type_validation.isValid) {
            // Don't penalize document formats for being ZIP-based
            if (!isCommonDocument || analysis.file_type_validation.risk === 'critical') {
                score -= this.weights.extensionMismatch;
                deductions.push('File type does not match extension');
            }
        }

        // URL analysis deductions
        if (analysis.url_analysis && analysis.url_analysis.flagged) {
            analysis.url_analysis.flagged.forEach(url => {
                const deduction = url.risk === 'high' ? this.weights.suspiciousURL : Math.floor(this.weights.suspiciousURL / 2);
                score -= deduction;
                deductions.push(`Suspicious URL: ${url.reasons.join(', ')}`);
            });
        }

        // PE-specific deductions
        if (analysis.pe_analysis) {
            // Suspicious sections
            analysis.pe_analysis.suspiciousSections.forEach(section => {
                const deduction = section.risk === 'high' ? this.weights.suspiciousPE : Math.floor(this.weights.suspiciousPE / 2);
                score -= deduction;
                deductions.push(`Suspicious PE section: ${section.name} (${section.reasons.join(', ')})`);
            });

            // No imports (possibly packed)
            if (analysis.pe_analysis.riskIndicators.some(indicator => indicator.type === 'no_imports')) {
                score -= this.weights.noImports;
                deductions.push('No imports found - possibly packed');
            }

            // Packer signatures
            if (analysis.metadata.possibleOrigin.possibleTools.some(tool => tool.includes('Packer') || tool.includes('Protector'))) {
                score -= this.weights.packedFile;
                deductions.push('Packer/protector detected');
            }
        }

        // Script-specific deductions
        if (analysis.pattern_analysis && analysis.pattern_analysis.specificFindings) {
            analysis.pattern_analysis.specificFindings.forEach(finding => {
                const deduction = finding.severity === 'high' ? this.weights.suspiciousPattern : Math.floor(this.weights.suspiciousPattern / 2);
                score -= deduction;
                deductions.push(`Script risk: ${finding.pattern}`);
            });
        }

        score = Math.max(0, Math.min(100, score));

        return {
            score: score,
            baseScore: this.baseScore,
            deductions: deductions,
            riskLevel: this.classifyRiskLevel(score),
            totalDeductions: this.baseScore - score
        };
    }
    
    classifyRiskLevel(score) {
        if (score >= 80) {
            return {
                level: 'Safe',
                color: 'green',
                description: 'File appears safe with minimal security concerns'
            };
        } else if (score >= 60) {
            return {
                level: 'Suspicious',
                color: 'orange',
                description: 'File contains suspicious elements - exercise caution'
            };
        } else {
            return {
                level: 'Malicious',
                color: 'red',
                description: 'File shows multiple malicious indicators - high probability of malware'
            };
        }
    }
    
    generateDetailedScoring(analysis) {
        const riskScore = this.calculateRiskScore(analysis);
        
        const detailedScoring = {
            ...riskScore,
            breakdown: {
                entropy: this.getEntropyScore(analysis.entropyAnalysis),
                patterns: this.getPatternScore(analysis.patternAnalysis),
                fileType: this.getFileTypeScore(analysis.fileTypeValidation),
                urls: this.getURLScore(analysis.urlAnalysis),
                pe: this.getPEScore(analysis.peAnalysis),
                metadata: this.getMetadataScore(analysis.metadata)
            },
            recommendations: this.generateScoreBasedRecommendations(riskScore.score, analysis)
        };
        
        return detailedScoring;
    }
    
    getEntropyScore(entropyAnalysis) {
        if (!entropyAnalysis || !entropyAnalysis.classification) {
            return {
                score: 0,
                maxDeduction: this.weights.highEntropy,
                analysis: 'Entropy analysis not available'
            };
        }
        
        const classification = entropyAnalysis.classification;
        const baseScore = classification.risk === 'high' ? -this.weights.highEntropy : 
                          classification.risk === 'medium' ? -Math.floor(this.weights.highEntropy / 2) : 0;
        
        return {
            score: baseScore,
            maxDeduction: this.weights.highEntropy,
            analysis: `Entropy: ${entropyAnalysis.entropy.toFixed(2)} (${classification.level})`
        };
    }
    
    getPatternScore(patternAnalysis) {
        let score = 0;
        const details = [];
        
        patternAnalysis.highRisk.forEach(pattern => {
            score -= this.weights.suspiciousPattern;
            details.push(`High: ${pattern.pattern} (${pattern.matches} matches)`);
        });
        
        patternAnalysis.mediumRisk.forEach(pattern => {
            score -= Math.floor(this.weights.suspiciousPattern / 2);
            details.push(`Medium: ${pattern.pattern} (${pattern.matches} matches)`);
        });
        
        return {
            score: score,
            maxDeduction: patternAnalysis.total * this.weights.suspiciousPattern,
            analysis: details.join('; ')
        };
    }
    
    getFileTypeScore(fileTypeValidation) {
        let score = 0;
        const details = [];
        
        if (!fileTypeValidation.isValid) {
            score -= this.weights.extensionMismatch;
            details.push('Extension mismatch');
        }
        
        if (fileTypeValidation.risk === 'critical') {
            score -= this.weights.dangerousFileType * 2;
            details.push('Critical file type');
        } else if (fileTypeValidation.risk === 'high') {
            score -= this.weights.dangerousFileType;
            details.push('Dangerous file type');
        }
        
        return {
            score: score,
            maxDeduction: this.weights.extensionMismatch + this.weights.dangerousFileType,
            analysis: details.join('; ') || 'File type validation passed'
        };
    }
    
    getURLScore(urlAnalysis) {
        let score = 0;
        const details = [];
        
        urlAnalysis.flagged.forEach(url => {
            const deduction = url.risk === 'high' ? this.weights.suspiciousURL : Math.floor(this.weights.suspiciousURL / 2);
            score -= deduction;
            details.push(`${url.risk}: ${url.reasons.join(', ')}`);
        });
        
        return {
            score: score,
            maxDeduction: urlAnalysis.flagged.length * this.weights.suspiciousURL,
            analysis: details.join('; ') || 'No suspicious URLs'
        };
    }
    
    getPEScore(peAnalysis) {
        if (!peAnalysis) return { score: 0, maxDeduction: 0, analysis: 'Not a PE file' };
        
        let score = 0;
        const details = [];
        
        peAnalysis.suspiciousSections.forEach(section => {
            const deduction = section.risk === 'high' ? this.weights.suspiciousSection : Math.floor(this.weights.suspiciousSection / 2);
            score -= deduction;
            details.push(`${section.name}: ${section.reasons.join(', ')}`);
        });
        
        peAnalysis.riskIndicators.forEach(indicator => {
            if (indicator.type === 'no_imports') {
                score -= this.weights.noImports;
                details.push('No imports found');
            }
        });
        
        return {
            score: score,
            maxDeduction: this.weights.suspiciousSection * 5 + this.weights.noImports,
            analysis: details.join('; ') || 'PE analysis passed'
        };
    }
    
    getMetadataScore(metadata) {
        let score = 0;
        const details = [];
        
        if (metadata.possibleOrigin.possibleTools.length > 0) {
            const packerTools = metadata.possibleOrigin.possibleTools.filter(tool => 
                tool.includes('Packer') || tool.includes('Protector')
            );
            
            if (packerTools.length > 0) {
                score -= this.weights.packedFile;
                details.push(`Packer detected: ${packerTools.join(', ')}`);
            }
        }
        
        return {
            score: score,
            maxDeduction: this.weights.packedFile,
            analysis: details.join('; ') || 'Metadata analysis passed'
        };
    }
    
    generateScoreBasedRecommendations(score, analysis) {
        const recommendations = [];
        
        if (score < 60) {
            recommendations.push({
                priority: 'critical',
                title: 'High Risk File Detected',
                description: 'File exhibits multiple malicious characteristics. Immediate quarantine recommended.'
            });
            recommendations.push({
                priority: 'high',
                title: 'Sandbox Analysis Required',
                description: 'File should be analyzed in isolated environment before any further handling.'
            });
        } else if (score < 80) {
            recommendations.push({
                priority: 'medium',
                title: 'Suspicious File Detected',
                description: 'File contains suspicious elements. Handle with caution and consider additional analysis.'
            });
        } else {
            recommendations.push({
                priority: 'low',
                title: 'File Appears Safe',
                description: 'No significant threats detected. Standard security precautions apply.'
            });
        }
        
        // Specific recommendations based on findings
        if (analysis.entropyAnalysis?.classification?.risk === 'high') {
            recommendations.push({
                priority: 'high',
                title: 'High Entropy Detected',
                description: 'File may be packed or encrypted. Deep analysis recommended.'
            });
        }
        
        if (analysis.fileTypeValidation?.risk === 'critical') {
            recommendations.push({
                priority: 'critical',
                title: 'File Type Mismatch',
                description: 'File extension does not match actual content. This is a strong indicator of malware.'
            });
        }
        
        if (analysis.urlAnalysis?.flagged?.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Suspicious URLs Found',
                description: `Found ${analysis.urlAnalysis.flagged.length} suspicious URLs in file content.`
            });
        }
        
        return recommendations;
    }

    isCommonDocumentFormat(mimeType, filename) {
        if (!mimeType && !filename) return false;
        
        const documentMimes = [
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // .docx
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
            'application/vnd.openxmlformats-officedocument.presentationml.presentation', // .pptx
            'application/vnd.ms-word.document.macroEnabled.12', // .docm
            'application/vnd.ms-excel.sheet.macroEnabled.12', // .xlsm
            'application/vnd.ms-powerpoint.presentation.macroEnabled.12', // .pptm
            'application/vnd.oasis.opendocument.text', // .odt
            'application/vnd.oasis.opendocument.spreadsheet', // .ods
            'application/vnd.oasis.opendocument.presentation', // .odp
            'application/zip' // Common container for Office documents
        ];
        
        const documentExtensions = ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.odt', '.ods', '.odp'];
        
        // Check MIME type
        if (mimeType && documentMimes.includes(mimeType)) {
            return true;
        }
        
        // Check filename extension
        if (filename) {
            const ext = filename.toLowerCase().split('.').pop();
            if (documentExtensions.includes('.' + ext)) {
                return true;
            }
        }
        
        return false;
    }
}

module.exports = FileScoringService;
