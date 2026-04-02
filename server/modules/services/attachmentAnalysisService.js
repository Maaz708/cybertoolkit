class AttachmentAnalysisService {
    constructor(virusTotalService = null) {
        this.virusTotalService = virusTotalService;
        this.dangerousExtensions = [
            '.exe', '.js', '.bat', '.scr', '.zip', '.rar', '.7z', '.msi',
            '.com', '.pif', '.vbs', '.jar', '.app', '.deb', '.rpm'
        ];
    }

    async analyzeAttachments(parsed) {
        const attachmentAnalysis = {
            totalAttachments: 0,
            dangerousAttachments: [],
            suspiciousAttachments: [],
            virusTotalScans: []
        };
        
        if (parsed.attachments) {
            attachmentAnalysis.totalAttachments = parsed.attachments.length;
            
            for (const att of parsed.attachments) {
                const analysis = await this.analyzeSingleAttachment(att);
                
                if (analysis.dangerous) {
                    attachmentAnalysis.dangerousAttachments.push({
                        filename: att.filename || 'unnamed',
                        contentType: att.contentType || 'unknown',
                        size: att.size || 0,
                        reason: analysis.reason
                    });
                }
                
                if (analysis.suspicious) {
                    attachmentAnalysis.suspiciousAttachments.push({
                        filename: att.filename || 'unnamed',
                        contentType: att.contentType || 'unknown',
                        size: att.size || 0,
                        reason: analysis.reason
                    });
                }

                // Perform VirusTotal scan if available
                if (this.virusTotalService && this.virusTotalService.isApiKeyValid() && att.content) {
                    const vtResult = await this.virusTotalService.analyzeAttachment({
                        filename: att.filename,
                        content: att.content
                    });
                    
                    if (vtResult.success) {
                        attachmentAnalysis.virusTotalScans.push({
                            filename: att.filename || 'unnamed',
                            positives: vtResult.positives,
                            total: vtResult.total,
                            scanId: vtResult.scanId,
                            permalink: vtResult.permalink,
                            detectedEngines: vtResult.detectedEngines,
                            fileHash: vtResult.fileHash
                        });
                    }
                }
            }
        }
        
        return attachmentAnalysis;
    }

    async analyzeSingleAttachment(attachment) {
        const filename = attachment.filename || 'unnamed';
        const extension = filename.toLowerCase().substring(filename.lastIndexOf('.'));
        
        let dangerous = false;
        let suspicious = false;
        let reason = '';
        
        // Check for dangerous file types
        if (this.dangerousExtensions.includes(extension)) {
            dangerous = true;
            reason = `Dangerous file type: ${extension}`;
        }
        
        // Check for suspicious patterns
        if (!dangerous) {
            if (extension === '.pdf' && attachment.size > 10 * 1024 * 1024) {
                suspicious = true;
                reason = 'Unusually large PDF file';
            } else if (filename.match(/^[a-f0-9]{32,}$/i) || filename.match(/^[a-f0-9]{40}$/i)) {
                suspicious = true;
                reason = 'Hash-like filename pattern';
            } else if (filename.match(/invoice|receipt|statement|payment/i) && extension !== '.pdf') {
                suspicious = true;
                reason = 'Financial document with non-PDF extension';
            } else if (extension === '.doc' || extension === '.docx' || extension === '.xls' || extension === '.xlsx') {
                // Check for double extensions
                if (filename.match(/\.[^.]+\.[^.]+$/)) {
                    suspicious = true;
                    reason = 'Double extension detected';
                }
            }
        }
        
        return { dangerous, suspicious, reason };
    }

    getAttachmentScore(attachmentAnalysis) {
        let score = 0;
        score -= attachmentAnalysis.dangerousAttachments.length * 25;
        score -= attachmentAnalysis.suspiciousAttachments.length * 15;
        
        // Additional deductions for VirusTotal detections
        if (attachmentAnalysis.virusTotalScans) {
            attachmentAnalysis.virusTotalScans.forEach(scan => {
                if (scan.positives > 0) {
                    score -= scan.positives * 20;
                }
            });
        }
        
        return score;
    }
}

module.exports = AttachmentAnalysisService;
