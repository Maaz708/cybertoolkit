class ScoringService {
    generateSummary(analysis) {
        let riskScore = 100;
        const deductions = [];
        
        // Authentication deductions
        if (analysis.authentication.spf.status === 'fail') {
            riskScore -= 20;
            deductions.push('SPF authentication failed');
        }
        
        if (analysis.authentication.dkim.status === 'fail') {
            riskScore -= 15;
            deductions.push('DKIM authentication failed');
        }
        
        if (analysis.authentication.dmarc.status === 'fail') {
            riskScore -= 15;
            deductions.push('DMARC authentication failed');
        }
        
        // Header analysis deductions
        riskScore -= analysis.headerAnalysis.anomalies.length * 10;
        if (analysis.headerAnalysis.anomalies.length > 0) {
            deductions.push(`${analysis.headerAnalysis.anomalies.length} header anomalies detected`);
        }
        
        // Link analysis deductions
        riskScore -= analysis.links.suspiciousLinks.length * 5;
        if (analysis.links.suspiciousLinks.length > 0) {
            deductions.push(`${analysis.links.suspiciousLinks.length} suspicious links found`);
        }
        
        // VirusTotal link deductions
        if (analysis.links.virusTotalScans) {
            analysis.links.virusTotalScans.forEach(scan => {
                if (scan.positives > 0) {
                    riskScore -= scan.positives * 10;
                    deductions.push(`VirusTotal detected ${scan.positives}/${scan.total} threats in link: ${scan.url}`);
                }
            });
        }
        
        // Attachment analysis deductions
        riskScore -= analysis.attachments.dangerousAttachments.length * 25;
        if (analysis.attachments.dangerousAttachments.length > 0) {
            deductions.push(`${analysis.attachments.dangerousAttachments.length} dangerous attachments`);
        }
        
        riskScore -= analysis.attachments.suspiciousAttachments.length * 15;
        if (analysis.attachments.suspiciousAttachments.length > 0) {
            deductions.push(`${analysis.attachments.suspiciousAttachments.length} suspicious attachments`);
        }
        
        // VirusTotal attachment deductions
        if (analysis.attachments.virusTotalScans) {
            analysis.attachments.virusTotalScans.forEach(scan => {
                if (scan.positives > 0) {
                    riskScore -= scan.positives * 20;
                    deductions.push(`VirusTotal detected ${scan.positives}/${scan.total} threats in attachment: ${scan.filename}`);
                }
            });
        }
        
        // Phishing analysis deductions
        riskScore -= analysis.phishingAnalysis.score;
        if (analysis.phishingAnalysis.score > 0) {
            deductions.push(`Phishing indicators detected (score: ${analysis.phishingAnalysis.score})`);
        }
        
        riskScore = Math.max(0, Math.min(100, riskScore));
        
        return {
            riskScore: riskScore,
            deductions: deductions,
            totalSuspiciousItems: 
                analysis.headerAnalysis.anomalies.length +
                analysis.links.suspiciousLinks.length +
                analysis.attachments.dangerousAttachments.length +
                analysis.attachments.suspiciousAttachments.length +
                analysis.phishingAnalysis.keywordsFound.length +
                (analysis.links.virusTotalScans?.filter(scan => scan.positives > 0).length || 0) +
                (analysis.attachments.virusTotalScans?.filter(scan => scan.positives > 0).length || 0)
        };
    }
    
    generateVerdict(riskScore) {
        if (riskScore >= 80) {
            return {
                level: 'Safe',
                color: 'green',
                details: 'Email appears safe with minimal security concerns'
            };
        } else if (riskScore >= 60) {
            return {
                level: 'Suspicious',
                color: 'orange',
                details: 'Email contains suspicious elements - exercise caution'
            };
        } else {
            return {
                level: 'High Risk',
                color: 'red',
                details: 'Email shows multiple security threats - high risk of phishing or malware'
            };
        }
    }
}

module.exports = ScoringService;
