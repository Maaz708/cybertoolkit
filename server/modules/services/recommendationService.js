class RecommendationService {
    generateRecommendations(analysis) {
        const recommendations = [];
        
        // Authentication recommendations
        if (analysis.authentication.spf.status !== 'pass') {
            recommendations.push({
                priority: 'high',
                title: 'SPF Authentication Failed',
                details: 'Sender could not be verified. Verify sender identity through alternative means before trusting this email.'
            });
        }
        
        if (analysis.authentication.dkim.status !== 'pass') {
            recommendations.push({
                priority: 'medium',
                title: 'DKIM Signature Issues',
                details: 'Email integrity could not be verified. The message may have been tampered with.'
            });
        }
        
        if (analysis.authentication.dmarc.status !== 'pass') {
            recommendations.push({
                priority: 'medium',
                title: 'DMARC Policy Not Satisfied',
                details: 'Domain authentication policies were not met. This email may be spoofed.'
            });
        }
        
        // Link recommendations
        if (analysis.links.suspiciousLinks.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Suspicious Links Detected',
                details: `Found ${analysis.links.suspiciousLinks.length} suspicious links. Do not click without verification.`
            });
        }

        // VirusTotal link recommendations
        if (analysis.links.virusTotalScans) {
            const maliciousLinks = analysis.links.virusTotalScans.filter(scan => scan.positives > 0);
            if (maliciousLinks.length > 0) {
                recommendations.push({
                    priority: 'critical',
                    title: 'Malicious Links Detected by VirusTotal',
                    details: `VirusTotal detected threats in ${maliciousLinks.length} links. These are confirmed malicious URLs.`
                });
            }
        }
        
        // Attachment recommendations
        if (analysis.attachments.dangerousAttachments.length > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Dangerous Attachments Found',
                details: `Found ${analysis.attachments.dangerousAttachments.length} dangerous file types. Do not open without scanning.`
            });
        }

        // VirusTotal attachment recommendations
        if (analysis.attachments.virusTotalScans) {
            const maliciousAttachments = analysis.attachments.virusTotalScans.filter(scan => scan.positives > 0);
            if (maliciousAttachments.length > 0) {
                recommendations.push({
                    priority: 'critical',
                    title: 'Malicious Attachments Detected by VirusTotal',
                    details: `VirusTotal detected malware in ${maliciousAttachments.length} attachments. These files are confirmed malicious.`
                });
            }
        }
        
        // Phishing recommendations
        if (analysis.phishingAnalysis.keywordsFound.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Phishing Indicators Detected',
                details: 'Email contains phishing keywords and patterns. Verify legitimacy before taking any action.'
            });
        }

        // Brand impersonation recommendations
        if (analysis.phishingAnalysis.brandImpersonation.length > 0) {
            const brands = analysis.phishingAnalysis.brandImpersonation.map(imp => imp.brand).join(', ');
            recommendations.push({
                priority: 'critical',
                title: 'Brand Impersonation Detected',
                details: `Email impersonates known brands: ${brands}. This is a strong indicator of phishing.`
            });
        }
        
        // Header anomaly recommendations
        if (analysis.headerAnalysis.anomalies.length > 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Header Anomalies Present',
                details: 'Email routing shows unusual patterns. This may indicate spoofing or relay abuse.'
            });
        }
        
        // Urgency recommendations
        if (analysis.phishingAnalysis.urgencyIndicators.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Urgency Tactics Detected',
                details: 'Sender uses urgency to pressure immediate action. Take time to verify legitimacy.'
            });
        }
        
        // General safety recommendations
        if (recommendations.length === 0) {
            recommendations.push({
                priority: 'low',
                title: 'Email Appears Safe',
                details: 'No immediate security threats detected. Always remain vigilant with unexpected emails.'
            });
        }

        // Add general security advice for high-risk emails
        if (analysis.summary.riskScore < 60) {
            recommendations.push({
                priority: 'critical',
                title: 'High Risk Email - Immediate Action Required',
                details: 'This email shows multiple security threats. Do not click any links, open attachments, or reply. Report as phishing and delete immediately.'
            });
        }
        
        return recommendations;
    }
}

module.exports = RecommendationService;
