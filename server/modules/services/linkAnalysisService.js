class LinkAnalysisService {
    constructor(virusTotalService = null) {
        this.virusTotalService = virusTotalService;
        this.urlShorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'rebrand.ly'
        ];
        
        this.suspiciousTlds = [
            '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.biz', '.info',
            '.work', '.click', '.download', '.loan', '.win', '.review'
        ];
    }

    async analyzeLinks(parsed) {
        const linkAnalysis = {
            totalLinks: 0,
            suspiciousLinks: [],
            virusTotalScans: [],
            categories: {
                ipBased: 0,
                shorteners: 0,
                suspiciousDomains: 0
            }
        };
        
        const text = parsed.text || '';
        const html = parsed.html || '';
        const content = text + ' ' + html;
        
        const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
        const urls = content.match(urlRegex) || [];
        
        linkAnalysis.totalLinks = urls.length;
        
        // Analyze each URL
        for (const url of urls) {
            const analysis = await this.analyzeSingleUrl(url);
            if (analysis.suspicious) {
                linkAnalysis.suspiciousLinks.push({
                    url: url.length > 100 ? url.substring(0, 100) + '...' : url,
                    reason: analysis.reason,
                    category: analysis.category
                });
            }
            
            if (analysis.category) {
                linkAnalysis.categories[analysis.category]++;
            }

            // Perform VirusTotal scan if available
            if (this.virusTotalService && this.virusTotalService.isApiKeyValid()) {
                const vtResult = await this.virusTotalService.analyzeUrl(url);
                if (vtResult.success) {
                    linkAnalysis.virusTotalScans.push({
                        url: url.length > 100 ? url.substring(0, 100) + '...' : url,
                        positives: vtResult.positives,
total: vtResult.total,
                        scanId: vtResult.scanId,
                        permalink: vtResult.permalink,
                        detectedEngines: vtResult.detectedEngines
                    });
                }
            }
        }
        
        return linkAnalysis;
    }

    async analyzeSingleUrl(url) {
        let suspicious = false;
        let reason = '';
        let category = null;
        
        // Check for IP-based URLs
        const ipMatch = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (ipMatch) {
            suspicious = true;
            reason = 'IP-based URL';
            category = 'ipBased';
        }
        
        // Check for URL shorteners
        if (!suspicious) {
            for (const shortener of this.urlShorteners) {
                if (url.toLowerCase().includes(shortener)) {
                    suspicious = true;
                    reason = 'URL shortener service';
                    category = 'shorteners';
                    break;
                }
            }
        }
        
        // Check for suspicious TLDs and domain patterns
        if (!suspicious) {
            try {
                const urlObj = new URL(url);
                const domain = urlObj.hostname.toLowerCase();
                
                for (const tld of this.suspiciousTlds) {
                    if (domain.endsWith(tld)) {
                        suspicious = true;
                        reason = `Suspicious TLD: ${tld}`;
                        category = 'suspiciousDomains';
                        break;
                    }
                }
                
                if (!suspicious && domain.length > 30) {
                    suspicious = true;
                    reason = 'Unusually long domain name';
                    category = 'suspiciousDomains';
                }

                // Check for suspicious domain patterns
                if (!suspicious) {
                    if (this.hasSuspiciousDomainPatterns(domain)) {
                        suspicious = true;
                        reason = 'Suspicious domain pattern detected';
                        category = 'suspiciousDomains';
                    }
                }
            } catch (e) {
                suspicious = true;
                reason = 'Malformed URL';
            }
        }
        
        return { suspicious, reason, category };
    }

    hasSuspiciousDomainPatterns(domain) {
        // Check for common phishing patterns
        const suspiciousPatterns = [
            /[0-9]{3,}/, // Lots of numbers
            /[^a-zA-Z0-9.-]{2,}/, // Multiple special characters
            /(.)\1{3,}/, // Repeated characters
            /paypal-secure|secure-paypal|apple-id|microsoft-security/gi, // Brand impersonation
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(domain));
    }

    getLinkScore(linkAnalysis) {
        let score = 0;
        score -= linkAnalysis.suspiciousLinks.length * 5;
        
        // Additional deductions for VirusTotal detections
        if (linkAnalysis.virusTotalScans) {
            linkAnalysis.virusTotalScans.forEach(scan => {
                if (scan.positives > 0) {
                    score -= scan.positives * 10;
                }
            });
        }
        
        return score;
    }
}

module.exports = LinkAnalysisService;
