class URLExtractionService {
    constructor() {
        this.urlPatterns = {
            http: /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi,
            ip: /https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            shorteners: [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
                'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'rebrand.ly',
                'short.link', 'cutt.ly', 'tiny.cc', 'rb.gy', 'clk.im'
            ],
            suspiciousTlds: [
                '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.biz', '.info',
                '.work', '.click', '.download', '.loan', '.win', '.review',
                '.top', '.site', '.online', '.tech', '.store', '.shop'
            ],
            suspiciousDomains: [
                'pastebin.com', 'gofile.io', 'anonfiles.com', 'mega.nz',
                'mediafire.com', 'dropbox.com', 'drive.google.com'
            ]
        };
    }

    extractURLs(content) {
        const textContent = Buffer.isBuffer(content) ? content.toString('utf8', 0, Math.min(content.length, 50000)) : content;
        
        const urls = textContent.match(this.urlPatterns.http) || [];
        const uniqueURLs = [...new Set(urls)];
        
        const analysis = {
            total: uniqueURLs.length,
            extracted: [],
            categories: {
                ipBased: [],
                shorteners: [],
                suspiciousDomains: [],
                suspiciousTlds: [],
                legitimate: []
            },
            flagged: []
        };
        
        uniqueURLs.forEach(url => {
            const urlAnalysis = this.analyzeSingleURL(url);
            analysis.extracted.push(urlAnalysis);
            
            // Categorize URLs
            if (urlAnalysis.isIPBased) {
                analysis.categories.ipBased.push(urlAnalysis);
            } else if (urlAnalysis.isShortener) {
                analysis.categories.shorteners.push(urlAnalysis);
            } else if (urlAnalysis.isSuspiciousDomain) {
                analysis.categories.suspiciousDomains.push(urlAnalysis);
            } else if (urlAnalysis.hasSuspiciousTld) {
                analysis.categories.suspiciousTlds.push(urlAnalysis);
            } else {
                analysis.categories.legitimate.push(urlAnalysis);
            }
            
            // Flag suspicious URLs
            if (urlAnalysis.isFlagged) {
                analysis.flagged.push(urlAnalysis);
            }
        });
        
        return analysis;
    }
    
    analyzeSingleURL(url) {
        const analysis = {
            url: url.length > 200 ? url.substring(0, 200) + '...' : url,
            isIPBased: false,
            isShortener: false,
            isSuspiciousDomain: false,
            hasSuspiciousTld: false,
            isFlagged: false,
            risk: 'low',
            reasons: [],
            domain: null,
            protocol: null
        };
        
        try {
            const urlObj = new URL(url);
            analysis.domain = urlObj.hostname.toLowerCase();
            analysis.protocol = urlObj.protocol;
            
            // Check for IP-based URLs
            const ipMatch = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (ipMatch) {
                analysis.isIPBased = true;
                analysis.isFlagged = true;
                analysis.risk = 'high';
                analysis.reasons.push('IP-based URL');
            }
            
            // Check for URL shorteners
            if (!analysis.isIPBased) {
                for (const shortener of this.urlPatterns.shorteners) {
                    if (analysis.domain.includes(shortener)) {
                        analysis.isShortener = true;
                        analysis.isFlagged = true;
                        if (analysis.risk === 'low') analysis.risk = 'medium';
                        analysis.reasons.push('URL shortener service');
                        break;
                    }
                }
            }
            
            // Check for suspicious domains
            if (!analysis.isIPBased && !analysis.isShortener) {
                for (const suspiciousDomain of this.urlPatterns.suspiciousDomains) {
                    if (analysis.domain.includes(suspiciousDomain)) {
                        analysis.isSuspiciousDomain = true;
                        analysis.isFlagged = true;
                        if (analysis.risk === 'low') analysis.risk = 'medium';
                        analysis.reasons.push(`Suspicious domain: ${suspiciousDomain}`);
                        break;
                    }
                }
            }
            
            // Check for suspicious TLDs
            if (!analysis.isIPBased && !analysis.isShortener && !analysis.isSuspiciousDomain) {
                for (const tld of this.urlPatterns.suspiciousTlds) {
                    if (analysis.domain.endsWith(tld)) {
                        analysis.hasSuspiciousTld = true;
                        analysis.isFlagged = true;
                        if (analysis.risk === 'low') analysis.risk = 'medium';
                        analysis.reasons.push(`Suspicious TLD: ${tld}`);
                        break;
                    }
                }
            }
            
            // Additional checks
            if (!analysis.isFlagged) {
                // Check for unusually long domains
                if (analysis.domain.length > 50) {
                    analysis.isFlagged = true;
                    analysis.risk = 'medium';
                    analysis.reasons.push('Unusually long domain name');
                }
                
                // Check for lots of subdomains
                const subdomainCount = analysis.domain.split('.').length - 2;
                if (subdomainCount > 3) {
                    analysis.isFlagged = true;
                    analysis.risk = 'medium';
                    analysis.reasons.push('Multiple subdomains');
                }
                
                // Check for suspicious patterns in domain
                if (this.hasSuspiciousDomainPatterns(analysis.domain)) {
                    analysis.isFlagged = true;
                    analysis.risk = 'medium';
                    analysis.reasons.push('Suspicious domain pattern');
                }
            }
            
        } catch (error) {
            analysis.isFlagged = true;
            analysis.risk = 'high';
            analysis.reasons.push('Malformed URL');
        }
        
        return analysis;
    }
    
    hasSuspiciousDomainPatterns(domain) {
        const patterns = [
            /[0-9]{3,}/, // Lots of numbers
            /[^a-zA-Z0-9.-]{2,}/, // Multiple special characters
            /(.)\1{3,}/, // Repeated characters
            /paypal-secure|secure-paypal|apple-id|microsoft-security/gi, // Brand impersonation
            /[a-z0-9]{20,}/gi // Long random strings
        ];
        
        return patterns.some(pattern => pattern.test(domain));
    }
    
    generateURLSummary(urlAnalysis) {
        const summary = {
            total: urlAnalysis.total,
            flagged: urlAnalysis.flagged.length,
            ipBased: urlAnalysis.categories.ipBased.length,
            shorteners: urlAnalysis.categories.shorteners.length,
            suspiciousDomains: urlAnalysis.categories.suspiciousDomains.length,
            suspiciousTlds: urlAnalysis.categories.suspiciousTlds.length,
            legitimate: urlAnalysis.categories.legitimate.length,
            risk: urlAnalysis.flagged.length > 0 ? 'high' : 'low'
        };
        
        if (urlAnalysis.flagged.length > 0) {
            summary.highRiskURLs = urlAnalysis.flagged.filter(url => url.risk === 'high').length;
            summary.mediumRiskURLs = urlAnalysis.flagged.filter(url => url.risk === 'medium').length;
        }
        
        return summary;
    }
}

module.exports = URLExtractionService;
