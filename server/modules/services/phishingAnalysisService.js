class PhishingAnalysisService {
    constructor() {
        this.phishingKeywords = [
            'urgent', 'verify account', 'password', 'bank', 'otp', 'click here',
            'suspend', 'limited', 'expire', 'security', 'update payment',
            'confirm identity', 'act now', 'immediate action', 'account locked'
        ];
        
        this.urgentPatterns = [
            /urgent/i,
            /immediate/i,
            /action required/i,
            /account suspended/i,
            /limited time/i,
            /expire soon/i
        ];
        
        this.brandImpersonationPatterns = [
            /paypal/i,
            /apple/i,
            /microsoft/i,
            /google/i,
            /amazon/i,
            /facebook/i,
            /instagram/i,
            /linkedin/i,
            /twitter/i,
            /netflix/i,
            /bank of america/i,
            /chase/i,
            /wells fargo/i
        ];
    }

    analyzePhishing(parsed) {
        const phishingAnalysis = {
            score: 0,
            keywordsFound: [],
            suspiciousPatterns: [],
            brandImpersonation: [],
            urgencyIndicators: []
        };
        
        const content = ((parsed.text || '') + ' ' + (parsed.html || '')).toLowerCase();
        const subject = (parsed.subject || '').toLowerCase();
        const fullContent = subject + ' ' + content;
        
        // Check for phishing keywords
        this.phishingKeywords.forEach(keyword => {
            if (content.includes(keyword) || subject.includes(keyword)) {
                phishingAnalysis.keywordsFound.push(keyword);
                phishingAnalysis.score += 10;
            }
        });
        
        // Check for urgent language in subject
        this.urgentPatterns.forEach(pattern => {
            if (subject.match(pattern)) {
                phishingAnalysis.urgencyIndicators.push({
                    type: 'urgent_subject',
                    pattern: pattern.source,
                    details: 'Urgent language in subject line'
                });
                phishingAnalysis.score += 15;
            }
        });
        
        // Check for urgent call-to-action
        if (content.includes('click here') || content.includes('immediately')) {
            phishingAnalysis.suspiciousPatterns.push({
                type: 'urgent_cta',
                details: 'Urgent call-to-action detected'
            });
            phishingAnalysis.score += 10;
        }
        
        // Check for brand impersonation
        this.brandImpersonationPatterns.forEach(brand => {
            if (content.match(brand) || subject.match(brand)) {
                phishingAnalysis.brandImpersonation.push({
                    brand: brand.source,
                    context: this.findBrandContext(fullContent, brand.source)
                });
                phishingAnalysis.score += 20;
            }
        });
        
        // Check for domain mismatches
        const senderDomain = parsed.from?.value?.[0]?.address?.split('@')[1];
        if (senderDomain) {
            const domainsInContent = content.match(/\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/g) || [];
            const uniqueDomains = [...new Set(domainsInContent)];
            
            if (uniqueDomains.length > 5 && !uniqueDomains.includes(senderDomain.toLowerCase())) {
                phishingAnalysis.suspiciousPatterns.push({
                    type: 'multiple_domains',
                    details: 'Multiple domains mentioned, none match sender'
                });
                phishingAnalysis.score += 20;
            }
        }
        
        // Check for suspicious sender patterns
        const senderAddress = parsed.from?.value?.[0]?.address;
        if (senderAddress) {
            if (this.hasSuspiciousSenderPattern(senderAddress)) {
                phishingAnalysis.suspiciousPatterns.push({
                    type: 'suspicious_sender',
                    details: 'Suspicious sender email pattern detected'
                });
                phishingAnalysis.score += 15;
            }
        }
        
        // Check for attachment-based phishing
        if (parsed.attachments && parsed.attachments.length > 0) {
            const suspiciousAttachments = parsed.attachments.filter(att => 
                this.isSuspiciousAttachment(att.filename)
            );
            
            if (suspiciousAttachments.length > 0) {
                phishingAnalysis.suspiciousPatterns.push({
                    type: 'suspicious_attachments',
                    details: `Found ${suspiciousAttachments.length} suspicious attachments`
                });
                phishingAnalysis.score += suspiciousAttachments.length * 10;
            }
        }
        
        return phishingAnalysis;
    }

    findBrandContext(content, brand) {
        const regex = new RegExp(`(.{0,50})${brand}(.{0,50})`, 'gi');
        const match = content.match(regex);
        return match ? match[0] : '';
    }

    hasSuspiciousSenderPattern(email) {
        const suspiciousPatterns = [
            /^[0-9]+@/, // Numbers at start
            /noreply|no-reply/i, // Common noreply patterns
            /[0-9]{4,}@/, // Lots of numbers
            /[^a-zA-Z0-9._-]/, // Special characters
            /(.)\1{3,}/ // Repeated characters
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(email));
    }

    isSuspiciousAttachment(filename) {
        if (!filename) return false;
        
        const suspiciousPatterns = [
            /invoice|receipt|statement|payment/i,
            /secure|verify|confirm/i,
            /urgent|immediate/i,
            /\.exe$|\.scr$|\.bat$|\.js$/i,
            /\.zip$|\.rar$|\.7z$/i
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(filename));
    }

    getPhishingScore(phishingAnalysis) {
        return -phishingAnalysis.score;
    }
}

module.exports = PhishingAnalysisService;
