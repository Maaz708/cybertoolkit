class HeaderAnalysisService {
    constructor() {
        this.privateIpRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./,
            /^127\./,
            /^169\.254\./,
            /^::1$/,
            /^fc00:/,
            /^fe80:/
        ];
    }

    analyzeHeaders(parsed) {
        // Handle different header formats
        let receivedHeaders = [];
        if (parsed.headers && parsed.headers.getAll) {
            receivedHeaders = parsed.headers.getAll('received') || [];
        } else if (parsed.headers && parsed.headers.received) {
            receivedHeaders = Array.isArray(parsed.headers.received) ? parsed.headers.received : [parsed.headers.received];
        }
        
        const analysis = {
            receivedHeaders: [],
            anomalies: [],
            senderIp: null,
            totalHops: receivedHeaders.length
        };
        
        receivedHeaders.forEach((header, index) => {
            const ipMatch = header.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g);
            if (ipMatch) {
                ipMatch.forEach(ip => {
                    if (this.isPrivateIp(ip)) {
                        analysis.anomalies.push({
                            type: 'private_ip_in_received',
                            details: `Private IP ${ip} found in received header ${index + 1}`,
                            severity: 'medium'
                        });
                    } else if (index === 0) {
                        analysis.senderIp = ip;
                    }
                });
            }
            
            analysis.receivedHeaders.push({
                index: index + 1,
                content: header.substring(0, 200) + (header.length > 200 ? '...' : '')
            });
        });
        
        if (parsed.from && parsed.from.value && parsed.from.value.length > 0) {
            const fromDomain = parsed.from.value[0].address.split('@')[1];
            
            for (const header of receivedHeaders) {
                const headerLower = header.toLowerCase();
                if (headerLower.includes('by') && !headerLower.includes(fromDomain.toLowerCase())) {
                    analysis.anomalies.push({
                        type: 'domain_mismatch',
                        details: `Domain mismatch in received headers`,
                        severity: 'high'
                    });
                    break;
                }
            }
        }
        
        if (analysis.totalHops > 10) {
            analysis.anomalies.push({
                type: 'excessive_hops',
                details: `Email traveled through ${analysis.totalHops} hops - unusual routing`,
                severity: 'medium'
            });
        }
        
        return analysis;
    }

    getHeaderScore(headerAnalysis) {
        let score = 0;
        score -= headerAnalysis.anomalies.length * 10;
        return score;
    }

    isPrivateIp(ip) {
        return this.privateIpRanges.some(range => range.test(ip));
    }
}

module.exports = HeaderAnalysisService;
