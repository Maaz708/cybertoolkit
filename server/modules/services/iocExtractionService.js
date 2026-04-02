const fs = require('fs');
const path = require('path');

class IOCExtractionService {
    constructor() {
        this.signaturesData = null;
        this.loadSignaturesData();
        this.initializePatterns();
    }

    loadSignaturesData() {
        try {
            const signaturesPath = path.join(__dirname, '../signatures.json');
            if (fs.existsSync(signaturesPath)) {
                this.signaturesData = JSON.parse(fs.readFileSync(signaturesPath, 'utf8'));
            }
        } catch (error) {
            console.error('Error loading signatures.json:', error.message);
        }
    }

    initializePatterns() {
        this.urlPatterns = {
            http: /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi,
            ip: /https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/[^\s<>"{}|\\^`[\]]*)?/gi,
            domain: /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:\/[^\s<>"{}|\\^`[\]]*)?/gi
        };

        // Load suspicious domains and IPs from signatures.json
        this.suspiciousDomains = this.getSuspiciousDomains();
        this.suspiciousIPs = this.getSuspiciousIPs();
        this.maliciousURLs = this.getMaliciousURLs();

        // Default suspicious TLDs
        this.suspiciousTlds = [
            '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.biz', '.info',
            '.work', '.click', '.download', '.loan', '.win', '.review',
            '.top', '.site', '.online', '.tech', '.store', '.shop'
        ];

        this.ipRanges = {
            private: [
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
                /^192\.168\./,
                /^127\./,
                /^169\.254\./
            ],
            suspicious: [
                /^0\./,
                /^255\./,
                /^22[4-9]\./,
                /^23[0-9]\./
            ]
        };
    }

    getSuspiciousDomains() {
        const domains = [
            'pastebin.com', 'gofile.io', 'anonfiles.com', 'mega.nz',
            'mediafire.com', 'dropbox.com', 'drive.google.com',
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'discord.com', 'telegram.org', 'webhook.site'
        ];

        // Add domains from signatures.json
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.domains) {
            domains.push(...this.signaturesData.iocs.domains);
        }

        return [...new Set(domains)];
    }

    getSuspiciousIPs() {
        const ips = [];

        // Add IPs from signatures.json
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.ips) {
            ips.push(...this.signaturesData.iocs.ips);
        }

        return ips;
    }

    getMaliciousURLs() {
        const urls = [];

        // Add URLs from signatures.json
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.urls) {
            urls.push(...this.signaturesData.iocs.urls);
        }

        return urls;
    }

    extractIOCs(buffer, filename = '') {
        const iocs = {
            urls: [],
            domains: [],
            ipAddresses: [],
            filePaths: [],
            registryKeys: [],
            emailAddresses: [],
            hashes: [],
            summary: {
                total: 0,
                byType: {},
                riskLevel: 'low'
            },
            riskScore: 0,
            knownMalicious: {
                domains: [],
                ips: [],
                urls: []
            }
        };

        // Convert buffer to text for analysis
        const textContent = this.extractTextContent(buffer);

        // Extract URLs
        iocs.urls = this.extractURLs(textContent);

        // Extract domains
        iocs.domains = this.extractDomains(textContent);

        // Extract IP addresses
        iocs.ipAddresses = this.extractIPAddresses(textContent);

        // Extract file paths
        iocs.filePaths = this.extractFilePaths(textContent);

        // Extract registry keys
        iocs.registryKeys = this.extractRegistryKeys(textContent);

        // Extract email addresses
        iocs.emailAddresses = this.extractEmailAddresses(textContent);

        // Extract potential file hashes
        iocs.hashes = this.extractHashes(textContent);

        // Check against known malicious IOCs from signatures.json
        iocs.knownMalicious = this.checkAgainstMaliciousIOCs(iocs);

        // Calculate summary and risk
        iocs.summary = this.calculateIOCSummary(iocs);
        iocs.riskScore = this.calculateIOCRiskScore(iocs);

        return iocs;
    }

    checkAgainstMaliciousIOCs(iocs) {
        const malicious = {
            domains: [],
            ips: [],
            urls: []
        };

        // Check domains against known malicious domains
        iocs.domains.forEach(domain => {
            if (this.suspiciousDomains.some(maliciousDomain => 
                domain.domain.toLowerCase().includes(maliciousDomain.toLowerCase()))) {
                malicious.domains.push({
                    domain: domain.domain,
                    source: 'signatures.json',
                    risk: 'high'
                });
            }
        });

        // Check IPs against known malicious IPs
        iocs.ipAddresses.forEach(ip => {
            if (this.suspiciousIPs.some(maliciousIP => ip.ip === maliciousIP)) {
                malicious.ips.push({
                    ip: ip.ip,
                    source: 'signatures.json',
                    risk: 'high'
                });
            }
        });

        // Check URLs against known malicious URLs
        iocs.urls.forEach(url => {
            if (this.maliciousURLs.some(maliciousURL => 
                url.url.includes(maliciousURL) || maliciousURL.includes(url.url))) {
                malicious.urls.push({
                    url: url.url,
                    source: 'signatures.json',
                    risk: 'high'
                });
            }
        });

        return malicious;
    }

    extractTextContent(buffer) {
        // Try different encodings
        const encodings = ['utf8', 'latin1', 'ascii'];
        
        for (const encoding of encodings) {
            try {
                const text = buffer.toString(encoding);
                if (this.isValidText(text)) {
                    return text;
                }
            } catch (error) {
                continue;
            }
        }
        
        // Fallback to latin1
        return buffer.toString('latin1');
    }

    isValidText(text) {
        // Check if text contains mostly printable characters
        let printableChars = 0;
        const sample = text.substring(0, 1000);
        
        for (let i = 0; i < sample.length; i++) {
            const char = sample.charCodeAt(i);
            if ((char >= 32 && char <= 126) || char === 9 || char === 10 || char === 13) {
                printableChars++;
            }
        }
        
        return (printableChars / sample.length) > 0.95;
    }

    extractURLs(textContent) {
        const urls = [];
        const matches = textContent.match(this.urlPatterns.http) || [];
        
        const uniqueURLs = [...new Set(matches)];
        
        uniqueURLs.forEach(url => {
            const urlAnalysis = this.analyzeURL(url);
            urls.push(urlAnalysis);
        });
        
        return urls;
    }

    analyzeURL(url) {
        const analysis = {
            url: url.length > 200 ? url.substring(0, 200) + '...' : url,
            isIPBased: false,
            isShortener: false,
            isSuspiciousDomain: false,
            hasSuspiciousTld: false,
            risk: 'low',
            reasons: [],
            domain: null,
            protocol: null,
            port: null
        };

        try {
            const urlObj = new URL(url);
            analysis.domain = urlObj.hostname.toLowerCase();
            analysis.protocol = urlObj.protocol;
            analysis.port = urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80');

            // Check for IP-based URLs
            const ipMatch = url.match(/https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (ipMatch) {
                analysis.isIPBased = true;
                analysis.risk = 'high';
                analysis.reasons.push('IP-based URL');
            }

            // Check for URL shorteners
            if (this.suspiciousDomains.some(domain => analysis.domain.includes(domain))) {
                analysis.isShortener = true;
                analysis.risk = 'medium';
                analysis.reasons.push('URL shortener service');
            }

            // Check for suspicious domains
            if (this.suspiciousDomains.some(domain => analysis.domain.includes(domain))) {
                analysis.isSuspiciousDomain = true;
                analysis.risk = 'high';
                analysis.reasons.push('Suspicious domain');
            }

            // Check for suspicious TLDs
            if (this.suspiciousTlds.some(tld => analysis.domain.endsWith(tld))) {
                analysis.hasSuspiciousTld = true;
                if (analysis.risk === 'low') analysis.risk = 'medium';
                analysis.reasons.push(`Suspicious TLD: ${this.suspiciousTlds.find(tld => analysis.domain.endsWith(tld))}`);
            }

            // Additional checks
            if (analysis.domain.length > 50) {
                analysis.risk = 'medium';
                analysis.reasons.push('Unusually long domain name');
            }

            // Check for non-standard ports
            if (analysis.port !== '80' && analysis.port !== '443' && analysis.port !== '8080') {
                analysis.risk = 'medium';
                analysis.reasons.push(`Non-standard port: ${analysis.port}`);
            }

        } catch (error) {
            analysis.risk = 'high';
            analysis.reasons.push('Malformed URL');
        }

        return analysis;
    }

    extractDomains(textContent) {
        const domains = [];
        const matches = textContent.match(this.urlPatterns.domain) || [];
        
        const uniqueDomains = [...new Set(matches.map(match => {
            try {
                const url = new URL(match);
                return url.hostname.toLowerCase();
            } catch (error) {
                return null;
            }
        }).filter(domain => domain !== null))];
        
        uniqueDomains.forEach(domain => {
            const domainAnalysis = this.analyzeDomain(domain);
            domains.push(domainAnalysis);
        });
        
        return domains;
    }

    analyzeDomain(domain) {
        const analysis = {
            domain: domain,
            risk: 'low',
            reasons: [],
            subdomainCount: domain.split('.').length - 2,
            hasNumbers: /\d/.test(domain),
            hasSuspiciousPattern: false
        };

        // Check for suspicious TLDs
        if (this.suspiciousTlds.some(tld => domain.endsWith(tld))) {
            analysis.risk = 'medium';
            analysis.reasons.push('Suspicious TLD');
        }

        // Check for suspicious domains
        if (this.suspiciousDomains.some(suspicious => domain.includes(suspicious))) {
            analysis.risk = 'high';
            analysis.reasons.push('Suspicious domain');
        }

        // Check for DGA patterns
        if (this.isDGA(domain)) {
            analysis.hasSuspiciousPattern = true;
            analysis.risk = 'high';
            analysis.reasons.push('Potential DGA (Domain Generation Algorithm)');
        }

        // Check for too many subdomains
        if (analysis.subdomainCount > 4) {
            analysis.risk = 'medium';
            analysis.reasons.push('Multiple subdomains');
        }

        return analysis;
    }

    isDGA(domain) {
        // Simple DGA detection
        const baseDomain = domain.split('.')[0];
        
        // Check for random-looking strings
        if (baseDomain.length > 10 && /[0-9]{3,}/.test(baseDomain)) {
            return true;
        }
        
        // Check for high entropy
        const entropy = this.calculateEntropy(baseDomain);
        if (entropy > 4.5) {
            return true;
        }
        
        return false;
    }

    extractIPAddresses(textContent) {
        const ipAddresses = [];
        const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        const matches = textContent.match(ipPattern) || [];
        
        const uniqueIPs = [...new Set(matches)];
        
        uniqueIPs.forEach(ip => {
            const ipAnalysis = this.analyzeIP(ip);
            ipAddresses.push(ipAnalysis);
        });
        
        return ipAddresses;
    }

    analyzeIP(ip) {
        const analysis = {
            ip: ip,
            risk: 'low',
            reasons: [],
            isPrivate: false,
            isSuspicious: false,
            geoLocation: null
        };

        // Check for private IPs
        if (this.ipRanges.private.some(range => range.test(ip))) {
            analysis.isPrivate = true;
            analysis.risk = 'medium';
            analysis.reasons.push('Private IP address');
        }

        // Check for suspicious IPs
        if (this.ipRanges.suspicious.some(range => range.test(ip))) {
            analysis.isSuspicious = true;
            analysis.risk = 'high';
            analysis.reasons.push('Suspicious IP range');
        }

        // Check for localhost
        if (ip === '127.0.0.1' || ip.startsWith('127.')) {
            analysis.risk = 'medium';
            analysis.reasons.push('Localhost address');
        }

        // Placeholder for geo-location
        analysis.geoLocation = {
            country: 'Unknown',
            city: 'Unknown',
            provider: 'GeoIP lookup not implemented'
        };

        return analysis;
    }

    extractFilePaths(textContent) {
        const filePaths = [];
        
        // Windows paths
        const windowsPathPattern = /[A-Za-z]:\\[^"<>|*\s]+/g;
        const windowsMatches = textContent.match(windowsPathPattern) || [];
        
        // Unix/Linux paths
        const unixPathPattern = /\/(?:[^"<>|*\s]+\/)+[^"<>|*\s]+/g;
        const unixMatches = textContent.match(unixPathPattern) || [];
        
        const allPaths = [...new Set([...windowsMatches, ...unixMatches])];
        
        allPaths.forEach(path => {
            const pathAnalysis = this.analyzePath(path);
            filePaths.push(pathAnalysis);
        });
        
        return filePaths;
    }

    analyzePath(path) {
        const analysis = {
            path: path,
            type: path.includes('\\') ? 'windows' : 'unix',
            risk: 'low',
            reasons: [],
            suspiciousLocations: []
        };

        // Check for suspicious locations
        const suspiciousWindowsPaths = [
            '\\Windows\\System32\\',
            '\\Windows\\Temp\\',
            '\\AppData\\Local\\Temp\\',
            '\\ProgramData\\',
            '\\Users\\Public\\'
        ];

        const suspiciousUnixPaths = [
            '/tmp/',
            '/var/tmp/',
            '/dev/shm/',
            '/etc/',
            '/root/',
            '/home/'
        ];

        const suspiciousPaths = path.includes('\\') ? suspiciousWindowsPaths : suspiciousUnixPaths;
        
        suspiciousPaths.forEach(suspiciousPath => {
            if (path.toLowerCase().includes(suspiciousPath.toLowerCase())) {
                analysis.suspiciousLocations.push(suspiciousPath);
                analysis.risk = 'medium';
                analysis.reasons.push(`Suspicious location: ${suspiciousPath}`);
            }
        });

        // Check for system directories
        if (path.toLowerCase().includes('system32') || path.toLowerCase().includes('system')) {
            analysis.risk = 'high';
            analysis.reasons.push('System directory access');
        }

        return analysis;
    }

    extractRegistryKeys(textContent) {
        const registryKeys = [];
        
        // Windows registry patterns
        const patterns = [
            /HKEY_[A-Z_]+\\[^"'\s\\]+/gi,
            /HK[CLU][A-Z_]*\\[^"'\s\\]+/gi
        ];
        
        patterns.forEach(pattern => {
            const matches = textContent.match(pattern) || [];
            matches.forEach(match => {
                const keyAnalysis = this.analyzeRegistryKey(match);
                registryKeys.push(keyAnalysis);
            });
        });
        
        return registryKeys;
    }

    analyzeRegistryKey(key) {
        const analysis = {
            key: key,
            hive: this.extractRegistryHive(key),
            risk: 'low',
            reasons: [],
            suspiciousKeys: []
        };

        // Check for suspicious registry locations
        const suspiciousKeys = [
            'Run', 'RunOnce', 'RunServices', 'RunServicesOnce',
            'Policies', 'System\\CurrentControlSet\\Services',
            'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        ];

        suspiciousKeys.forEach(suspiciousKey => {
            if (key.toLowerCase().includes(suspiciousKey.toLowerCase())) {
                analysis.suspiciousKeys.push(suspiciousKey);
                analysis.risk = 'high';
                analysis.reasons.push(`Suspicious registry key: ${suspiciousKey}`);
            }
        });

        return analysis;
    }

    extractRegistryHive(key) {
        const match = key.match(/^(HKEY_[A-Z_]+|HK[CLU][A-Z_]*)/);
        return match ? match[1] : 'Unknown';
    }

    extractEmailAddresses(textContent) {
        const emailAddresses = [];
        const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
        const matches = textContent.match(emailPattern) || [];
        
        const uniqueEmails = [...new Set(matches)];
        
        uniqueEmails.forEach(email => {
            const emailAnalysis = this.analyzeEmail(email);
            emailAddresses.push(emailAnalysis);
        });
        
        return emailAddresses;
    }

    analyzeEmail(email) {
        const analysis = {
            email: email,
            domain: email.split('@')[1].toLowerCase(),
            risk: 'low',
            reasons: [],
            isSuspiciousDomain: false
        };

        // Check for suspicious domains
        if (this.suspiciousDomains.some(domain => analysis.domain.includes(domain))) {
            analysis.isSuspiciousDomain = true;
            analysis.risk = 'medium';
            analysis.reasons.push('Suspicious email domain');
        }

        // Check for disposable email patterns
        const disposablePatterns = [
            '10minutemail', 'guerrillamail', 'mailinator', 'tempmail',
            'throwaway', 'disposable', 'temporary'
        ];

        if (disposablePatterns.some(pattern => analysis.domain.includes(pattern))) {
            analysis.risk = 'high';
            analysis.reasons.push('Disposable email service');
        }

        return analysis;
    }

    extractHashes(textContent) {
        const hashes = [];
        
        // MD5 pattern
        const md5Pattern = /\b[a-fA-F0-9]{32}\b/g;
        const md5Matches = textContent.match(md5Pattern) || [];
        
        // SHA1 pattern
        const sha1Pattern = /\b[a-fA-F0-9]{40}\b/g;
        const sha1Matches = textContent.match(sha1Pattern) || [];
        
        // SHA256 pattern
        const sha256Pattern = /\b[a-fA-F0-9]{64}\b/g;
        const sha256Matches = textContent.match(sha256Pattern) || [];
        
        // Add unique hashes
        const uniqueHashes = [
            ...new Set(md5Matches.map(h => ({ type: 'MD5', hash: h }))),
            ...new Set(sha1Matches.map(h => ({ type: 'SHA1', hash: h }))),
            ...new Set(sha256Matches.map(h => ({ type: 'SHA256', hash: h })))
        ];
        
        uniqueHashes.forEach(hashInfo => {
            hashes.push({
                type: hashInfo.type,
                hash: hashInfo.hash,
                risk: 'medium',
                reason: 'Potential file hash found'
            });
        });
        
        return hashes;
    }

    calculateIOCSummary(iocs) {
        const summary = {
            total: 0,
            byType: {},
            riskLevel: 'low'
        };

        // Count by type
        summary.byType.urls = iocs.urls.length;
        summary.byType.domains = iocs.domains.length;
        summary.byType.ipAddresses = iocs.ipAddresses.length;
        summary.byType.filePaths = iocs.filePaths.length;
        summary.byType.registryKeys = iocs.registryKeys.length;
        summary.byType.emailAddresses = iocs.emailAddresses.length;
        summary.byType.hashes = iocs.hashes.length;

        summary.total = Object.values(summary.byType).reduce((a, b) => a + b, 0);

        // Determine risk level
        const highRiskCount = iocs.urls.filter(u => u.risk === 'high').length +
                             iocs.domains.filter(d => d.risk === 'high').length +
                             iocs.ipAddresses.filter(ip => ip.risk === 'high').length;

        const mediumRiskCount = iocs.urls.filter(u => u.risk === 'medium').length +
                               iocs.domains.filter(d => d.risk === 'medium').length +
                               iocs.ipAddresses.filter(ip => ip.risk === 'medium').length;

        if (highRiskCount > 0) {
            summary.riskLevel = 'high';
        } else if (mediumRiskCount > 2) {
            summary.riskLevel = 'medium';
        } else if (mediumRiskCount > 0) {
            summary.riskLevel = 'low';
        }

        return summary;
    }

    calculateIOCRiskScore(iocs) {
        let score = 0;

        // Score based on risk level of IOCs
        iocs.urls.forEach(url => {
            if (url.risk === 'high') score += 10;
            else if (url.risk === 'medium') score += 5;
            else if (url.risk === 'low') score += 2;
        });

        iocs.domains.forEach(domain => {
            if (domain.risk === 'high') score += 8;
            else if (domain.risk === 'medium') score += 4;
            else if (domain.risk === 'low') score += 2;
        });

        iocs.ipAddresses.forEach(ip => {
            if (ip.risk === 'high') score += 15;
            else if (ip.risk === 'medium') score += 8;
            else if (ip.risk === 'low') score += 3;
        });

        iocs.filePaths.forEach(path => {
            if (path.risk === 'high') score += 5;
            else if (path.risk === 'medium') score += 3;
        });

        iocs.registryKeys.forEach(key => {
            if (key.risk === 'high') score += 12;
            else if (key.risk === 'medium') score += 6;
        });

        iocs.emailAddresses.forEach(email => {
            if (email.risk === 'high') score += 4;
            else if (email.risk === 'medium') score += 2;
        });

        iocs.hashes.forEach(hash => {
            score += 3; // Hashes are moderately suspicious
        });

        return Math.min(score, 100); // Cap at 100
    }

    calculateEntropy(str) {
        const entropy = [];
        const strLength = str.length;

        for (let i = 0; i < 256; i++) {
            const char = str.charCodeAt(i);
            const probability = (str.split(char).length - 1) / strLength;
            if (probability > 0) {
                entropy.push(-probability * Math.log2(probability));
            }
        }

        return entropy.reduce((a, b) => a + b, 0);
    }

    // Export IOCs in various formats
    exportIOCs(iocs, format = 'json') {
        switch (format.toLowerCase()) {
            case 'json':
                return JSON.stringify(iocs, null, 2);
            case 'csv':
                return this.exportToCSV(iocs);
            case 'stix':
                return this.exportToSTIX(iocs);
            default:
                return JSON.stringify(iocs, null, 2);
        }
    }

    exportToCSV(iocs) {
        const csvLines = ['Type,Value,Risk,Details'];
        
        iocs.urls.forEach(url => {
            csvLines.push(`URL,"${url.url}",${url.risk},"${url.reasons.join('; ')}"`);
        });
        
        iocs.domains.forEach(domain => {
            csvLines.push(`Domain,"${domain.domain}",${domain.risk},"${domain.reasons.join('; ')}"`);
        });
        
        iocs.ipAddresses.forEach(ip => {
            csvLines.push(`IP,"${ip.ip}",${ip.risk},"${ip.reasons.join('; ')}"`);
        });
        
        return csvLines.join('\n');
    }

    exportToSTIX(iocs) {
        // Placeholder for STIX format export
        return {
            type: 'bundle',
            id: 'bundle--' + require('crypto').randomUUID(),
            objects: [],
            message: 'STIX export not fully implemented'
        };
    }
}

module.exports = IOCExtractionService;
