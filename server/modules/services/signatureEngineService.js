const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class SignatureEngineService {
    constructor() {
        this.signatureDatabase = new Map();
        this.partialHashIndex = new Map();
        this.fuzzySignatures = [];
        this.signaturesData = null;
        this.initializeSignatureDatabase();
    }

    initializeSignatureDatabase() {
        try {
            // Load signatures from JSON file
            const signaturesPath = path.join(__dirname, '../signatures.json');
            if (fs.existsSync(signaturesPath)) {
                this.signaturesData = JSON.parse(fs.readFileSync(signaturesPath, 'utf8'));
                this.loadSignaturesFromFile();
            } else {
                console.warn('signatures.json not found, using default signatures');
                this.loadDefaultSignatures();
            }
        } catch (error) {
            console.error('Error loading signatures.json:', error.message);
            this.loadDefaultSignatures();
        }

        // Initialize fuzzy signatures from loaded data or defaults
        this.initializeFuzzySignatures();
    }

    loadSignaturesFromFile() {
        if (!this.signaturesData || !this.signaturesData.signatures) {
            return;
        }

        this.signaturesData.signatures.forEach(signature => {
            // Convert old format to new format if needed
            const normalizedSignature = this.normalizeSignature(signature);
            this.addSignature(normalizedSignature);
        });
    }

    normalizeSignature(signature) {
        // Handle both old and new signature formats
        if (signature.algorithm && signature.severity) {
            // New format - return as-is
            return {
                hash: signature.hash,
                algorithm: signature.algorithm || 'md5',
                type: signature.type || 'Unknown',
                description: signature.description || 'No description',
                severity: signature.severity || 'medium',
                category: signature.category || 'unknown',
                family: signature.family || 'Unknown',
                first_seen: signature.first_seen || '2020-01-01',
                last_updated: signature.last_updated || new Date().toISOString().split('T')[0],
                tags: signature.tags || []
            };
        } else {
            // Old format - normalize to new format
            const hash = signature.hash;
            let algorithm = 'md5';
            
            // Detect algorithm based on hash length
            if (hash.length === 64) algorithm = 'sha256';
            else if (hash.length === 40) algorithm = 'sha1';
            else if (hash.length === 32) algorithm = 'md5';

            // Determine severity based on type
            let severity = 'medium';
            if (signature.type.includes('EICAR')) severity = 'low';
            else if (signature.type.includes('Malware') || signature.type.includes('Trojan')) severity = 'high';
            else if (signature.type.includes('Suspicious')) severity = 'medium';

            // Determine category based on type
            let category = 'unknown';
            if (signature.type.includes('Test')) category = 'test';
            else if (signature.type.includes('Malware') || signature.type.includes('Trojan')) category = 'trojan';
            else if (signature.type.includes('PDF')) category = 'dropper';
            else if (signature.type.includes('Archive') || signature.type.includes('ZIP')) category = 'archive';
            else if (signature.type.includes('Suspicious')) category = 'suspicious';

            return {
                hash: hash,
                algorithm: algorithm,
                type: signature.type,
                description: signature.description,
                severity: severity,
                category: category,
                family: this.extractFamily(signature.type),
                first_seen: '2020-01-01',
                last_updated: new Date().toISOString().split('T')[0],
                tags: [category, algorithm]
            };
        }
    }

    extractFamily(type) {
        // Extract family name from type
        if (type.includes('EICAR')) return 'EICAR';
        if (type.includes('Generic')) return 'Generic';
        if (type.includes('PDF')) return 'PDF';
        if (type.includes('Archive') || type.includes('ZIP')) return 'Archive';
        if (type.includes('Suspicious')) return 'Suspicious';
        return 'Unknown';
    }

    loadDefaultSignatures() {
        // Fallback default signatures
        const defaultSignatures = [
            {
                hash: '44d88612fea8a8f36de82e1278abb02f',
                algorithm: 'md5',
                type: 'EICAR Test File',
                description: 'Standard antivirus test file',
                severity: 'low',
                category: 'test',
                family: 'EICAR',
                first_seen: '2003-01-01',
                last_updated: new Date().toISOString().split('T')[0],
                tags: ['test', 'eicar']
            }
        ];

        defaultSignatures.forEach(signature => {
            this.addSignature(signature);
        });
    }

    initializeFuzzySignatures() {
        this.fuzzySignatures = [];

        // Load patterns from signatures.json if available
        if (this.signaturesData && this.signaturesData.patterns) {
            this.signaturesData.patterns.forEach(pattern => {
                try {
                    this.fuzzySignatures.push({
                        pattern: new RegExp(pattern.pattern, 'gi'),
                        name: pattern.type,
                        severity: pattern.severity || 'medium',
                        description: pattern.description,
                        category: pattern.category || 'unknown',
                        tags: pattern.tags || []
                    });
                } catch (error) {
                    console.warn('Invalid regex pattern:', pattern.pattern, error.message);
                }
            });
        } else {
            // Default fuzzy signatures
            this.fuzzySignatures = [
                {
                    pattern: /eval\s*\(/gi,
                    name: 'Dynamic Code Execution',
                    severity: 'medium',
                    description: 'Detects eval() function calls',
                    category: 'script',
                    tags: ['javascript', 'obfuscation']
                },
                {
                    pattern: /powershell.*-enc/i,
                    name: 'PowerShell Encoded Command',
                    severity: 'high',
                    description: 'Detects PowerShell encoded commands',
                    category: 'execution',
                    tags: ['powershell', 'windows']
                },
                {
                    pattern: /cmd\.exe.*\/c/i,
                    name: 'Command Prompt Execution',
                    severity: 'medium',
                    description: 'Detects command prompt execution',
                    category: 'execution',
                    tags: ['windows', 'cmd']
                }
            ];
        }
    }

    addSignature(signature) {
        const key = this.createSignatureKey(signature);
        this.signatureDatabase.set(key, signature);

        // Add to partial hash index for faster lookup
        this.indexPartialHash(signature.hash, key);
    }

    createSignatureKey(signature) {
        return `${signature.hash}:${signature.algorithm}`;
    }

    indexPartialHash(hash, signatureKey) {
        if (!hash) return;
        
        // Index first 8 characters for partial matching
        const partial = hash.substring(0, 8);
        if (!this.partialHashIndex.has(partial)) {
            this.partialHashIndex.set(partial, new Set());
        }
        this.partialHashIndex.get(partial).add(signatureKey);
    }

    calculateHashes(buffer) {
        return {
            md5: crypto.createHash('md5').update(buffer).digest('hex'),
            sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
            sha256: crypto.createHash('sha256').update(buffer).digest('hex')
        };
    }

    scanByHashes(hashes) {
        const results = {
            exactMatch: null,
            partialMatches: [],
            scanTime: Date.now()
        };

        // Exact hash matching
        const md5Key = `${hashes.md5}:md5`;
        const sha1Key = `${hashes.sha1}:sha1`;
        const sha256Key = `${hashes.sha256}:sha256`;

        if (this.signatureDatabase.has(md5Key)) {
            results.exactMatch = this.signatureDatabase.get(md5Key);
        } else if (this.signatureDatabase.has(sha1Key)) {
            results.exactMatch = this.signatureDatabase.get(sha1Key);
        } else if (this.signatureDatabase.has(sha256Key)) {
            results.exactMatch = this.signatureDatabase.get(sha256Key);
        }

        // Partial hash matching
        const partialResults = this.searchPartialHashes(hashes);
        results.partialMatches = partialResults;

        results.scanTime = Date.now() - results.scanTime;
        return results;
    }

    searchPartialHashes(hashes) {
        const matches = [];

        [hashes.md5, hashes.sha1, hashes.sha256].forEach(hash => {
            if (!hash) return;

            // Search for partial matches
            for (let i = 4; i <= 16; i += 4) {
                const partial = hash.substring(0, i);
                if (this.partialHashIndex.has(partial)) {
                    const signatureKeys = this.partialHashIndex.get(partial);
                    signatureKeys.forEach(key => {
                        const signature = this.signatureDatabase.get(key);
                        if (signature && !matches.find(m => m.key === key)) {
                            matches.push({
                                ...signature,
                                matchType: 'partial',
                                matchLength: i,
                                confidence: i / hash.length,
                                key: key
                            });
                        }
                    });
                }
            }
        });

        // Sort by confidence
        return matches.sort((a, b) => b.confidence - a.confidence);
    }

    scanByFuzzySignatures(content) {
        const results = {
            matches: [],
            scanTime: Date.now()
        };

        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;

        this.fuzzySignatures.forEach(signature => {
            const matches = textContent.match(signature.pattern);
            if (matches && matches.length > 0) {
                results.matches.push({
                    name: signature.name,
                    severity: signature.severity,
                    description: signature.description,
                    matchCount: matches.length,
                    samples: matches.slice(0, 3), // First 3 matches
                    pattern: signature.pattern.source,
                    category: signature.category,
                    tags: signature.tags
                });
            }
        });

        results.scanTime = Date.now() - results.scanTime;
        return results;
    }

    // Enhanced methods using signatures.json data
    getSignaturesByCategory(category) {
        const signatures = [];
        for (const signature of this.signatureDatabase.values()) {
            if (signature.category === category) {
                signatures.push(signature);
            }
        }
        return signatures;
    }

    getSignaturesByFamily(family) {
        const signatures = [];
        for (const signature of this.signatureDatabase.values()) {
            if (signature.family === family) {
                signatures.push(signature);
            }
        }
        return signatures;
    }

    getSignaturesBySeverity(severity) {
        const signatures = [];
        for (const signature of this.signatureDatabase.values()) {
            if (signature.severity === severity) {
                signatures.push(signature);
            }
        }
        return signatures;
    }

    getSignaturesByTag(tag) {
        const signatures = [];
        for (const signature of this.signatureDatabase.values()) {
            if (signature.tags && signature.tags.includes(tag)) {
                signatures.push(signature);
            }
        }
        return signatures;
    }

    // IOC-related methods from signatures.json
    getMaliciousDomains() {
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.domains) {
            return this.signaturesData.iocs.domains;
        }
        return [];
    }

    getMaliciousIPs() {
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.ips) {
            return this.signaturesData.iocs.ips;
        }
        return [];
    }

    getMaliciousURLs() {
        if (this.signaturesData && this.signaturesData.iocs && this.signaturesData.iocs.urls) {
            return this.signaturesData.iocs.urls;
        }
        return [];
    }

    getFileRiskProfiles() {
        if (this.signaturesData && this.signaturesData.file_risk_profiles) {
            return this.signaturesData.file_risk_profiles;
        }
        return {
            exe: 'high',
            dll: 'high',
            js: 'medium',
            pdf: 'medium',
            zip: 'medium',
            txt: 'low'
        };
    }

    getFileRisk(extension) {
        const profiles = this.getFileRiskProfiles();
        const ext = extension.toLowerCase();
        return profiles[ext] || 'medium';
    }

    getYARARules() {
        if (this.signaturesData && this.signaturesData.yara_rules) {
            return this.signaturesData.yara_rules;
        }
        return [];
    }

    getBehaviorPatterns() {
        if (this.signaturesData && this.signaturesData.behavior_patterns) {
            return this.signaturesData.behavior_patterns;
        }
        return [];
    }

    // Enhanced signature matching with metadata
    getSignatureDetails(hash) {
        const keys = [`${hash}:md5`, `${hash}:sha1`, `${hash}:sha256`];
        
        for (const key of keys) {
            if (this.signatureDatabase.has(key)) {
                return this.signatureDatabase.get(key);
            }
        }
        
        return null;
    }

    getSignatureStatistics() {
        const stats = {
            totalSignatures: this.signatureDatabase.size,
            byCategory: {},
            byFamily: {},
            bySeverity: {},
            byAlgorithm: {},
            fuzzyPatterns: this.fuzzySignatures.length,
            iocs: {
                domains: this.getMaliciousDomains().length,
                ips: this.getMaliciousIPs().length,
                urls: this.getMaliciousURLs().length
            }
        };

        // Count by category
        for (const signature of this.signatureDatabase.values()) {
            stats.byCategory[signature.category] = (stats.byCategory[signature.category] || 0) + 1;
            stats.byFamily[signature.family] = (stats.byFamily[signature.family] || 0) + 1;
            stats.bySeverity[signature.severity] = (stats.bySeverity[signature.severity] || 0) + 1;
            stats.byAlgorithm[signature.algorithm] = (stats.byAlgorithm[signature.algorithm] || 0) + 1;
        }

        return stats;
    }

    // Update methods
    updateSignatureDatabase(newSignaturesData) {
        try {
            // Clear existing data
            this.signatureDatabase.clear();
            this.partialHashIndex.clear();
            this.fuzzySignatures = [];
            
            // Update signatures data
            this.signaturesData = newSignaturesData;
            
            // Reload signatures
            this.loadSignaturesFromFile();
            this.initializeFuzzySignatures();
            
            return {
                success: true,
                signaturesLoaded: this.signatureDatabase.size,
                patternsLoaded: this.fuzzySignatures.length
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    addFuzzySignature(pattern, name, severity, description, category = 'unknown', tags = []) {
        try {
            this.fuzzySignatures.push({
                pattern: new RegExp(pattern, 'gi'),
                name: name,
                severity: severity,
                description: description,
                category: category,
                tags: tags
            });
            return true;
        } catch (error) {
            console.error('Error adding fuzzy signature:', error.message);
            return false;
        }
    }

    removeSignature(signatureKey) {
        if (this.signatureDatabase.has(signatureKey)) {
            const signature = this.signatureDatabase.get(signatureKey);
            this.signatureDatabase.delete(signatureKey);

            // Remove from partial hash index
            const hash = signature.hash;
            for (let i = 4; i <= 16; i += 4) {
                const partial = hash.substring(0, i);
                if (this.partialHashIndex.has(partial)) {
                    this.partialHashIndex.get(partial).delete(signatureKey);
                    if (this.partialHashIndex.get(partial).size === 0) {
                        this.partialHashIndex.delete(partial);
                    }
                }
            }

            return true;
        }
        return false;
    }

    // Placeholder for VirusTotal integration
    async checkVirusTotal(hashes) {
        return {
            supported: false,
            message: 'VirusTotal integration not implemented',
            apiKey: process.env.VIRUSTOTAL_API_KEY ? 'configured' : 'not configured',
            results: null
        };
    }

    // Placeholder for YARA rule integration
    async scanWithYARA(filePath) {
        return {
            supported: false,
            message: 'YARA rule scanning not implemented',
            rules: this.getYARARules(),
            matches: []
        };
    }

    // Performance optimization methods
    optimizeDatabase() {
        // Clean up empty partial hash entries
        for (const [key, value] of this.partialHashIndex.entries()) {
            if (value.size === 0) {
                this.partialHashIndex.delete(key);
            }
        }

        return {
            optimized: true,
            partialHashEntries: this.partialHashIndex.size,
            timestamp: new Date().toISOString()
        };
    }

    // Export methods
    exportSignatures() {
        const signatures = Array.from(this.signatureDatabase.values());
        return {
            signatures: signatures,
            fuzzySignatures: this.fuzzySignatures,
            exportedAt: new Date().toISOString()
        };
    }

    importSignatures(signatureData) {
        if (signatureData.signatures) {
            signatureData.signatures.forEach(signature => {
                this.addSignature(this.normalizeSignature(signature));
            });
        }

        if (signatureData.fuzzySignatures) {
            signatureData.fuzzySignatures.forEach(fuzzySig => {
                try {
                    this.fuzzySignatures.push({
                        pattern: new RegExp(fuzzySig.pattern, 'gi'),
                        name: fuzzySig.name,
                        severity: fuzzySig.severity,
                        description: fuzzySig.description,
                        category: fuzzySig.category || 'unknown',
                        tags: fuzzySig.tags || []
                    });
                } catch (error) {
                    console.warn('Invalid fuzzy signature pattern:', fuzzySig.pattern);
                }
            });
        }

        return {
            imported: signatureData.signatures?.length || 0,
            fuzzyImported: signatureData.fuzzySignatures?.length || 0
        };
    }

    // Health check
    getHealthStatus() {
        return {
            status: 'healthy',
            signaturesLoaded: this.signatureDatabase.size,
            fuzzyPatternsLoaded: this.fuzzySignatures.length,
            lastUpdated: new Date().toISOString(),
            signaturesFile: this.signaturesData ? 'loaded' : 'not found',
            errors: []
        };
    }
}

module.exports = SignatureEngineService;
