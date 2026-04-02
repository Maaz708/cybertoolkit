const fs = require('fs');
const path = require('path');

class HeuristicAnalysisService {
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
        // Initialize with default patterns
        this.suspiciousPatterns = {
            obfuscation: [
                { pattern: /eval\s*\(/gi, severity: 'high', name: 'eval() function', description: 'Dynamic code execution detected' },
                { pattern: /atob\s*\(/gi, severity: 'medium', name: 'atob() function', description: 'Base64 decoding detected' },
                { pattern: /fromCharCode/gi, severity: 'medium', name: 'fromCharCode', description: 'Character code conversion' },
                { pattern: /String\.fromCharCode/gi, severity: 'medium', name: 'String.fromCharCode', description: 'Character code conversion' },
                { pattern: /\\x[0-9a-fA-F]{2}/g, severity: 'medium', name: 'Hex escape sequences', description: 'Hexadecimal obfuscation' },
                { pattern: /\\u[0-9a-fA-F]{4}/g, severity: 'medium', name: 'Unicode escape', description: 'Unicode obfuscation' }
            ],
            powershell: [
                { pattern: /powershell\s+-/gi, severity: 'high', name: 'PowerShell command', description: 'PowerShell execution command' },
                { pattern: /Invoke-Expression/gi, severity: 'critical', name: 'Invoke-Expression', description: 'PowerShell script execution' },
                { pattern: /Start-Process/gi, severity: 'high', name: 'Start-Process', description: 'Process creation command' },
                { pattern: /New-Object/gi, severity: 'medium', name: 'New-Object', description: 'Object creation' },
                { pattern: /Get-WmiObject/gi, severity: 'medium', name: 'Get-WmiObject', description: 'WMI query' }
            ],
            reverseShell: [
                { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp/gi, severity: 'critical', name: 'Bash reverse shell', description: 'Bash reverse shell pattern' },
                { pattern: /nc\s+-l/gi, severity: 'high', name: 'Netcat listener', description: 'Netcat listener setup' },
                { pattern: /netcat\s+-l/gi, severity: 'high', name: 'Netcat listener', description: 'Netcat listener setup' },
                { pattern: /socat\s+TCP/gi, severity: 'high', name: 'Socat TCP', description: 'Socat TCP connection' },
                { pattern: /python.*socket.*connect/gi, severity: 'high', name: 'Python socket', description: 'Python socket connection' }
            ],
            suspiciousStrings: [
                { pattern: /cmd\.exe/gi, severity: 'high', name: 'cmd.exe', description: 'Windows command prompt' },
                { pattern: /powershell\.exe/gi, severity: 'high', name: 'powershell.exe', description: 'PowerShell executable' },
                { pattern: /\/bin\/bash/gi, severity: 'medium', name: '/bin/bash', description: 'Linux shell' },
                { pattern: /\/bin\/sh/gi, severity: 'medium', name: '/bin/sh', description: 'Linux shell' },
                { pattern: /wget\s+/gi, severity: 'medium', name: 'wget', description: 'File download command' },
                { pattern: /curl\s+/gi, severity: 'medium', name: 'curl', description: 'HTTP request command' },
                { pattern: /nc\.exe/gi, severity: 'high', name: 'nc.exe', description: 'Netcat executable' },
                { pattern: /netcat\.exe/gi, severity: 'high', name: 'netcat.exe', description: 'Netcat executable' },
                { pattern: /plink\.exe/gi, severity: 'high', name: 'plink.exe', description: 'PuTTY Link tool' },
                { pattern: /putty\.exe/gi, severity: 'medium', name: 'putty.exe', description: 'PuTTY SSH client' }
            ],
            base64Payloads: [
                { pattern: /[A-Za-z0-9+/]{100,}={0,2}/g, severity: 'medium', name: 'Long Base64 string', description: 'Potential Base64 payload' },
                { pattern: /echo\s+[A-Za-z0-9+/]{50,}\s*\|\s*base64\s*-d/gi, severity: 'high', name: 'Base64 decode pipe', description: 'Base64 decoding command' },
                { pattern: /certutil\s+-decode/gi, severity: 'high', name: 'certutil decode', description: 'Certificate utility decode' }
            ],
            registry: [
                { pattern: /reg\s+add/gi, severity: 'medium', name: 'Registry add', description: 'Registry modification' },
                { pattern: /regsvr32\.exe/gi, severity: 'high', name: 'regsvr32.exe', description: 'DLL registration' },
                { pattern: /rundll32\.exe/gi, severity: 'high', name: 'rundll32.exe', description: 'DLL execution' }
            ],
            network: [
                { pattern: /socket\s*\(/gi, severity: 'medium', name: 'Socket creation', description: 'Network socket creation' },
                { pattern: /connect\s*\(/gi, severity: 'medium', name: 'Socket connect', description: 'Network connection' },
                { pattern: /bind\s*\(/gi, severity: 'medium', name: 'Socket bind', description: 'Socket binding' },
                { pattern: /listen\s*\(/gi, severity: 'medium', name: 'Socket listen', description: 'Socket listening' }
            ]
        };

        // Load patterns from signatures.json if available
        this.loadPatternsFromSignatures();

        this.severityWeights = {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4
        };
    }

    loadPatternsFromSignatures() {
        if (!this.signaturesData || !this.signaturesData.patterns) {
            return;
        }

        // Add patterns from signatures.json to appropriate categories
        this.signaturesData.patterns.forEach(pattern => {
            try {
                const regex = new RegExp(pattern.pattern, 'gi');
                const patternObj = {
                    pattern: regex,
                    severity: pattern.severity || 'medium',
                    name: pattern.type,
                    description: pattern.description,
                    tags: pattern.tags || []
                };

                // Determine category based on tags or type
                let category = 'general';
                if (pattern.tags) {
                    if (pattern.tags.includes('script')) category = 'obfuscation';
                    else if (pattern.tags.includes('execution')) category = 'powershell';
                    else if (pattern.tags.includes('network')) category = 'reverseShell';
                    else if (pattern.tags.includes('obfuscation')) category = 'obfuscation';
                    else if (pattern.tags.includes('windows')) category = 'suspiciousStrings';
                    else if (pattern.tags.includes('linux')) category = 'suspiciousStrings';
                }

                if (pattern.type.toLowerCase().includes('powershell')) category = 'powershell';
                else if (pattern.type.toLowerCase().includes('shell') || pattern.type.toLowerCase().includes('reverse')) category = 'reverseShell';
                else if (pattern.type.toLowerCase().includes('obfuscation') || pattern.type.toLowerCase().includes('js')) category = 'obfuscation';
                else if (pattern.type.toLowerCase().includes('command') || pattern.type.toLowerCase().includes('execution')) category = 'suspiciousStrings';

                // Add to appropriate category
                if (!this.suspiciousPatterns[category]) {
                    this.suspiciousPatterns[category] = [];
                }
                this.suspiciousPatterns[category].push(patternObj);

            } catch (error) {
                console.warn('Invalid pattern in signatures.json:', pattern.pattern, error.message);
            }
        });
    }

    analyzeContent(content, filename = '') {
        const analysis = {
            totalMatches: 0,
            severityBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
            categoryBreakdown: {},
            matches: [],
            riskScore: 0,
            severity: 'low'
        };

        // Convert buffer to string if needed
        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;
        
        // Analyze each category
        Object.entries(this.suspiciousPatterns).forEach(([category, patterns]) => {
            const categoryResults = this.analyzeCategory(textContent, category, patterns);
            
            analysis.categoryBreakdown[category] = categoryResults;
            analysis.matches.push(...categoryResults.matches);
            analysis.totalMatches += categoryResults.totalMatches;
            
            // Update severity breakdown
            Object.entries(categoryResults.severityBreakdown).forEach(([severity, count]) => {
                analysis.severityBreakdown[severity] += count;
            });
        });

        // Calculate overall risk score and severity
        analysis.riskScore = this.calculateRiskScore(analysis.severityBreakdown);
        analysis.severity = this.determineOverallSeverity(analysis.severityBreakdown);

        // Add filename-specific analysis
        if (filename) {
            const filenameAnalysis = this.analyzeFilename(filename);
            if (filenameAnalysis.matches.length > 0) {
                analysis.matches.push(...filenameAnalysis.matches);
                analysis.totalMatches += filenameAnalysis.matches.length;
                analysis.categoryBreakdown.filename = filenameAnalysis;
            }
        }

        return analysis;
    }

    analyzeCategory(textContent, category, patterns) {
        const results = {
            totalMatches: 0,
            severityBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
            matches: []
        };

        patterns.forEach(patternObj => {
            const matches = textContent.match(patternObj.pattern);
            if (matches && matches.length > 0) {
                const matchInfo = {
                    pattern: patternObj.name,
                    severity: patternObj.severity,
                    description: patternObj.description,
                    matchCount: matches.length,
                    samples: matches.slice(0, 3), // First 3 matches
                    category: category,
                    riskContribution: this.severityWeights[patternObj.severity] * matches.length
                };

                results.matches.push(matchInfo);
                results.totalMatches += matches.length;
                results.severityBreakdown[patternObj.severity] += matches.length;
            }
        });

        return results;
    }

    analyzeFilename(filename) {
        const results = {
            totalMatches: 0,
            severityBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
            matches: []
        };

        const suspiciousFilenamePatterns = [
            { pattern: /installer|setup|crack|keygen|patch/gi, severity: 'medium', name: 'Suspicious installer', description: 'Potentially malicious installer' },
            { pattern: /temp|tmp|cache|download/gi, severity: 'low', name: 'Temporary file', description: 'Temporary or cache file' },
            { pattern: /svchost|system32|windows/gi, severity: 'high', name: 'System impersonation', description: 'Impersonating system file' },
            { pattern: /\.scr$|\.bat$|\.cmd$|\.ps1$|\.vbs$/gi, severity: 'medium', name: 'Executable script', description: 'Script file extension' }
        ];

        suspiciousFilenamePatterns.forEach(patternObj => {
            if (patternObj.pattern.test(filename)) {
                const matchInfo = {
                    pattern: patternObj.name,
                    severity: patternObj.severity,
                    description: patternObj.description,
                    matchCount: 1,
                    samples: [filename],
                    category: 'filename',
                    riskContribution: this.severityWeights[patternObj.severity]
                };

                results.matches.push(matchInfo);
                results.totalMatches += 1;
                results.severityBreakdown[patternObj.severity] += 1;
            }
        });

        return results;
    }

    calculateRiskScore(severityBreakdown) {
        let score = 0;
        
        score += severityBreakdown.low * 1;
        score += severityBreakdown.medium * 3;
        score += severityBreakdown.high * 5;
        score += severityBreakdown.critical * 10;

        return Math.min(score, 100); // Cap at 100
    }

    determineOverallSeverity(severityBreakdown) {
        if (severityBreakdown.critical > 0) return 'critical';
        if (severityBreakdown.high > 2) return 'high';
        if (severityBreakdown.high > 0 || severityBreakdown.medium > 5) return 'high';
        if (severityBreakdown.medium > 2) return 'medium';
        if (severityBreakdown.medium > 0 || severityBreakdown.low > 5) return 'medium';
        if (severityBreakdown.low > 0) return 'low';
        return 'clean';
    }

    detectObfuscationTechniques(content) {
        const techniques = [];
        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;

        // Detect various obfuscation techniques
        if (/\\x[0-9a-fA-F]{2}/g.test(textContent)) {
            techniques.push({
                name: 'Hex Encoding',
                severity: 'medium',
                description: 'Hexadecimal encoding detected'
            });
        }

        if (/\\u[0-9a-fA-F]{4}/g.test(textContent)) {
            techniques.push({
                name: 'Unicode Encoding',
                severity: 'medium',
                description: 'Unicode encoding detected'
            });
        }

        if (/[A-Za-z0-9+/]{50,}={0,2}/g.test(textContent)) {
            techniques.push({
                name: 'Base64 Encoding',
                severity: 'medium',
                description: 'Base64 encoding detected'
            });
        }

        if (/\$\{[^}]+\}/g.test(textContent)) {
            techniques.push({
                name: 'Variable Substitution',
                severity: 'low',
                description: 'Shell variable substitution detected'
            });
        }

        // Detect string concatenation obfuscation
        if (/"[^"]+"\s*\+\s*"[^"]+"/g.test(textContent) || /'[^']+'\s*\+\s*'[^']+'/g.test(textContent)) {
            techniques.push({
                name: 'String Concatenation',
                severity: 'low',
                description: 'String concatenation obfuscation detected'
            });
        }

        return techniques;
    }

    detectSuspiciousImports(content) {
        const suspiciousImports = [];
        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;

        const dangerousAPIs = [
            'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory', 'SetWindowsHookEx',
            'CreateProcess', 'WinExec', 'ShellExecute', 'URLDownloadToFile', 'InternetOpenUrl',
            'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
            'system', 'exec', 'popen', 'CreateFile', 'WriteFile', 'DeleteFile',
            'RegCreateKey', 'RegSetValue', 'RegDeleteKey'
        ];

        dangerousAPIs.forEach(api => {
            const regex = new RegExp(api, 'gi');
            if (regex.test(textContent)) {
                const matches = textContent.match(regex);
                suspiciousImports.push({
                    api: api,
                    matchCount: matches.length,
                    severity: this.getAPISeverity(api),
                    samples: matches.slice(0, 3)
                });
            }
        });

        return suspiciousImports;
    }

    getAPISeverity(api) {
        const highRiskAPIs = [
            'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory', 'SetWindowsHookEx',
            'CreateProcess', 'WinExec', 'ShellExecute', 'URLDownloadToFile'
        ];

        const mediumRiskAPIs = [
            'InternetOpenUrl', 'socket', 'connect', 'bind', 'listen', 'accept',
            'system', 'exec', 'popen', 'CreateFile', 'WriteFile', 'DeleteFile'
        ];

        if (highRiskAPIs.includes(api)) return 'high';
        if (mediumRiskAPIs.includes(api)) return 'medium';
        return 'low';
    }

    addCustomPattern(category, pattern, severity, name, description) {
        if (!this.suspiciousPatterns[category]) {
            this.suspiciousPatterns[category] = [];
        }

        this.suspiciousPatterns[category].push({
            pattern: pattern,
            severity: severity,
            name: name,
            description: description
        });
    }

    removePattern(category, patternName) {
        if (this.suspiciousPatterns[category]) {
            const index = this.suspiciousPatterns[category].findIndex(p => p.name === patternName);
            if (index !== -1) {
                this.suspiciousPatterns[category].splice(index, 1);
                return true;
            }
        }
        return false;
    }

    getPatternStats() {
        const stats = {
            totalPatterns: 0,
            categories: {}
        };

        Object.entries(this.suspiciousPatterns).forEach(([category, patterns]) => {
            stats.categories[category] = patterns.length;
            stats.totalPatterns += patterns.length;
        });

        return stats;
    }

    // Advanced heuristic methods
    detectEncodedCommands(content) {
        const encodedCommands = [];
        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;

        // Look for common encoded command patterns
        const patterns = [
            { regex: /powershell.*-e(?:ncoded)?\s+([A-Za-z0-9+/]+)/gi, type: 'PowerShell Encoded' },
            { regex: /cmd.*\/c.*echo.*([A-Za-z0-9+/]+).*\|\s*base64/gi, type: 'CMD Base64' },
            { regex: /certutil.*-decode.*([A-Za-z0-9+/]+)/gi, type: 'Certutil Decode' }
        ];

        patterns.forEach(patternObj => {
            const matches = textContent.match(patternObj.regex);
            if (matches) {
                encodedCommands.push({
                    type: patternObj.type,
                    matches: matches,
                    count: matches.length,
                    severity: 'high'
                });
            }
        });

        return encodedCommands;
    }

    analyzeCodeStructure(content) {
        const analysis = {
            hasLoops: false,
            hasConditions: false,
            hasFunctions: false,
            hasClasses: false,
            complexity: 'simple'
        };

        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;

        // Detect code structures
        if (/\b(for|while|do)\b/gi.test(textContent)) {
            analysis.hasLoops = true;
        }

        if (/\b(if|else|switch|case)\b/gi.test(textContent)) {
            analysis.hasConditions = true;
        }

        if (/\b(function|def|sub|proc)\b/gi.test(textContent)) {
            analysis.hasFunctions = true;
        }

        if (/\b(class|struct|interface)\b/gi.test(textContent)) {
            analysis.hasClasses = true;
        }

        // Determine complexity
        const complexityScore = [
            analysis.hasLoops ? 1 : 0,
            analysis.hasConditions ? 1 : 0,
            analysis.hasFunctions ? 1 : 0,
            analysis.hasClasses ? 1 : 0
        ].reduce((a, b) => a + b, 0);

        if (complexityScore >= 3) {
            analysis.complexity = 'complex';
        } else if (complexityScore >= 2) {
            analysis.complexity = 'moderate';
        }

        return analysis;
    }
}

module.exports = HeuristicAnalysisService;
