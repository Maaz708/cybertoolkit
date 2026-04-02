class PatternDetectionService {
    constructor() {
        this.suspiciousPatterns = {
            executables: [
                { pattern: /^MZ/, name: 'PE Header', severity: 'high', description: 'Windows executable detected' },
                { pattern: /^\x7FELF/, name: 'ELF Header', severity: 'high', description: 'Linux executable detected' }
            ],
            powershell: [
                { pattern: /powershell\s+-/i, name: 'PowerShell Command', severity: 'medium', description: 'PowerShell execution command' },
                { pattern: /Invoke-Expression/i, name: 'Invoke-Expression', severity: 'high', description: 'PowerShell script execution' },
                { pattern: /Start-Process/i, name: 'Start-Process', severity: 'medium', description: 'Process creation command' }
            ],
            javascript: [
                { pattern: /eval\s*\(/i, name: 'eval()', severity: 'high', description: 'Dynamic code execution' },
                { pattern: /atob\s*\(/i, name: 'atob()', severity: 'medium', description: 'Base64 decoding' },
                { pattern: /fromCharCode/i, name: 'fromCharCode', severity: 'medium', description: 'Character code conversion' },
                { pattern: /document\.write/i, name: 'document.write', severity: 'medium', description: 'DOM manipulation' }
            ],
            base64: [
                { pattern: /[A-Za-z0-9+/]{20,}={0,2}/g, name: 'Base64 String', severity: 'low', description: 'Base64 encoded data' }
            ],
            suspiciousStrings: [
                { pattern: /cmd\.exe/i, name: 'cmd.exe', severity: 'high', description: 'Windows command prompt' },
                { pattern: /powershell\.exe/i, name: 'powershell.exe', severity: 'high', description: 'PowerShell executable' },
                { pattern: /\/bin\/bash/i, name: '/bin/bash', severity: 'medium', description: 'Linux shell' },
                { pattern: /wget\s+/i, name: 'wget', severity: 'medium', description: 'File download command' },
                { pattern: /curl\s+/i, name: 'curl', severity: 'medium', description: 'HTTP request command' },
                { pattern: /net\.sh/i, name: 'net.sh', severity: 'high', description: 'Network configuration script' },
                { pattern: /system\s*\(/i, name: 'system()', severity: 'high', description: 'System command execution' },
                { pattern: /exec\s*\(/i, name: 'exec()', severity: 'high', description: 'Command execution' }
            ],
            obfuscation: [
                { pattern: /\\x[0-9a-fA-F]{2}/g, name: 'Hex Escape', severity: 'medium', description: 'Hexadecimal obfuscation' },
                { pattern: /\\u[0-9a-fA-F]{4}/g, name: 'Unicode Escape', severity: 'medium', description: 'Unicode obfuscation' },
                { pattern: /\$\{[^}]+\}/g, name: 'Variable Substitution', severity: 'low', description: 'Shell variable substitution' }
            ]
        };
    }

    detectPatterns(content, filename) {
        const findings = {
            total: 0,
            byCategory: {},
            highRisk: [],
            mediumRisk: [],
            lowRisk: []
        };

        // Convert buffer to string for text-based patterns
        const textContent = Buffer.isBuffer(content) ? content.toString('latin1') : content;
        
        for (const [category, patterns] of Object.entries(this.suspiciousPatterns)) {
            findings.byCategory[category] = [];
            
            patterns.forEach(patternObj => {
                const matches = textContent.match(patternObj.pattern);
                if (matches) {
                    const finding = {
                        pattern: patternObj.name,
                        severity: patternObj.severity,
                        description: patternObj.description,
                        matches: matches.length,
                        samples: matches.slice(0, 3) // First 3 matches
                    };
                    
                    findings.byCategory[category].push(finding);
                    findings.total++;
                    
                    // Categorize by severity
                    switch (patternObj.severity) {
                        case 'high':
                            findings.highRisk.push(finding);
                            break;
                        case 'medium':
                            findings.mediumRisk.push(finding);
                            break;
                        case 'low':
                            findings.lowRisk.push(finding);
                            break;
                    }
                }
            });
        }

        return findings;
    }

    detectFileTypeSpecificPatterns(content, filename) {
        const ext = filename.toLowerCase().split('.').pop();
        const textContent = Buffer.isBuffer(content) ? content.toString('utf8', 0, Math.min(content.length, 10000)) : content;
        
        const specificFindings = [];

        switch (ext) {
            case 'js':
                specificFindings.push(...this.analyzeJavaScript(textContent));
                break;
            case 'html':
            case 'htm':
                specificFindings.push(...this.analyzeHTML(textContent));
                break;
            case 'php':
                specificFindings.push(...this.analyzePHP(textContent));
                break;
            case 'py':
                specificFindings.push(...this.analyzePython(textContent));
                break;
        }

        return specificFindings;
    }

    analyzeJavaScript(content) {
        const findings = [];
        
        // Detect obfuscation techniques
        if (content.includes('eval(') && content.includes('String.fromCharCode')) {
            findings.push({
                pattern: 'Obfuscated JavaScript',
                severity: 'high',
                description: 'Common obfuscation pattern detected'
            });
        }

        // Detect suspicious URLs
        const urlPattern = /https?:\/\/[^\s"']+/gi;
        const urls = content.match(urlPattern);
        if (urls && urls.length > 5) {
            findings.push({
                pattern: 'Multiple URLs',
                severity: 'medium',
                description: `Found ${urls.length} URLs in JavaScript code`
            });
        }

        return findings;
    }

    analyzeHTML(content) {
        const findings = [];
        
        // Detect scripts with external sources
        const scriptPattern = /<script[^>]*src[^>]*>/gi;
        const scripts = content.match(scriptPattern);
        if (scripts && scripts.length > 3) {
            findings.push({
                pattern: 'Multiple External Scripts',
                severity: 'medium',
                description: `Found ${scripts.length} external script references`
            });
        }

        // Detect iframes
        if (content.includes('<iframe')) {
            findings.push({
                pattern: 'iframe detected',
                severity: 'medium',
                description: 'HTML iframe found - potential for hidden content'
            });
        }

        return findings;
    }

    analyzePHP(content) {
        const findings = [];
        
        // Detect dangerous PHP functions
        const dangerousFunctions = ['eval(', 'system(', 'exec(', 'shell_exec(', 'passthru('];
        dangerousFunctions.forEach(func => {
            if (content.includes(func)) {
                findings.push({
                    pattern: `Dangerous PHP function: ${func}`,
                    severity: 'high',
                    description: `PHP code contains dangerous function ${func}`
                });
            }
        });

        return findings;
    }

    analyzePython(content) {
        const findings = [];
        
        // Detect dangerous Python functions
        const dangerousFunctions = ['eval(', 'exec(', 'subprocess.call(', 'os.system('];
        dangerousFunctions.forEach(func => {
            if (content.includes(func)) {
                findings.push({
                    pattern: `Dangerous Python function: ${func}`,
                    severity: 'high',
                    description: `Python code contains dangerous function ${func}`
                });
            }
        });

        return findings;
    }
}

module.exports = PatternDetectionService;
