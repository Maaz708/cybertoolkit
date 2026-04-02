const fs = require('fs');
const path = require('path');

class BehaviorAnalysisService {
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
        this.behaviorPatterns = {
            fileDropper: [
                { pattern: /createFile|writeFile|fopen|fwrite/gi, severity: 'medium', name: 'File Creation' },
                { pattern: /copyFile|moveFile|renameFile/gi, severity: 'medium', name: 'File Manipulation' },
                { pattern: /\.exe|\.dll|\.scr|\.bat|\.cmd|\.ps1|\.vbs/gi, severity: 'high', name: 'Executable File Extension' },
                { pattern: /temp|tmp|appdata|startup|system32/gi, severity: 'high', name: 'Suspicious File Location' }
            ],
            keylogger: [
                { pattern: /getAsyncKeyState|getKeyboardState|setWindowsHookEx/gi, severity: 'critical', name: 'Keylogging API' },
                { pattern: /keyboard|keystroke|keylog/gi, severity: 'high', name: 'Keylogging Keywords' },
                { pattern: /hook|wh_keyboard|ll_keyboard/gi, severity: 'high', name: 'Keyboard Hooking' },
                { pattern: /log.*key|record.*key|capture.*key/gi, severity: 'high', name: 'Key Capture' }
            ],
            networkBeaconing: [
                { pattern: /setInterval|setTimeout.*\d+/gi, severity: 'medium', name: 'Timed Execution' },
                { pattern: /while\s*\(true\)|for\s*\(;;\)/gi, severity: 'medium', name: 'Infinite Loop' },
                { pattern: /sleep.*\d+/gi, severity: 'medium', name: 'Sleep Patterns' },
                { pattern: /connect.*socket|tcp.*connect/gi, severity: 'high', name: 'Network Connection' },
                { pattern: /http.*request|fetch|xmlhttprequest/gi, severity: 'medium', name: 'HTTP Requests' }
            ],
            persistence: [
                { pattern: /registry.*run|startup|autorun/gi, severity: 'high', name: 'Persistence Mechanism' },
                { pattern: /hkey.*run|hkey.*currentversion/gi, severity: 'high', name: 'Registry Persistence' },
                { pattern: /scheduled.*task|task.*scheduler/gi, severity: 'high', name: 'Scheduled Task' },
                { pattern: /service.*create|createService/gi, severity: 'high', name: 'Service Creation' },
                { pattern: /wmi.*event|__eventconsumer/gi, severity: 'high', name: 'WMI Persistence' }
            ],
            privilegeEscalation: [
                { pattern: /token.*privilege|adjusttoken|seprivilege/gi, severity: 'high', name: 'Token Privilege' },
                { pattern: /impersonate|duplicateToken/gi, severity: 'high', name: 'Token Impersonation' },
                { pattern: /runas|sudo|su\s+/gi, severity: 'medium', name: 'Privilege Escalation' },
                { pattern: /bypassuac|uac.*bypass/gi, severity: 'critical', name: 'UAC Bypass' }
            ],
            dataExfiltration: [
                { pattern: /upload|post.*data|send.*file/gi, severity: 'high', name: 'Data Upload' },
                { pattern: /email.*send|smtp|mail.*to/gi, severity: 'medium', name: 'Email Exfiltration' },
                { pattern: /ftp.*upload|sftp.*upload/gi, severity: 'high', name: 'FTP Upload' },
                { pattern: /compress.*file|zip.*file/gi, severity: 'medium', name: 'File Compression' },
                { pattern: /encrypt.*file|aes|rsa|des/gi, severity: 'medium', name: 'File Encryption' }
            ],
            antiAnalysis: [
                { pattern: /debugger|isdebuggerpresent/gi, severity: 'high', name: 'Debugger Detection' },
                { pattern: /virtual.*box|vmware|qemu|sandbox/gi, severity: 'high', name: 'VM Detection' },
                { pattern: /process.*hide|hide.*process/gi, severity: 'medium', name: 'Process Hiding' },
                { pattern: /delete.*self|remove.*self/gi, severity: 'medium', name: 'Self Deletion' },
                { pattern: /timing.*check|sleep.*random/gi, severity: 'medium', name: 'Timing Checks' }
            ],
            ransomware: [
                { pattern: /encrypt.*file|decrypt.*file/gi, severity: 'critical', name: 'File Encryption' },
                { pattern: /ransom|payment|bitcoin|crypto/gi, severity: 'critical', name: 'Ransom Keywords' },
                { pattern: /delete.*shadow|vssadmin|wbadmin/gi, severity: 'high', name: 'Shadow Copy Deletion' },
                { pattern: /note.*txt|readme.*txt|decrypt.*txt/gi, severity: 'high', name: 'Ransom Note' }
            ]
        };

        // Load behavior patterns from signatures.json
        this.loadBehaviorPatternsFromSignatures();

        this.severityWeights = {
            low: 1,
            medium: 3,
            high: 5,
            critical: 10
        };
    }

    loadBehaviorPatternsFromSignatures() {
        if (!this.signaturesData || !this.signaturesData.behavior_patterns) {
            return;
        }

        // Add behavior patterns from signatures.json
        this.signaturesData.behavior_patterns.forEach(behaviorPattern => {
            const pattern = {
                pattern: new RegExp(behaviorPattern.type.replace(/\s+/g, '|'), 'gi'),
                severity: behaviorPattern.severity || 'medium',
                name: behaviorPattern.type,
                description: behaviorPattern.description
            };

            // Determine category based on type
            let category = 'general';
            const type = behaviorPattern.type.toLowerCase();
            
            if (type.includes('reverse_shell') || type.includes('shell')) category = 'keylogger';
            else if (type.includes('data_exfiltration')) category = 'dataExfiltration';
            else if (type.includes('persistence')) category = 'persistence';
            else if (type.includes('file_dropper')) category = 'fileDropper';
            else if (type.includes('privilege')) category = 'privilegeEscalation';
            else if (type.includes('anti')) category = 'antiAnalysis';
            else if (type.includes('ransom')) category = 'ransomware';
            else if (type.includes('network') || type.includes('beacon')) category = 'networkBeaconing';

            if (!this.behaviorPatterns[category]) {
                this.behaviorPatterns[category] = [];
            }
            this.behaviorPatterns[category].push(pattern);
        });
    }

    analyzeBehavior(buffer, filename = '') {
        const analysis = {
            behaviors: {},
            behaviorTags: [],
            riskScore: 0,
            severity: 'low',
            summary: {
                totalBehaviors: 0,
                criticalBehaviors: 0,
                highBehaviors: 0,
                mediumBehaviors: 0,
                lowBehaviors: 0
            },
            recommendations: []
        };

        // Convert buffer to text for analysis
        const textContent = this.extractTextContent(buffer);

        // Analyze each behavior category
        Object.entries(this.behaviorPatterns).forEach(([category, patterns]) => {
            const categoryAnalysis = this.analyzeBehaviorCategory(textContent, category, patterns);
            analysis.behaviors[category] = categoryAnalysis;
            
            // Update summary
            analysis.summary.totalBehaviors += categoryAnalysis.matches.length;
            Object.entries(categoryAnalysis.severityBreakdown).forEach(([severity, count]) => {
                analysis.summary[severity + 'Behaviors'] += count;
            });

            // Add behavior tags
            if (categoryAnalysis.matches.length > 0) {
                analysis.behaviorTags.push(category);
            }
        });

        // Calculate overall risk score and severity
        analysis.riskScore = this.calculateBehaviorRiskScore(analysis.summary);
        analysis.severity = this.determineBehaviorSeverity(analysis.summary);
        analysis.recommendations = this.generateBehaviorRecommendations(analysis);

        return analysis;
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
        
        return buffer.toString('latin1');
    }

    isValidText(text) {
        let printableChars = 0;
        const sample = text.substring(0, 1000);
        
        for (let i = 0; i < sample.length; i++) {
            const char = sample.charCodeAt(i);
            if ((char >= 32 && char <= 126) || char === 9 || char === 10 || char === 13) {
                printableChars++;
            }
        }
        
        return (printableChars / sample.length) > 0.7;
    }

    analyzeBehaviorCategory(textContent, category, patterns) {
        const analysis = {
            matches: [],
            severityBreakdown: { low: 0, medium: 0, high: 0, critical: 0 },
            riskScore: 0,
            confidence: 0
        };

        patterns.forEach(patternObj => {
            const matches = textContent.match(patternObj.pattern);
            if (matches && matches.length > 0) {
                const matchInfo = {
                    pattern: patternObj.name,
                    severity: patternObj.severity,
                    description: this.getBehaviorDescription(category, patternObj.name),
                    matchCount: matches.length,
                    samples: matches.slice(0, 3),
                    category: category,
                    riskContribution: this.severityWeights[patternObj.severity] * matches.length
                };

                analysis.matches.push(matchInfo);
                analysis.severityBreakdown[patternObj.severity] += matches.length;
            }
        });

        // Calculate category risk score
        analysis.riskScore = this.calculateCategoryRiskScore(analysis.severityBreakdown);
        
        // Calculate confidence based on match diversity and count
        analysis.confidence = this.calculateCategoryConfidence(analysis.matches);

        return analysis;
    }

    getBehaviorDescription(category, patternName) {
        const descriptions = {
            fileDropper: {
                'File Creation': 'Creates new files on the system',
                'File Manipulation': 'Manipulates existing files',
                'Executable File Extension': 'References executable file extensions',
                'Suspicious File Location': 'Accesses suspicious file system locations'
            },
            keylogger: {
                'Keylogging API': 'Uses keylogging APIs',
                'Keylogging Keywords': 'Contains keylogging-related keywords',
                'Keyboard Hooking': 'Implements keyboard hooking',
                'Key Capture': 'Captures keystrokes'
            },
            networkBeaconing: {
                'Timed Execution': 'Implements timed execution patterns',
                'Infinite Loop': 'Contains infinite loops',
                'Sleep Patterns': 'Uses sleep patterns',
                'Network Connection': 'Establishes network connections',
                'HTTP Requests': 'Makes HTTP requests'
            },
            persistence: {
                'Persistence Mechanism': 'Implements persistence mechanisms',
                'Registry Persistence': 'Uses registry for persistence',
                'Scheduled Task': 'Creates scheduled tasks',
                'Service Creation': 'Creates system services',
                'WMI Persistence': 'Uses WMI for persistence'
            },
            privilegeEscalation: {
                'Token Privilege': 'Manipulates token privileges',
                'Token Impersonation': 'Impersonates user tokens',
                'Privilege Escalation': 'Attempts privilege escalation',
                'UAC Bypass': 'Attempts to bypass UAC'
            },
            dataExfiltration: {
                'Data Upload': 'Uploads data to external servers',
                'Email Exfiltration': 'Uses email for data exfiltration',
                'FTP Upload': 'Uses FTP for file upload',
                'File Compression': 'Compresses files before exfiltration',
                'File Encryption': 'Encrypts files before exfiltration'
            },
            antiAnalysis: {
                'Debugger Detection': 'Detects debuggers',
                'VM Detection': 'Detects virtual environments',
                'Process Hiding': 'Hides processes',
                'Self Deletion': 'Deletes itself after execution',
                'Timing Checks': 'Implements timing-based checks'
            },
            ransomware: {
                'File Encryption': 'Encrypts files',
                'Ransom Keywords': 'Contains ransom-related keywords',
                'Shadow Copy Deletion': 'Deletes shadow copies',
                'Ransom Note': 'Creates ransom notes'
            }
        };

        return descriptions[category]?.[patternName] || `${category} behavior: ${patternName}`;
    }

    calculateCategoryRiskScore(severityBreakdown) {
        let score = 0;
        
        score += severityBreakdown.low * 1;
        score += severityBreakdown.medium * 3;
        score += severityBreakdown.high * 5;
        score += severityBreakdown.critical * 10;

        return Math.min(score, 100);
    }

    calculateCategoryConfidence(matches) {
        if (matches.length === 0) return 0;
        
        // Confidence based on number of unique patterns and total matches
        const uniquePatterns = matches.length;
        const totalMatches = matches.reduce((sum, match) => sum + match.matchCount, 0);
        
        // More unique patterns and more matches increase confidence
        let confidence = Math.min((uniquePatterns * 10) + (totalMatches * 2), 100);
        
        // Cap at 95% unless there are critical severity matches
        if (!matches.some(m => m.severity === 'critical')) {
            confidence = Math.min(confidence, 95);
        }
        
        return confidence;
    }

    calculateBehaviorRiskScore(summary) {
        let score = 0;
        
        score += summary.lowBehaviors * 2;
        score += summary.mediumBehaviors * 5;
        score += summary.highBehaviors * 10;
        score += summary.criticalBehaviors * 20;

        return Math.min(score, 100);
    }

    determineBehaviorSeverity(summary) {
        if (summary.criticalBehaviors > 0) return 'critical';
        if (summary.highBehaviors > 2) return 'high';
        if (summary.highBehaviors > 0 || summary.mediumBehaviors > 5) return 'high';
        if (summary.mediumBehaviors > 2) return 'medium';
        if (summary.mediumBehaviors > 0 || summary.lowBehaviors > 5) return 'medium';
        if (summary.lowBehaviors > 0) return 'low';
        return 'clean';
    }

    generateBehaviorRecommendations(analysis) {
        const recommendations = [];
        const { behaviors, behaviorTags, severity } = analysis;

        // Critical behavior recommendations
        if (severity === 'critical') {
            recommendations.push({
                priority: 'critical',
                title: 'Critical Malicious Behavior Detected',
                description: 'File exhibits critical malicious behaviors. Immediate quarantine recommended.',
                actions: ['quarantine', 'incident_response', 'forensic_analysis']
            });
        }

        // Specific behavior-based recommendations
        if (behaviorTags.includes('keylogger')) {
            recommendations.push({
                priority: 'critical',
                title: 'Keylogger Behavior Detected',
                description: 'File exhibits keylogging behavior. Potential credential theft.',
                actions: ['quarantine', 'password_change', 'system_scan']
            });
        }

        if (behaviorTags.includes('ransomware')) {
            recommendations.push({
                priority: 'critical',
                title: 'Ransomware Behavior Detected',
                description: 'File exhibits ransomware behavior. Immediate isolation required.',
                actions: ['isolate_system', 'disconnect_network', 'backup_recovery']
            });
        }

        if (behaviorTags.includes('persistence')) {
            recommendations.push({
                priority: 'high',
                title: 'Persistence Mechanism Detected',
                description: 'File attempts to maintain persistence on the system.',
                actions: ['remove_persistence', 'scan_registry', 'monitor_system']
            });
        }

        if (behaviorTags.includes('privilegeEscalation')) {
            recommendations.push({
                priority: 'high',
                title: 'Privilege Escalation Attempt',
                description: 'File attempts to escalate privileges.',
                actions: ['review_permissions', 'audit_logs', 'system_hardening']
            });
        }

        if (behaviorTags.includes('dataExfiltration')) {
            recommendations.push({
                priority: 'high',
                title: 'Data Exfiltration Risk',
                description: 'File may attempt to exfiltrate sensitive data.',
                actions: ['monitor_network', 'data_loss_prevention', 'access_review']
            });
        }

        if (behaviorTags.includes('antiAnalysis')) {
            recommendations.push({
                priority: 'medium',
                title: 'Anti-Analysis Techniques',
                description: 'File uses anti-analysis techniques to evade detection.',
                actions: ['sandbox_analysis', 'deep_inspection', 'behavior_monitoring']
            });
        }

        if (behaviorTags.includes('networkBeaconing')) {
            recommendations.push({
                priority: 'medium',
                title: 'Network Beaconing Behavior',
                description: 'File exhibits network beaconing patterns.',
                actions: ['network_monitoring', 'firewall_rules', 'ip_blocking']
            });
        }

        if (behaviorTags.includes('fileDropper')) {
            recommendations.push({
                priority: 'medium',
                title: 'File Dropper Behavior',
                description: 'File may drop additional malicious files.',
                actions: ['file_monitoring', 'quarantine_drops', 'system_scan']
            });
        }

        // Default recommendations for lower severity
        if (severity === 'medium' && recommendations.length === 0) {
            recommendations.push({
                priority: 'medium',
                title: 'Suspicious Behavior Detected',
                description: 'File exhibits suspicious behaviors that require monitoring.',
                actions: ['monitor', 'log_activity', 'periodic_scan']
            });
        }

        if (severity === 'low' && recommendations.length === 0) {
            recommendations.push({
                priority: 'low',
                title: 'Behavioral Analysis Complete',
                description: 'File shows minimal suspicious behaviors.',
                actions: ['monitor', 'document', 'periodic_review']
            });
        }

        return recommendations;
    }

    // Advanced behavior analysis methods
    detectCommandAndControl(textContent) {
        const c2Indicators = {
            hardcodedIPs: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
            domains: /[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
            urls: /https?:\/\/[^\s<>"{}|\\^`[\]]+/g,
            ports: /:\d{2,5}/g,
            protocols: /http|https|ftp|tcp|udp|icmp/gi
        };

        const indicators = {};
        
        Object.entries(c2Indicators).forEach(([type, pattern]) => {
            const matches = textContent.match(pattern);
            if (matches) {
                indicators[type] = [...new Set(matches)];
            }
        });

        return indicators;
    }

    detectLateralMovement(textContent) {
        const lateralMovementPatterns = {
            networkScanning: /nmap|masscan|zmap|net.*scan|port.*scan/gi,
            credentialDumping: /mimikatz|procdump|lsass|credential|hash/gi,
            remoteExecution: /psexec|wmiexec|smbexec|dcom/gi,
            passTheHash: /pth|pass.*hash|overpass.*hash/gi,
            serviceAbuse: /sc.*create|net.*start|service.*create/gi
        };

        const detected = {};
        
        Object.entries(lateralMovementPatterns).forEach(([technique, pattern]) => {
            const matches = textContent.match(pattern);
            if (matches) {
                detected[technique] = {
                    pattern: pattern.source,
                    matches: matches.length,
                    samples: matches.slice(0, 3)
                };
            }
        });

        return detected;
    }

    detectDefenseEvasion(textContent) {
        const evasionTechniques = {
            obfuscation: /base64|hex|unicode|rot13|atob|btoa/gi,
            packing: /upx|themida|vmprotect|enigma/gi,
            processHiding: /hideproc|runas|impersonate/gi,
            fileDeletion: /deletefile|removefile|self.*delete/gi,
            logClearing: /clear.*log|delete.*log|wevtutil/gi,
            timestampModification: /setfiletime|modify.*time/gi
        };

        const detected = {};
        
        Object.entries(evasionTechniques).forEach(([technique, pattern]) => {
            const matches = textContent.match(pattern);
            if (matches) {
                detected[technique] = {
                    pattern: pattern.source,
                    matches: matches.length,
                    samples: matches.slice(0, 3)
                };
            }
        });

        return detected;
    }

    generateBehaviorReport(analysis) {
        const report = {
            summary: {
                severity: analysis.severity,
                riskScore: analysis.riskScore,
                totalBehaviors: analysis.summary.totalBehaviors,
                behaviorTags: analysis.behaviorTags
            },
            detailedBehaviors: {},
            threatAssessment: this.assessThreatLevel(analysis),
            mitigationSteps: this.getMitigationSteps(analysis),
            iocSummary: this.extractBehaviorIOCs(analysis)
        };

        // Add detailed behavior analysis
        Object.entries(analysis.behaviors).forEach(([category, behavior]) => {
            if (behavior.matches.length > 0) {
                report.detailedBehaviors[category] = {
                    riskScore: behavior.riskScore,
                    confidence: behavior.confidence,
                    matches: behavior.matches.map(match => ({
                        pattern: match.pattern,
                        severity: match.severity,
                        description: match.description,
                        matchCount: match.matchCount
                    }))
                };
            }
        });

        return report;
    }

    assessThreatLevel(analysis) {
        const { severity, behaviorTags, riskScore } = analysis;
        
        if (severity === 'critical') {
            return {
                level: 'Critical',
                description: 'File exhibits critical malicious behaviors. Immediate action required.',
                impact: 'High - System compromise, data loss, or service disruption likely',
                urgency: 'Immediate'
            };
        } else if (severity === 'high') {
            return {
                level: 'High',
                description: 'File exhibits dangerous behaviors requiring urgent attention.',
                impact: 'Medium-High - System compromise or data loss possible',
                urgency: 'Urgent'
            };
        } else if (severity === 'medium') {
            return {
                level: 'Medium',
                description: 'File exhibits suspicious behaviors that warrant investigation.',
                impact: 'Medium - Potential security risk',
                urgency: 'Medium'
            };
        } else {
            return {
                level: 'Low',
                description: 'File shows minimal suspicious behaviors.',
                impact: 'Low - Minimal security risk',
                urgency: 'Low'
            };
        }
    }

    getMitigationSteps(analysis) {
        const steps = [];
        const { behaviorTags } = analysis;

        if (behaviorTags.includes('ransomware')) {
            steps.push('Isolate affected system from network');
            steps.push('Disconnect from all network shares');
            steps.push('Initiate incident response procedures');
        }

        if (behaviorTags.includes('keylogger')) {
            steps.push('Change all user passwords');
            steps.push('Enable two-factor authentication');
            steps.push('Scan for credential compromise');
        }

        if (behaviorTags.includes('persistence')) {
            steps.push('Check system startup locations');
            steps.push('Review scheduled tasks and services');
            steps.push('Scan registry for persistence mechanisms');
        }

        if (behaviorTags.includes('dataExfiltration')) {
            steps.push('Monitor network traffic for data transfers');
            steps.push('Review access logs for unusual activity');
            steps.push('Implement data loss prevention measures');
        }

        if (steps.length === 0) {
            steps.push('Monitor system activity');
            steps.push('Keep antivirus definitions updated');
            steps.push('Educate users about security best practices');
        }

        return steps;
    }

    extractBehaviorIOCs(analysis) {
        const iocs = {
            behaviors: [],
            patterns: [],
            recommendations: []
        };

        Object.entries(analysis.behaviors).forEach(([category, behavior]) => {
            behavior.matches.forEach(match => {
                iocs.behaviors.push({
                    category: category,
                    pattern: match.pattern,
                    severity: match.severity,
                    samples: match.samples
                });
            });
        });

        iocs.recommendations = analysis.recommendations.map(rec => ({
            priority: rec.priority,
            title: rec.title,
            actions: rec.actions
        }));

        return iocs;
    }

    // Utility methods
    addBehaviorPattern(category, pattern, severity, name, description) {
        if (!this.behaviorPatterns[category]) {
            this.behaviorPatterns[category] = [];
        }

        this.behaviorPatterns[category].push({
            pattern: pattern,
            severity: severity,
            name: name,
            description: description
        });
    }

    removeBehaviorPattern(category, patternName) {
        if (this.behaviorPatterns[category]) {
            const index = this.behaviorPatterns[category].findIndex(p => p.name === patternName);
            if (index !== -1) {
                this.behaviorPatterns[category].splice(index, 1);
                return true;
            }
        }
        return false;
    }

    getBehaviorPatternStats() {
        const stats = {
            totalPatterns: 0,
            categories: {}
        };

        Object.entries(this.behaviorPatterns).forEach(([category, patterns]) => {
            stats.categories[category] = patterns.length;
            stats.totalPatterns += patterns.length;
        });

        return stats;
    }
}

module.exports = BehaviorAnalysisService;
