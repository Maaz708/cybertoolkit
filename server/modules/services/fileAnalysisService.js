const fs = require('fs');
const path = require('path');

class FileAnalysisService {
    constructor() {
        this.signaturesData = null;
        this.loadSignaturesData();
        this.initializeMagicBytes();
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

    initializeMagicBytes() {
        this.magicBytes = {
            // Images
            'image/png': Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            'image/jpeg': Buffer.from([0xFF, 0xD8, 0xFF]),
            'image/gif': Buffer.from([0x47, 0x49, 0x46, 0x38]),
            'image/bmp': Buffer.from([0x42, 0x4D]),
            
            // Archives
            'application/zip': Buffer.from([0x50, 0x4B, 0x03, 0x04]),
            'application/x-rar-compressed': Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            'application/x-7z-compressed': Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            'application/gzip': Buffer.from([0x1F, 0x8B, 0x08]),
            
            // Documents
            'application/pdf': Buffer.from([0x25, 0x50, 0x44, 0x46]),
            'application/msword': Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': Buffer.from([0x50, 0x4B, 0x03, 0x04]),
            
            // Executables
            'application/x-dosexec': Buffer.from([0x4D, 0x5A]),
            'application/x-executable': Buffer.from([0x7F, 0x45, 0x4C, 0x46]),
            'application/x-mach-binary': Buffer.from([0xFE, 0xED, 0xFA, 0xCE]),
            
            // Scripts
            'text/plain': Buffer.from([]), // No magic bytes for text
            'application/javascript': Buffer.from([]),
            'text/html': Buffer.from([])
        };

        this.extensionMap = {
            'exe': 'application/x-dosexec',
            'dll': 'application/x-dosexec',
            'elf': 'application/x-executable',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            '7z': 'application/x-7z-compressed',
            'gz': 'application/gzip',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'js': 'application/javascript',
            'html': 'text/html',
            'htm': 'text/html',
            'php': 'application/x-httpd-php',
            'py': 'text/x-python',
            'bat': 'text/plain',
            'cmd': 'text/plain',
            'ps1': 'text/plain',
            'vbs': 'text/plain',
            'scr': 'text/plain'
        };
    }

    getFileRiskProfile(extension) {
        // Get risk profiles from signatures.json
        if (this.signaturesData && this.signaturesData.file_risk_profiles) {
            const profiles = this.signaturesData.file_risk_profiles;
            const ext = extension.toLowerCase();
            return profiles[ext] || 'medium';
        }

        // Default risk profiles
        const defaultProfiles = {
            'exe': 'high',
            'dll': 'high',
            'scr': 'high',
            'bat': 'medium',
            'cmd': 'medium',
            'ps1': 'medium',
            'vbs': 'medium',
            'js': 'medium',
            'pdf': 'medium',
            'zip': 'medium',
            'rar': 'medium',
            '7z': 'medium',
            'doc': 'medium',
            'docx': 'medium',
            'txt': 'low',
            'jpg': 'low',
            'jpeg': 'low',
            'png': 'low',
            'gif': 'low',
            'bmp': 'low'
        };

        return defaultProfiles[extension.toLowerCase()] || 'medium';
    }

    analyzeFileType(buffer, filename) {
        const analysis = {
            detectedType: this.detectRealFileType(buffer),
            extension: this.extractExtension(filename),
            isValid: true,
            risk: 'low',
            description: 'File type matches extension'
        };

        // Get file risk profile from signatures.json
        const fileRiskProfile = this.getFileRiskProfile(analysis.extension);
        analysis.risk = fileRiskProfile;

        // Validate file type against extension
        const validation = this.validateFileType(buffer, filename);
        analysis.isValid = validation.isValid;
        if (validation.risk !== 'low') {
            analysis.risk = validation.risk;
            analysis.description = validation.description;
        }

        // Perform deep analysis based on file type
        analysis.deepAnalysis = this.performDeepAnalysis(buffer, analysis.detectedType.mimeType);

        // Update risk based on deep analysis
        if (analysis.deepAnalysis && analysis.deepAnalysis.risk !== 'low') {
            const riskLevels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
            const currentRisk = riskLevels[analysis.risk] || 1;
            const deepRisk = riskLevels[analysis.deepAnalysis.risk] || 1;
            
            if (deepRisk > currentRisk) {
                analysis.risk = analysis.deepAnalysis.risk;
            }
        }

        return analysis;
    }

    detectRealFileType(buffer) {
        const detected = {
            mimeType: 'application/octet-stream',
            confidence: 0,
            description: 'Unknown file type',
            signature: null
        };

        for (const [mimeType, magicBytes] of Object.entries(this.magicBytes)) {
            if (magicBytes.length === 0) continue; // Skip text files
            
            if (buffer.length >= magicBytes.length && 
                buffer.slice(0, magicBytes.length).equals(magicBytes)) {
                detected.mimeType = mimeType;
                detected.confidence = 1.0;
                detected.description = this.getMimeTypeDescription(mimeType);
                detected.signature = magicBytes.toString('hex');
                break;
            }
        }

        // Additional checks for text-based files
        if (detected.mimeType === 'application/octet-stream') {
            if (this.isTextFile(buffer)) {
                detected.mimeType = 'text/plain';
                detected.confidence = 0.8;
                detected.description = 'Text file';
            }
        }

        return detected;
    }

    getMimeTypeDescription(mimeType) {
        const descriptions = {
            'image/png': 'PNG image',
            'image/jpeg': 'JPEG image',
            'image/gif': 'GIF image',
            'image/bmp': 'Bitmap image',
            'application/zip': 'ZIP archive',
            'application/x-rar-compressed': 'RAR archive',
            'application/x-7z-compressed': '7-Zip archive',
            'application/gzip': 'GZIP archive',
            'application/pdf': 'PDF document',
            'application/msword': 'Microsoft Word document',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'Microsoft Word document (OOXML)',
            'application/x-dosexec': 'Windows executable',
            'application/x-executable': 'Linux/Unix executable',
            'application/x-mach-binary': 'macOS executable',
            'application/javascript': 'JavaScript file',
            'text/html': 'HTML document',
            'text/plain': 'Plain text'
        };

        return descriptions[mimeType] || 'Unknown file type';
    }

    isTextFile(buffer) {
        const sample = buffer.slice(0, 1024);
        let textBytes = 0;
        
        for (let i = 0; i < sample.length; i++) {
            const byte = sample[i];
            // Printable ASCII, tab, newline, carriage return
            if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
                textBytes++;
            }
        }
        
        return (textBytes / sample.length) > 0.95;
    }

    validateFileType(buffer, filename) {
        const extension = this.extractExtension(filename);
        const expectedMime = this.extensionMap[extension];
        const detected = this.detectRealFileType(buffer);
        
        const validation = {
            extension: extension,
            expectedMimeType: expectedMime || null,
            detectedMimeType: detected.mimeType,
            isValid: true,
            risk: 'low',
            description: 'File type matches extension'
        };

        if (expectedMime && detected.mimeType !== expectedMime) {
            validation.isValid = false;
            validation.risk = 'high';
            validation.description = `File type mismatch: expected ${expectedMime}, detected ${detected.mimeType}`;
        }

        // Special case: executables disguised as images
        if (['jpg', 'jpeg', 'png', 'gif', 'bmp'].includes(extension) && 
            detected.mimeType.startsWith('application/')) {
            validation.isValid = false;
            validation.risk = 'critical';
            validation.description = `Executable disguised as image file`;
        }

        // Special case: scripts disguised as documents
        if (['pdf', 'doc', 'docx'].includes(extension) && 
            (detected.mimeType.includes('javascript') || detected.mimeType.includes('text'))) {
            validation.isValid = false;
            validation.risk = 'critical';
            validation.description = `Script disguised as document file`;
        }

        return validation;
    }

    performDeepAnalysis(buffer, mimeType) {
        const analysis = {
            type: 'basic',
            details: {},
            risk: 'low'
        };

        switch (mimeType) {
            case 'application/x-dosexec':
                analysis.type = 'pe';
                analysis.details = this.analyzePEFile(buffer);
                analysis.risk = this.assessPERisk(analysis.details);
                break;
                
            case 'application/pdf':
                analysis.type = 'pdf';
                analysis.details = this.analyzePDFFile(buffer);
                analysis.risk = this.assessPDFRisk(analysis.details);
                break;
                
            case 'application/zip':
            case 'application/x-rar-compressed':
            case 'application/x-7z-compressed':
                analysis.type = 'archive';
                analysis.details = this.analyzeArchiveFile(buffer);
                analysis.risk = this.assessArchiveRisk(analysis.details);
                break;
                
            case 'application/javascript':
            case 'text/html':
                analysis.type = 'script';
                analysis.details = this.analyzeScriptFile(buffer);
                analysis.risk = this.assessScriptRisk(analysis.details);
                break;
        }

        return analysis;
    }

    analyzePEFile(buffer) {
        const analysis = {
            isValidPE: false,
            architecture: 'unknown',
            sections: [],
            imports: [],
            entryPoint: null,
            suspiciousAPIs: [],
            packingIndicators: []
        };

        if (buffer.length < 2) return analysis;
        if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) return analysis; // Not "MZ"

        analysis.isValidPE = true;
        analysis.architecture = this.detectPEArchitecture(buffer);
        analysis.sections = this.extractPESections(buffer);
        analysis.imports = this.extractPEImports(buffer);
        analysis.entryPoint = this.getPEEntryPoint(buffer);
        
        // Check for suspicious APIs
        analysis.suspiciousAPIs = this.findSuspiciousPEAPIs(analysis.imports);
        
        // Check for packing indicators
        analysis.packingIndicators = this.detectPEPacking(analysis.sections, analysis.imports);

        return analysis;
    }

    detectPEArchitecture(buffer) {
        if (buffer.length < 60) return 'unknown';
        
        const peOffset = buffer.readUInt32LE(0x3C);
        if (peOffset + 4 >= buffer.length) return 'unknown';
        
        const machine = buffer.readUInt16LE(peOffset + 4);
        
        const machines = {
            0x014c: 'x86 (32-bit)',
            0x0200: 'IA64',
            0x8664: 'x64 (64-bit)',
            0x01c0: 'ARM',
            0xaa64: 'ARM64'
        };

        return machines[machine] || `unknown (0x${machine.toString(16)})`;
    }

    extractPESections(buffer) {
        const sections = [];
        const peOffset = buffer.readUInt32LE(0x3C);
        
        if (peOffset + 24 >= buffer.length) return sections;
        
        const numberOfSections = buffer.readUInt16LE(peOffset + 6);
        const optionalHeaderSize = buffer.readUInt16LE(peOffset + 20);
        const sectionTableOffset = peOffset + 24 + optionalHeaderSize;
        
        const sectionHeaderSize = 40;
        
        for (let i = 0; i < Math.min(numberOfSections, 20); i++) {
            const offset = sectionTableOffset + (i * sectionHeaderSize);
            
            if (offset + sectionHeaderSize > buffer.length) break;
            
            const section = {
                name: this.extractPESectionName(buffer, offset),
                virtualSize: buffer.readUInt32LE(offset + 8),
                virtualAddress: buffer.readUInt32LE(offset + 12),
                sizeOfRawData: buffer.readUInt32LE(offset + 16),
                characteristics: buffer.readUInt32LE(offset + 36),
                permissions: this.decodePESectionPermissions(buffer.readUInt32LE(offset + 36))
            };
            
            sections.push(section);
        }
        
        return sections;
    }

    extractPESectionName(buffer, offset) {
        let name = '';
        for (let i = 0; i < 8; i++) {
            const byte = buffer[offset + i];
            if (byte === 0) break;
            name += String.fromCharCode(byte);
        }
        return name;
    }

    decodePESectionPermissions(characteristics) {
        const perms = [];
        
        if (characteristics & 0x20000000) perms.push('execute');
        if (characteristics & 0x40000000) perms.push('read');
        if (characteristics & 0x80000000) perms.push('write');
        
        return perms.join(', ') || 'none';
    }

    extractPEImports(buffer) {
        const imports = [];
        const peOffset = buffer.readUInt32LE(0x3C);
        
        try {
            const is64bit = buffer.readUInt16LE(peOffset + 4) === 0x8664;
            const importTableOffset = this.getPEImportTableOffset(buffer, peOffset, is64bit);
            
            if (importTableOffset && importTableOffset + 20 < buffer.length) {
                // Read a few import entries (simplified)
                for (let i = 0; i < 10; i++) {
                    const entryOffset = importTableOffset + (i * 20);
                    if (entryOffset + 20 > buffer.length) break;
                    
                    const nameRVA = buffer.readUInt32LE(entryOffset + 12);
                    if (nameRVA === 0) break;
                    
                    const name = this.readPEStringAtRVA(buffer, nameRVA);
                    if (name) {
                        imports.push({
                            name: name,
                            dll: this.extractPEDLLName(name),
                            type: this.classifyPEImportFunction(name)
                        });
                    }
                }
            }
        } catch (error) {
            // Import extraction failed
        }
        
        return imports;
    }

    getPEImportTableOffset(buffer, peOffset, is64bit) {
        const optionalHeaderOffset = peOffset + 24;
        const importTableRVAOffset = is64bit ? optionalHeaderOffset + 120 : optionalHeaderOffset + 104;
        
        if (importTableRVAOffset + 4 > buffer.length) return null;
        
        return buffer.readUInt32LE(importTableRVAOffset);
    }

    readPEStringAtRVA(buffer, rva) {
        // Simplified string reading - would need proper RVA to file offset conversion
        const commonImports = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll', 'shell32.dll'];
        return commonImports[Math.floor(Math.random() * commonImports.length)];
    }

    extractPEDLLName(importName) {
        const dllMatch = importName.match(/([a-zA-Z0-9_]+\.dll)/i);
        return dllMatch ? dllMatch[1].toLowerCase() : 'unknown';
    }

    classifyPEImportFunction(functionName) {
        const suspicious = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 'SetWindowsHookEx',
            'CreateRemoteThread', 'WriteFile', 'CreateFile', 'DeleteFile',
            'RegCreateKey', 'RegSetValue', 'Socket', 'Connect', 'Send', 'Recv',
            'URLDownloadToFile', 'InternetOpenUrl', 'WinExec', 'ShellExecute'
        ];
        
        const suspiciousLower = suspicious.map(s => s.toLowerCase());
        
        if (suspiciousLower.some(s => functionName.toLowerCase().includes(s))) {
            return 'suspicious';
        }
        
        return 'normal';
    }

    getPEEntryPoint(buffer) {
        const peOffset = buffer.readUInt32LE(0x3C);
        
        if (peOffset + 40 >= buffer.length) return null;
        
        const is64bit = buffer.readUInt16LE(peOffset + 4) === 0x8664;
        const entryPointOffset = is64bit ? peOffset + 40 + 24 : peOffset + 40 + 16;
        
        if (entryPointOffset + 4 > buffer.length) return null;
        
        return buffer.readUInt32LE(entryPointOffset);
    }

    findSuspiciousPEAPIs(imports) {
        return imports.filter(imp => imp.type === 'suspicious');
    }

    detectPEPacking(sections, imports) {
        const indicators = [];
        
        // Check for unusual section names
        const suspiciousNames = ['.upx', '.packed', '.themida', '.vmprotect', '.enigma'];
        sections.forEach(section => {
            if (suspiciousNames.some(name => section.name.toLowerCase().includes(name))) {
                indicators.push({
                    type: 'suspicious_section',
                    name: section.name,
                    description: `Packer/cryptor signature detected: ${section.name}`
                });
            }
        });
        
        // Check for executable + writable sections
        sections.forEach(section => {
            if (section.permissions.includes('execute') && section.permissions.includes('write')) {
                indicators.push({
                    type: 'writable_executable',
                    name: section.name,
                    description: `Writable and executable section: ${section.name}`
                });
            }
        });
        
        // Check for no imports (possibly packed)
        if (imports.length === 0) {
            indicators.push({
                type: 'no_imports',
                name: 'No Imports',
                description: 'No imports found - possibly packed or obfuscated'
            });
        }
        
        return indicators;
    }

    assessPERisk(analysis) {
        let risk = 'low';
        
        if (analysis.suspiciousAPIs.length > 0) {
            risk = analysis.suspiciousAPIs.length > 3 ? 'high' : 'medium';
        }
        
        if (analysis.packingIndicators.length > 0) {
            risk = analysis.packingIndicators.some(ind => ind.type === 'writable_executable') ? 'critical' : 'high';
        }
        
        return risk;
    }

    analyzePDFFile(buffer) {
        const analysis = {
            isValidPDF: false,
            version: null,
            hasJavaScript: false,
            hasAutoAction: false,
            embeddedFiles: [],
            suspiciousObjects: []
        };

        const textContent = buffer.toString('latin1');
        
        // Check PDF signature
        if (!textContent.startsWith('%PDF-')) {
            return analysis;
        }
        
        analysis.isValidPDF = true;
        
        // Extract version
        const versionMatch = textContent.match(/%PDF-(\d+\.\d+)/);
        if (versionMatch) {
            analysis.version = versionMatch[1];
        }
        
        // Check for JavaScript
        if (/\/JS\s*|\/JavaScript\s*|JavaScript\s*\(/i.test(textContent)) {
            analysis.hasJavaScript = true;
            analysis.suspiciousObjects.push({
                type: 'javascript',
                description: 'JavaScript code found in PDF'
            });
        }
        
        // Check for auto-execution
        if (/\/OpenAction\s*|\/AA\s*|\/Launch\s*/i.test(textContent)) {
            analysis.hasAutoAction = true;
            analysis.suspiciousObjects.push({
                type: 'auto_action',
                description: 'Auto-execution action found in PDF'
            });
        }
        
        // Check for embedded files
        const embeddedFileMatches = textContent.match(/\/EF\s*\s*<<.*?>>/gs);
        if (embeddedFileMatches) {
            analysis.embeddedFiles = embeddedFileMatches.map((match, index) => ({
                index: index,
                snippet: match.substring(0, 100) + '...'
            }));
            
            if (analysis.embeddedFiles.length > 0) {
                analysis.suspiciousObjects.push({
                    type: 'embedded_files',
                    description: `${analysis.embeddedFiles.length} embedded files found`
                });
            }
        }
        
        return analysis;
    }

    assessPDFRisk(analysis) {
        let risk = 'low';
        
        if (analysis.hasJavaScript) {
            risk = 'medium';
        }
        
        if (analysis.hasAutoAction) {
            risk = 'high';
        }
        
        if (analysis.embeddedFiles.length > 0) {
            risk = analysis.embeddedFiles.length > 2 ? 'high' : 'medium';
        }
        
        if (analysis.hasJavaScript && analysis.hasAutoAction) {
            risk = 'critical';
        }
        
        return risk;
    }

    analyzeArchiveFile(buffer) {
        const analysis = {
            type: 'unknown',
            fileCount: 0,
            hasNestedArchives: false,
            hasEncryptedFiles: false,
            compressionRatio: 0,
            suspiciousFiles: []
        };

        // Basic archive analysis (simplified)
        if (buffer.length >= 4) {
            const header = buffer.slice(0, 4).toString('hex');
            
            if (header.startsWith('504b')) { // ZIP
                analysis.type = 'zip';
                // Simplified ZIP analysis
                analysis.fileCount = this.countZipFiles(buffer);
            } else if (header.startsWith('5261')) { // RAR
                analysis.type = 'rar';
                analysis.fileCount = 1; // Simplified
            } else if (header.startsWith('377a')) { // 7Z
                analysis.type = '7z';
                analysis.fileCount = 1; // Simplified
            }
        }

        // Calculate compression ratio (simplified)
        analysis.compressionRatio = this.calculateCompressionRatio(buffer);

        return analysis;
    }

    countZipFiles(buffer) {
        // Simplified ZIP file counting
        const textContent = buffer.toString('latin1');
        const fileHeaderMatches = textContent.match(/PK\x03\x04/g);
        return fileHeaderMatches ? fileHeaderMatches.length : 0;
    }

    calculateCompressionRatio(buffer) {
        // Simplified compression ratio calculation
        // This would need proper archive parsing for accurate results
        return Math.random() * 10; // Placeholder
    }

    assessArchiveRisk(analysis) {
        let risk = 'low';
        
        if (analysis.fileCount > 50) {
            risk = 'medium';
        }
        
        if (analysis.hasNestedArchives) {
            risk = 'high';
        }
        
        if (analysis.hasEncryptedFiles) {
            risk = 'high';
        }
        
        if (analysis.compressionRatio > 100) {
            risk = 'high'; // Potential zip bomb
        }
        
        return risk;
    }

    analyzeScriptFile(buffer) {
        const analysis = {
            language: 'unknown',
            hasObfuscation: false,
            hasNetworkCalls: false,
            hasFileOperations: false,
            suspiciousPatterns: []
        };

        const textContent = buffer.toString('utf8');
        
        // Detect language
        if (textContent.includes('function') || textContent.includes('var ') || textContent.includes('let ')) {
            analysis.language = 'javascript';
        } else if (textContent.includes('#!/usr/bin/python') || textContent.includes('def ') || textContent.includes('import ')) {
            analysis.language = 'python';
        } else if (textContent.includes('<!DOCTYPE') || textContent.includes('<html')) {
            analysis.language = 'html';
        }

        // Check for obfuscation
        if (/eval\s*\(|atob\s*\(|\\x[0-9a-fA-F]{2}/g.test(textContent)) {
            analysis.hasObfuscation = true;
            analysis.suspiciousPatterns.push('obfuscation');
        }

        // Check for network calls
        if (/fetch\s*\(|XMLHttpRequest|socket\s*\(|connect\s*\(/g.test(textContent)) {
            analysis.hasNetworkCalls = true;
            analysis.suspiciousPatterns.push('network_calls');
        }

        // Check for file operations
        if (/fopen|fwrite|FileWriter|createObject|ActiveXObject/g.test(textContent)) {
            analysis.hasFileOperations = true;
            analysis.suspiciousPatterns.push('file_operations');
        }

        return analysis;
    }

    assessScriptRisk(analysis) {
        let risk = 'low';
        
        if (analysis.hasObfuscation) {
            risk = 'medium';
        }
        
        if (analysis.hasNetworkCalls) {
            risk = 'medium';
        }
        
        if (analysis.hasFileOperations) {
            risk = 'medium';
        }
        
        if (analysis.suspiciousPatterns.length > 2) {
            risk = 'high';
        }
        
        return risk;
    }

    extractExtension(filename) {
        if (!filename) return '';
        const parts = filename.toLowerCase().split('.');
        return parts.length > 1 ? parts[parts.length - 1] : '';
    }
}

module.exports = FileAnalysisService;
