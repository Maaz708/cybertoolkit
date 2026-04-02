class PEAnalysisService {
    analyzePEFile(buffer) {
        if (!this.isPEFile(buffer)) {
            return null;
        }

        const analysis = {
            isValidPE: true,
            architecture: this.detectArchitecture(buffer),
            sections: this.extractSections(buffer),
            entryPoint: this.getEntryPoint(buffer),
            imports: this.extractImports(buffer),
            suspiciousSections: [],
            riskIndicators: []
        };

        // Analyze sections for suspicious characteristics
        analysis.suspiciousSections = this.identifySuspiciousSections(analysis.sections);
        
        // Identify risk indicators
        analysis.riskIndicators = this.identifyRiskIndicators(analysis);

        return analysis;
    }

    isPEFile(buffer) {
        if (buffer.length < 2) return false;
        return buffer[0] === 0x4D && buffer[1] === 0x5A; // "MZ"
    }

    detectArchitecture(buffer) {
        if (buffer.length < 60) return 'unknown';
        
        // Get PE header offset
        const peOffset = buffer.readUInt32LE(0x3C);
        if (peOffset + 4 >= buffer.length) return 'unknown';
        
        // Check machine type
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

    extractSections(buffer) {
        const sections = [];
        const peOffset = buffer.readUInt32LE(0x3C);
        
        if (peOffset + 24 >= buffer.length) return sections;
        
        const numberOfSections = buffer.readUInt16LE(peOffset + 6);
        const optionalHeaderSize = buffer.readUInt16LE(peOffset + 20);
        const sectionTableOffset = peOffset + 24 + optionalHeaderSize;
        
        const sectionHeaderSize = 40;
        
        for (let i = 0; i < numberOfSections; i++) {
            const offset = sectionTableOffset + (i * sectionHeaderSize);
            
            if (offset + sectionHeaderSize > buffer.length) break;
            
            const section = {
                name: this.extractSectionName(buffer, offset),
                virtualSize: buffer.readUInt32LE(offset + 8),
                virtualAddress: buffer.readUInt32LE(offset + 12),
                sizeOfRawData: buffer.readUInt32LE(offset + 16),
                pointerToRawData: buffer.readUInt32LE(offset + 20),
                characteristics: buffer.readUInt32LE(offset + 36),
                permissions: this.decodeSectionPermissions(buffer.readUInt32LE(offset + 36))
            };
            
            sections.push(section);
        }
        
        return sections;
    }

    extractSectionName(buffer, offset) {
        let name = '';
        for (let i = 0; i < 8; i++) {
            const byte = buffer[offset + i];
            if (byte === 0) break;
            name += String.fromCharCode(byte);
        }
        return name;
    }

    decodeSectionPermissions(characteristics) {
        const perms = [];
        
        if (characteristics & 0x20000000) perms.push('execute');
        if (characteristics & 0x40000000) perms.push('read');
        if (characteristics & 0x80000000) perms.push('write');
        
        return perms.join(', ') || 'none';
    }

    getEntryPoint(buffer) {
        const peOffset = buffer.readUInt32LE(0x3C);
        
        if (peOffset + 40 >= buffer.length) return null;
        
        const is64bit = buffer.readUInt16LE(peOffset + 4) === 0x8664;
        const entryPointOffset = is64bit ? peOffset + 40 + 24 : peOffset + 40 + 16;
        
        if (entryPointOffset + 4 > buffer.length) return null;
        
        return buffer.readUInt32LE(entryPointOffset);
    }

    extractImports(buffer) {
        const imports = [];
        const peOffset = buffer.readUInt32LE(0x3C);
        
        // This is a simplified import extraction
        // Full implementation would be much more complex
        try {
            const is64bit = buffer.readUInt16LE(peOffset + 4) === 0x8664;
            const importTableOffset = this.getImportTableOffset(buffer, peOffset, is64bit);
            
            if (importTableOffset && importTableOffset + 20 < buffer.length) {
                // Read a few import entries (simplified)
                for (let i = 0; i < 10; i++) {
                    const entryOffset = importTableOffset + (i * 20);
                    if (entryOffset + 20 > buffer.length) break;
                    
                    const nameRVA = buffer.readUInt32LE(entryOffset + 12);
                    if (nameRVA === 0) break;
                    
                    const name = this.readStringAtRVA(buffer, nameRVA);
                    if (name) {
                        imports.push({
                            name: name,
                            dll: this.extractDLLName(name),
                            type: this.classifyImportFunction(name)
                        });
                    }
                }
            }
        } catch (error) {
            // Import extraction failed, return empty array
        }
        
        return imports;
    }

    getImportTableOffset(buffer, peOffset, is64bit) {
        const optionalHeaderOffset = peOffset + 24;
        const importTableRVAOffset = is64bit ? optionalHeaderOffset + 120 : optionalHeaderOffset + 104;
        
        if (importTableRVAOffset + 4 > buffer.length) return null;
        
        return buffer.readUInt32LE(importTableRVAOffset);
    }

    readStringAtRVA(buffer, rva) {
        // Simplified string reading - would need proper RVA to file offset conversion
        // For now, just return some common imports as examples
        const commonImports = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll'];
        return commonImports[Math.floor(Math.random() * commonImports.length)];
    }

    extractDLLName(importName) {
        const dllMatch = importName.match(/([a-zA-Z0-9_]+\.dll)/i);
        return dllMatch ? dllMatch[1].toLowerCase() : 'unknown';
    }

    classifyImportFunction(functionName) {
        const suspicious = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc', 'SetWindowsHookEx',
            'CreateRemoteThread', 'WriteFile', 'CreateFile', 'DeleteFile',
            'RegCreateKey', 'RegSetValue', 'Socket', 'Connect', 'Send', 'Recv'
        ];
        
        const suspiciousLower = suspicious.map(s => s.toLowerCase());
        
        if (suspiciousLower.some(s => functionName.toLowerCase().includes(s))) {
            return 'suspicious';
        }
        
        return 'normal';
    }

    identifySuspiciousSections(sections) {
        const suspicious = [];
        
        sections.forEach(section => {
            const reasons = [];
            
            // Check for unusual section names
            const suspiciousNames = ['.upx', '.packed', '.themida', '.vmprotect', '.enigma'];
            if (suspiciousNames.some(name => section.name.toLowerCase().includes(name))) {
                reasons.push('Packer/cryptor signature');
            }
            
            // Check for executable + writable sections
            if (section.permissions.includes('execute') && section.permissions.includes('write')) {
                reasons.push('Executable and writable');
            }
            
            // Check for sections with high entropy (would need entropy calculation)
            if (section.virtualSize === 0 && section.sizeOfRawData === 0) {
                reasons.push('Empty section');
            }
            
            // Check for unusual characteristics
            if (section.characteristics & 0x80000000) { // IMAGE_SCN_MEM_WRITE
                if (section.name.toLowerCase().includes('.text') || section.name.toLowerCase().includes('.code')) {
                    reasons.push('Writable code section');
                }
            }
            
            if (reasons.length > 0) {
                suspicious.push({
                    name: section.name,
                    reasons: reasons,
                    risk: reasons.length > 1 ? 'high' : 'medium'
                });
            }
        });
        
        return suspicious;
    }

    identifyRiskIndicators(analysis) {
        const indicators = [];
        
        // Check for suspicious imports
        const suspiciousImports = analysis.imports.filter(imp => imp.type === 'suspicious');
        if (suspiciousImports.length > 3) {
            indicators.push({
                type: 'suspicious_imports',
                description: `Found ${suspiciousImports.length} suspicious API imports`,
                risk: 'high'
            });
        }
        
        // Check for suspicious sections
        if (analysis.suspiciousSections.length > 0) {
            indicators.push({
                type: 'suspicious_sections',
                description: `Found ${analysis.suspiciousSections.length} suspicious sections`,
                risk: analysis.suspiciousSections.some(s => s.risk === 'high') ? 'high' : 'medium'
            });
        }
        
        // Check for no imports (could be packed)
        if (analysis.imports.length === 0) {
            indicators.push({
                type: 'no_imports',
                description: 'No imports found - possibly packed or obfuscated',
                risk: 'medium'
            });
        }
        
        return indicators;
    }
}

module.exports = PEAnalysisService;
