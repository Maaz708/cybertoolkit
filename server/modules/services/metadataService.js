const fs = require('fs');

class MetadataService {
    extractMetadata(filename, buffer) {
        const metadata = {
            fileSignature: this.extractFileSignature(buffer),
            encoding: this.detectEncoding(buffer),
            possibleOrigin: this.analyzePossibleOrigin(buffer, filename),
            creationInfo: this.extractCreationInfo(filename),
            structureInfo: this.analyzeFileStructure(buffer)
        };

        return metadata;
    }

    extractFileSignature(buffer) {
        if (buffer.length < 16) return null;
        
        const signature = {
            hex: buffer.slice(0, 16).toString('hex'),
            ascii: this.bufferToASCII(buffer.slice(0, 16)),
            description: 'Unknown'
        };

        const signatures = {
            '4d5a': 'PE/Windows executable',
            '7f454c46': 'ELF/Linux executable',
            'cafebabe': 'Java class file',
            '89504e47': 'PNG image',
            'ffd8ff': 'JPEG image',
            '504b0304': 'ZIP archive',
            '52617221': 'RAR archive',
            '1f8b08': 'GZIP archive',
            '25504446': 'PDF document',
            'd0cf11e0': 'Microsoft Office document'
        };

        const hexLower = signature.hex.toLowerCase();
        for (const [sig, desc] of Object.entries(signatures)) {
            if (hexLower.startsWith(sig)) {
                signature.description = desc;
                break;
            }
        }

        return signature;
    }

    bufferToASCII(buffer) {
        let ascii = '';
        for (let i = 0; i < buffer.length; i++) {
            const byte = buffer[i];
            if (byte >= 32 && byte <= 126) {
                ascii += String.fromCharCode(byte);
            } else {
                ascii += '.';
            }
        }
        return ascii;
    }

    detectEncoding(buffer) {
        const sample = buffer.slice(0, 1024);
        
        // Check for UTF-8 BOM
        if (sample.length >= 3 && sample[0] === 0xEF && sample[1] === 0xBB && sample[2] === 0xBF) {
            return { type: 'UTF-8 with BOM', confidence: 1.0 };
        }
        
        // Check for UTF-16 LE BOM
        if (sample.length >= 2 && sample[0] === 0xFF && sample[1] === 0xFE) {
            return { type: 'UTF-16 LE', confidence: 1.0 };
        }
        
        // Check for UTF-16 BE BOM
        if (sample.length >= 2 && sample[0] === 0xFE && sample[1] === 0xFF) {
            return { type: 'UTF-16 BE', confidence: 1.0 };
        }
        
        // Analyze byte patterns for encoding detection
        const analysis = this.analyzeBytePatterns(sample);
        
        return {
            type: analysis.encoding,
            confidence: analysis.confidence,
            details: analysis.details
        };
    }

    analyzeBytePatterns(sample) {
        let asciiCount = 0;
        let highByteCount = 0;
        let nullCount = 0;
        
        for (let i = 0; i < sample.length; i++) {
            const byte = sample[i];
            
            if (byte === 0) {
                nullCount++;
            } else if (byte <= 127) {
                asciiCount++;
            } else if (byte >= 128) {
                highByteCount++;
            }
        }
        
        const asciiRatio = asciiCount / sample.length;
        const highByteRatio = highByteCount / sample.length;
        const nullRatio = nullCount / sample.length;
        
        if (asciiRatio > 0.95) {
            return { encoding: 'ASCII/UTF-8', confidence: 0.9, details: 'Mostly ASCII characters' };
        } else if (nullRatio > 0.3 && highByteRatio > 0.3) {
            return { encoding: 'UTF-16', confidence: 0.7, details: 'High null byte and high byte ratio' };
        } else if (highByteRatio > 0.1) {
            return { encoding: 'UTF-8 with multibyte', confidence: 0.6, details: 'Contains multibyte characters' };
        } else {
            return { encoding: 'Binary', confidence: 0.8, details: 'Binary data detected' };
        }
    }

    analyzePossibleOrigin(buffer, filename) {
        const origin = {
            platform: 'unknown',
            compiler: 'unknown',
            possibleTools: [],
            indicators: []
        };

        // Platform detection
        if (buffer.length >= 2) {
            if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
                origin.platform = 'Windows';
                origin.indicators.push('PE signature detected');
            } else if (buffer.length >= 4 && 
                       buffer[0] === 0x7F && buffer[1] === 0x45 && 
                       buffer[2] === 0x4C && buffer[3] === 0x46) {
                origin.platform = 'Linux/Unix';
                origin.indicators.push('ELF signature detected');
            } else if (buffer.length >= 4 && 
                       ((buffer[0] === 0xFE && buffer[1] === 0xED) || 
                        (buffer[0] === 0xCE && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE))) {
                origin.platform = 'macOS';
                origin.indicators.push('Mach-O signature detected');
            }
        }

        // Tool detection (simplified)
        const content = buffer.toString('utf8', 0, Math.min(buffer.length, 10000));
        
        const tools = {
            'UPX': 'UPX Packer',
            'Themida': 'Themida Protector',
'VMProtect': 'VMProtect',
            'Enigma': 'Enigma Protector',
            'AutoIt': 'AutoIt Script',
            'Python': 'Python Interpreter',
            'Node.js': 'Node.js',
            'Java': 'Java Virtual Machine'
        };
        
        for (const [signature, tool] of Object.entries(tools)) {
            if (content.includes(signature)) {
                origin.possibleTools.push(tool);
                origin.indicators.push(`${tool} signature detected`);
            }
        }

        return origin;
    }
    
    extractCreationInfo(filename) {
        const creationInfo = {
            filename: filename,
            extension: require('path').extname(filename).toLowerCase(),
            analyzedAt: new Date().toISOString()
        };

        // Since we're working with buffers, we can't get file system stats
        creationInfo.error = 'File system stats not available for buffer analysis';

        return creationInfo;
    }

    analyzeFileStructure(buffer) {
        const structure = {
            hasPEHeader: false,
            hasELFHeader: false,
            hasMachOHeader: false,
            hasArchiveSignature: false,
            hasScriptSignature: false,
            sections: [],
            resources: []
        };

        // PE header check
        if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
            structure.hasPEHeader = true;
            structure.sections = this.extractPESections(buffer);
        }

        // ELF header check
        if (buffer.length >= 4 && 
            buffer[0] === 0x7F && buffer[1] === 0x45 && 
            buffer[2] === 0x4C && buffer[3] === 0x46) {
            structure.hasELFHeader = true;
        }

        // Mach-O header check
        if (buffer.length >= 4 && 
            ((buffer[0] === 0xFE && buffer[1] === 0xED) || 
             (buffer[0] === 0xCE && buffer[1] === 0xFA && buffer[2] === 0xED && buffer[3] === 0xFE))) {
            structure.hasMachOHeader = true;
        }

        // Archive signatures
        const archiveSigs = {
            'PK': 'ZIP',
            'Rar!': 'RAR',
            '\x1F\x8B': 'GZIP',
            'BZ': 'BZIP2'
        };

        for (const [sig, type] of Object.entries(archiveSigs)) {
            const sigBytes = Buffer.from(sig, 'utf8');
            if (buffer.length >= sigBytes.length && 
                buffer.slice(0, sigBytes.length).equals(sigBytes)) {
                structure.hasArchiveSignature = true;
                structure.resources.push(type + ' archive');
                break;
            }
        }

        // Script signatures
        const scriptPatterns = [
            { pattern: '#!/', name: 'Shell script' },
            { pattern: '<?php', name: 'PHP script' },
            { pattern: '<!DOCTYPE', name: 'HTML document' },
            { pattern: '#!/usr/bin/python', name: 'Python script' },
            { pattern: '#!/usr/bin/env', name: 'Unix script' }
        ];

        const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1000));
        scriptPatterns.forEach(script => {
            if (content.includes(script.pattern)) {
                structure.hasScriptSignature = true;
                structure.resources.push(script.name);
            }
        });

        return structure;
    }

    extractPESections(buffer) {
        const sections = [];
        
        try {
            const peOffset = buffer.readUInt32LE(0x3C);
            if (peOffset + 6 >= buffer.length) return sections;
            
            const numberOfSections = buffer.readUInt16LE(peOffset + 6);
            const optionalHeaderSize = buffer.readUInt16LE(peOffset + 20);
            const sectionTableOffset = peOffset + 24 + optionalHeaderSize;
            
            const sectionHeaderSize = 40;
            
            for (let i = 0; i < Math.min(numberOfSections, 10); i++) {
                const offset = sectionTableOffset + (i * sectionHeaderSize);
                
                if (offset + sectionHeaderSize > buffer.length) break;
                
                let name = '';
                for (let j = 0; j < 8; j++) {
                    const byte = buffer[offset + j];
                    if (byte === 0) break;
                    name += String.fromCharCode(byte);
                }
                
                sections.push({
                    name: name,
                    virtualSize: buffer.readUInt32LE(offset + 8),
                    characteristics: buffer.readUInt32LE(offset + 36)
                });
            }
        } catch (error) {
            // PE section extraction failed
        }
        
        return sections;
    }
}

module.exports = MetadataService;
