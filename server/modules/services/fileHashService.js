const crypto = require('crypto');

class FileHashService {
    calculateHashes(buffer) {
        return {
            md5: crypto.createHash('md5').update(buffer).digest('hex'),
            sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
            sha256: crypto.createHash('sha256').update(buffer).digest('hex')
        };
    }

    generateFingerprint(buffer) {
        const size = buffer.length;
        const firstBytes = buffer.slice(0, 16).toString('hex');
        const lastBytes = buffer.slice(-16).toString('hex');
        const entropy = this.calculateEntropy(buffer);
        
        return {
            size,
            firstBytes,
            lastBytes,
            entropy: entropy.toFixed(2),
            signature: this.extractFileSignature(buffer)
        };
    }

    calculateEntropy(buffer) {
        const frequency = new Array(256).fill(0);
        
        for (let i = 0; i < buffer.length; i++) {
            frequency[buffer[i]]++;
        }
        
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (frequency[i] > 0) {
                const probability = frequency[i] / buffer.length;
                entropy -= probability * Math.log2(probability);
            }
        }
        
        return entropy;
    }

    extractFileSignature(buffer) {
        if (buffer.length < 16) return null;
        
        const signatures = {
            '4d5a': 'PE/Windows executable',
            '7f454c46': 'ELF/Linux executable',
            'cafebabe': 'Java class file',
            '89504e47': 'PNG image',
            'ffd8ff': 'JPEG image',
            '504b0304': 'ZIP archive',
            '52617221': 'RAR archive',
            '1f8b08': 'GZIP archive'
        };
        
        const hex = buffer.slice(0, 8).toString('hex').toLowerCase();
        
        for (const [sig, type] of Object.entries(signatures)) {
            if (hex.startsWith(sig)) {
                return {
                    signature: sig,
                    type: type,
                    confidence: sig.length / 2
                };
            }
        }
        
        return null;
    }

    classifyEntropy(entropy) {
        if (entropy < 5) return { level: 'normal', risk: 'low', description: 'Normal file entropy' };
        if (entropy <= 7) return { level: 'suspicious', risk: 'medium', description: 'Elevated entropy - possible obfuscation' };
        return { level: 'high', risk: 'high', description: 'High entropy - likely packed or encrypted' };
    }
}

module.exports = FileHashService;
