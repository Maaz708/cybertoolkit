class FileTypeService {
    constructor() {
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
            'py': 'text/x-python'
        };
    }

    detectRealFileType(buffer) {
        const detected = {
            mimeType: 'application/octet-stream',
            confidence: 0,
            description: 'Unknown file type'
        };

        for (const [mimeType, magicBytes] of Object.entries(this.magicBytes)) {
            if (magicBytes.length === 0) continue; // Skip text files
            
            if (buffer.length >= magicBytes.length && 
                buffer.slice(0, magicBytes.length).equals(magicBytes)) {
                detected.mimeType = mimeType;
                detected.confidence = 1.0;
                detected.description = this.getMimeTypeDescription(mimeType);
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
        const extension = filename.toLowerCase().split('.').pop();
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

        return validation;
    }

    isExecutable(mimeType) {
        return [
            'application/x-dosexec',
            'application/x-executable',
            'application/x-mach-binary',
            'application/x-msdownload'
        ].includes(mimeType);
    }

    isScript(mimeType) {
        return [
            'application/javascript',
            'text/html',
            'application/x-httpd-php',
            'text/x-python',
            'application/x-sh'
        ].includes(mimeType);
    }

    isArchive(mimeType) {
        return [
            'application/zip',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/gzip',
            'application/x-tar'
        ].includes(mimeType);
    }
}

module.exports = FileTypeService;
