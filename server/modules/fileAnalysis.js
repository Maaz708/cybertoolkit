const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mime = require('mime-types');

class FileAnalyzer {
  constructor() {
    this.analysisHistory = [];
  }

  async analyzeFile(filePath) {
    try {
      const fileBuffer = fs.readFileSync(filePath);
      const fileStats = fs.statSync(filePath);
      const mimeType = mime.lookup(filePath) || 'application/octet-stream';

      const analysis = {
        basic_info: {
          filename: path.basename(filePath),
          size: fileStats.size,
          created: fileStats.birthtime,
          modified: fileStats.mtime,
          accessed: fileStats.atime,
          mime_type: mimeType,
          extension: path.extname(filePath).toLowerCase()
        },
        security: {
          hashes: this.calculateHashes(fileBuffer),
          entropy: this.calculateEntropy(fileBuffer),
          suspicious_patterns: this.findSuspiciousPatterns(fileBuffer)
        },
        content_analysis: await this.analyzeContent(fileBuffer, mimeType),
        metadata: this.extractMetadata(fileBuffer, mimeType),
        timestamp: new Date().toISOString()
      };

      this.analysisHistory.push({
        filename: analysis.basic_info.filename,
        size: analysis.basic_info.size,
        type: analysis.basic_info.mime_type,
        timestamp: analysis.timestamp
      });

      return analysis;
    } catch (error) {
      console.error('File analysis error:', error);
      throw error;
    }
  }

  calculateHashes(buffer) {
    return {
      md5: crypto.createHash('md5').update(buffer).digest('hex'),
      sha1: crypto.createHash('sha1').update(buffer).digest('hex'),
      sha256: crypto.createHash('sha256').update(buffer).digest('hex')
    };
  }

  calculateEntropy(buffer) {
    const frequencies = new Array(256).fill(0);
    buffer.forEach(byte => frequencies[byte]++);

    return frequencies.reduce((entropy, freq) => {
      if (freq === 0) return entropy;
      const p = freq / buffer.length;
      return entropy - (p * Math.log2(p));
    }, 0);
  }

  findSuspiciousPatterns(buffer) {
    const patterns = {
      executable_code: /\x4D\x5A|\x7F\x45\x4C\x46/,
      scripts: /<script[^>]*>|eval\(|setTimeout\(|setInterval\(/i,
      base64: /[A-Za-z0-9+/]{40,}={0,3}/
    };

    const results = {};
    const content = buffer.toString('utf8');

    for (const [key, pattern] of Object.entries(patterns)) {
      results[key] = pattern.test(content);
    }

    return results;
  }

  async analyzeContent(buffer, mimeType) {
    const analysis = {
      file_type: mimeType,
      size_bytes: buffer.length,
      text_preview: null,
      binary: false
    };

    if (mimeType.startsWith('text/') || mimeType === 'application/json') {
      const text = buffer.toString('utf8').slice(0, 1000);
      analysis.text_preview = text;
      analysis.lines = text.split('\n').length;
      analysis.words = text.split(/\s+/).length;
    } else {
      analysis.binary = true;
    }

    return analysis;
  }

  extractMetadata(buffer, mimeType) {
    const metadata = {
      file_type: mimeType,
      size: buffer.length,
      encoding: this.detectEncoding(buffer)
    };

    return metadata;
  }

  detectEncoding(buffer) {
    // Simple encoding detection
    if (buffer.includes(Buffer.from([0xFF, 0xFE]))) return 'UTF-16LE';
    if (buffer.includes(Buffer.from([0xFE, 0xFF]))) return 'UTF-16BE';
    if (buffer.includes(Buffer.from([0xEF, 0xBB, 0xBF]))) return 'UTF-8';
    return 'ASCII/Unknown';
  }
}

const analyzer = new FileAnalyzer();

router.post('/analyze', async (req, res) => {
  try {
    console.log('Received file analysis request');

    if (!req.files || !req.files.file) {
      console.log('No file uploaded');
      return res.status(400).json({
        status: 'error',
        message: 'No file uploaded'
      });
    }

    const uploadedFile = req.files.file;
    console.log('Processing file:', uploadedFile.name);

    const tempPath = path.join(__dirname, '../tmp', `analysis_${Date.now()}_${uploadedFile.name}`);

    // Ensure tmp directory exists
    const tmpDir = path.dirname(tempPath);
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true });
    }

    try {
      await uploadedFile.mv(tempPath);
      console.log('File saved to:', tempPath);

      const results = await analyzer.analyzeFile(tempPath);
      console.log('Analysis completed');

      // Clean up
      fs.unlinkSync(tempPath);

      res.json({
        status: 'success',
        data: results
      });
    } catch (err) {
      console.error('Analysis error:', err);
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }
      throw err;
    }
  } catch (error) {
    console.error('File analysis error:', error);
    res.status(500).json({
      status: 'error',
      message: error.message || 'Failed to analyze file'
    });
  }
});

module.exports = router;