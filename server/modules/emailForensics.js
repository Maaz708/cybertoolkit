const express = require('express');
const { simpleParser } = require('mailparser');
const router = express.Router();

class EmailAnalyzer {
    async analyzeEmail(emailFile) {
        try {
            console.log('Starting email analysis');
            const emailContent = emailFile.data.toString('utf8');
            const parsed = await simpleParser(emailContent);

            console.log('Parsed email data:', parsed); // Debug log

            const analysis = {
                status: 'success',
                analysis: {
                    content: {
                        subject: parsed.subject || '',
                        from: parsed.from?.text || '',
                        to: Array.isArray(parsed.to) ? parsed.to.map(t => t.text).join(', ') : parsed.to?.text || '',
                        date: parsed.date?.toISOString() || new Date().toISOString(),
                        textContent: parsed.text || '',
                        htmlContent: parsed.html || ''
                    },
                    attachments: (parsed.attachments || []).map(att => ({
                        filename: att.filename || 'unnamed',
                        contentType: att.contentType || 'application/octet-stream',
                        size: att.size || 0,
                        malwareScan: {
                            safe: true,
                            score: 0
                        }
                    })),
                    security: {
                        spfRecord: null,
                        dmarcRecord: null,
                        returnPathValid: false,
                        suspiciousLinks: [],
                        suspiciousAttachments: [],
                        securityScore: 50 // Default score
                    },
                    metadata: {
                        receivedTimestamp: parsed.date?.toISOString() || new Date().toISOString(),
                        messageId: parsed.messageId || '',
                        size: emailFile.size
                    }
                }
            };

            console.log('Analysis completed:', JSON.stringify(analysis, null, 2));
            return analysis;
        } catch (error) {
            console.error('Email analysis error:', error);
            throw error;
        }
    }
}

const analyzer = new EmailAnalyzer();

router.post('/analyze', async (req, res) => {
    try {
        console.log('Received email analysis request');

        if (!req.files?.email) {
            return res.status(400).json({
                status: 'error',
                message: 'No email file uploaded'
            });
        }

        const emailFile = req.files.email;
        console.log('Processing file:', emailFile.name);

        const result = await analyzer.analyzeEmail(emailFile);
        console.log('Raw analysis result:', result); // Debug log

        // Format response with safe access to properties
        const response = {
            status: 'success',
            analysis: {
                content: {
                    subject: result?.analysis?.content?.subject || '',
                    from: result?.analysis?.content?.from || '',
                    to: result?.analysis?.content?.to || '',
                    date: result?.analysis?.content?.date || ''
                },
                security: {
                    securityScore: result?.analysis?.security?.securityScore || 0,
                    spfRecord: result?.analysis?.security?.spfRecord || null,
                    dmarcRecord: result?.analysis?.security?.dmarcRecord || null,
                    returnPathValid: result?.analysis?.security?.returnPathValid || false,
                    suspiciousLinks: result?.analysis?.security?.suspiciousLinks || [],
                    suspiciousAttachments: result?.analysis?.security?.suspiciousAttachments || []
                },
                attachments: result?.analysis?.attachments || [],
                metadata: {
                    receivedTimestamp: new Date().toISOString(),
                    messageId: result?.analysis?.metadata?.messageId || '',
                    size: emailFile.size || 0
                }
            }
        };

        console.log('Sending formatted response:', JSON.stringify(response, null, 2));
        return res.json(response);

    } catch (error) {
        console.error('Email analysis error:', error);
        return res.status(500).json({
            status: 'error',
            message: error.message || 'Failed to analyze email'
        });
    }
});

module.exports = router; 