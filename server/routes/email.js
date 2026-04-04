const express = require('express');
const router = express.Router();
const { getPool } = require('../utils/database');
const logger = require('../utils/logger');
const { authenticateToken, setUserContext } = require('../middleware/auth');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Multer configuration for email file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Get database pool
const pool = getPool();

// In-memory storage for development (fallback)
const memoryStorage = {
  analyses: [],
  emails: []
};

// Get user's email analyses
router.get('/analyses', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    let analyses = [];

    if (pool) {
      const result = await pool.query(
        `SELECT id, subject, sender_email, is_phishing, is_spam, is_malicious, 
                created_at, completed_at
         FROM email_analyses 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 50`,
        [userId]
      );
      analyses = result.rows;
    } else {
      analyses = memoryStorage.analyses.filter(analysis => analysis.user_id === userId);
    }

    res.json({
      success: true,
      analyses
    });

  } catch (error) {
    logger.error('Failed to get email analyses', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load email analyses'
    });
  }
});

// Analyze email
router.post('/analyze', authenticateToken, setUserContext, upload.single('email'), async (req, res) => {
  try {
    const userId = req.user.userId;
    
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No email file uploaded'
      });
    }

    // For now, simulate email analysis from file
    // In a real implementation, you would parse the email file (.eml, .msg)
    const file = req.file;
    const filename = file.originalname;
    
    // Generate unique ID for this analysis
    const analysisId = 'email_analysis_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

    // Mock email analysis results
    const isPhishing = Math.random() > 0.7;
    const isSpam = Math.random() > 0.5;
    const isMalicious = Math.random() > 0.8;
    
    let analysis;
    if (pool) {
      const result = await pool.query(
        `INSERT INTO email_analyses (user_id, subject, sender_email, status, is_phishing, is_spam, is_malicious, created_at, completed_at) VALUES ($1, $2, $3, 'completed', $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) RETURNING id`,
        [userId, filename, 'unknown@sender.com', isPhishing, isSpam, isMalicious]
      );
      analysis = { id: result.rows[0].id };
    } else {
      analysis = { id: analysisId };
      memoryStorage.analyses.push({
        id: analysisId,
        user_id: userId,
        subject: filename,
        sender_email: 'unknown@sender.com',
        status: 'completed',
        is_phishing: isPhishing,
        is_spam: isSpam,
        is_malicious: isMalicious,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString()
      });
    }

    // Return analysis results
    res.json({
      success: true,
      data: {
        id: analysis.id,
        subject: filename,
        senderEmail: 'unknown@sender.com',
        isPhishing,
        isSpam,
        isMalicious,
        riskScore: (isPhishing ? 40 : 0) + (isSpam ? 20 : 0) + (isMalicious ? 60 : 0),
        analysis: {
          suspiciousLinks: Math.floor(Math.random() * 3),
          suspiciousAttachments: Math.random() > 0.8 ? 1 : 0,
          senderReputation: Math.random() > 0.5 ? 'good' : 'suspicious',
          languageAnalysis: Math.random() > 0.6 ? 'suspicious' : 'normal',
          headerAnalysis: Math.random() > 0.7 ? 'spoofed' : 'legitimate'
        },
        createdAt: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Email analysis failed', {
      error: error.message,
      userId: req.user?.userId,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      error: 'Failed to analyze email'
    });
  }
});

// Get analysis details
router.get('/analysis/:analysisId', authenticateToken, setUserContext, async (req, res) => {
  try {
    const { analysisId } = req.params;
    const userId = req.user.userId;

    let analysis;
    if (pool) {
      const result = await pool.query(
        `SELECT * FROM email_analyses 
         WHERE id = $1 AND user_id = $2`,
        [analysisId, userId]
      );
      analysis = result.rows[0];
    } else {
      analysis = memoryStorage.analyses.find(a => a.id === analysisId && a.user_id === userId);
    }

    if (!analysis) {
      return res.status(404).json({
        success: false,
        error: 'Analysis not found'
      });
    }

    res.json({
      success: true,
      analysis
    });

  } catch (error) {
    logger.error('Failed to get analysis details', { 
      error: error.message, 
      analysisId: req.params.analysisId,
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load analysis details'
    });
  }
});

// Delete analysis
router.delete('/analysis/:analysisId', authenticateToken, setUserContext, async (req, res) => {
  try {
    const { analysisId } = req.params;
    const userId = req.user.userId;

    if (pool) {
      await pool.query(
        `DELETE FROM email_analyses 
         WHERE id = $1 AND user_id = $2`,
        [analysisId, userId]
      );
    } else {
      const index = memoryStorage.analyses.findIndex(a => a.id === analysisId && a.user_id === userId);
      if (index > -1) {
        memoryStorage.analyses.splice(index, 1);
      }
    }

    logger.info('Email analysis deleted', { 
      analysisId, 
      userId,
      ip: req.ip 
    });

    res.json({
      success: true,
      message: 'Email analysis deleted successfully'
    });

  } catch (error) {
    logger.error('Failed to delete email analysis', { 
      error: error.message, 
      analysisId: req.params.analysisId,
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to delete email analysis'
    });
  }
});

// Get email statistics
router.get('/statistics', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    let stats = {
      totalAnalyses: 0,
      completedAnalyses: 0,
      phishingDetected: 0,
      spamDetected: 0,
      maliciousEmails: 0,
      averageAnalysisTime: 0
    };

    if (pool) {
      const result = await pool.query(
        `SELECT status, is_phishing, is_spam, is_malicious, created_at, completed_at
         FROM email_analyses 
         WHERE user_id = $1 
         ORDER BY created_at DESC`,
        [userId]
      );
      
      stats.totalAnalyses = result.rows.length;
      stats.completedAnalyses = result.rows.filter(analysis => analysis.status === 'completed').length;
      stats.phishingDetected = result.rows.filter(analysis => analysis.is_phishing).length;
      stats.spamDetected = result.rows.filter(analysis => analysis.is_spam).length;
      stats.maliciousEmails = result.rows.filter(analysis => analysis.is_malicious).length;
      
      const completedAnalyses = result.rows.filter(analysis => analysis.completed_at);
      if (completedAnalyses.length > 0) {
        const totalTime = completedAnalyses.reduce((sum, analysis) => {
          const duration = new Date(analysis.completed_at) - new Date(analysis.created_at);
          return sum + duration;
        }, 0);
        stats.averageAnalysisTime = totalTime / completedAnalyses.length / 1000; // Convert to seconds
      }
    } else {
      const userAnalyses = memoryStorage.analyses.filter(analysis => analysis.user_id === userId);
      stats.totalAnalyses = userAnalyses.length;
      stats.completedAnalyses = userAnalyses.filter(analysis => analysis.status === 'completed').length;
      stats.phishingDetected = userAnalyses.filter(analysis => analysis.is_phishing).length;
      stats.spamDetected = userAnalyses.filter(analysis => analysis.is_spam).length;
      stats.maliciousEmails = userAnalyses.filter(analysis => analysis.is_malicious).length;
    }

    res.json({
      success: true,
      statistics: stats
    });

  } catch (error) {
    logger.error('Failed to get email statistics', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load email statistics'
    });
  }
});

module.exports = router;
