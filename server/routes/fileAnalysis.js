const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const logger = require('../utils/logger');
const { authenticateToken, setUserContext } = require('../middleware/auth');
const fileAnalysis = require('../modules/fileAnalysis');

// PostgreSQL connection
let pool;
try {
  const { Pool } = require('pg');
  pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5433,
    database: process.env.DB_NAME || 'cybertoolkit',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
  });
  console.log('✅ File analysis routes database connection configured');
} catch (error) {
  console.log('⚠️  File analysis routes using memory storage');
  pool = null;
}

// In-memory storage for development (fallback)
const memoryStorage = {
  analyses: [],
  files: []
};

// Get user's file analyses
router.get('/analyses', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    let analyses = [];

    if (pool) {
      const result = await pool.query(
        `SELECT id, filename, status, threats_found, is_malicious, 
                scan_duration, created_at, completed_at
         FROM file_scans 
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
    logger.error('Failed to get file analyses', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load file analyses'
    });
  }
});

// Upload and analyze file
router.post('/analyze', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded'
      });
    }

    const file = req.file;
    const filename = file.originalname;
    const fileSize = file.size;
    const mimeType = file.mimetype;

    // Generate unique ID for this analysis
    const analysisId = 'analysis_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);

    let analysis;
    if (pool) {
      const result = await pool.query(
        `INSERT INTO file_scans (user_id, original_filename, file_path, file_size, mime_type, status, created_at)
         VALUES ($1, $2, $3, $4, $5, 'pending', CURRENT_TIMESTAMP)
         RETURNING id`,
        [userId, filename, `/uploads/${filename}`, fileSize, mimeType]
      );
      analysis = { id: result.rows[0].id };
    } else {
      analysis = { id: analysisId };
      memoryStorage.analyses.push({
        id: analysisId,
        user_id: userId,
        filename: filename,
        file_size: fileSize,
        mime_type: mimeType,
        status: 'pending',
        created_at: new Date().toISOString()
      });
    }

    // TODO: Perform actual file analysis
    // For now, simulate analysis
    setTimeout(async () => {
      try {
        const threatsFound = Math.floor(Math.random() * 5);
        const isMalicious = threatsFound > 2;
        
        if (pool) {
          await pool.query(
            `UPDATE file_scans 
             SET status = 'completed', threats_found = $1, is_malicious = $2, completed_at = CURRENT_TIMESTAMP
             WHERE id = $3`,
            [threatsFound, isMalicious, analysis.id]
          );
        } else {
          const index = memoryStorage.analyses.findIndex(a => a.id === analysisId);
          if (index > -1) {
            memoryStorage.analyses[index].status = 'completed';
            memoryStorage.analyses[index].threats_found = threatsFound;
            memoryStorage.analyses[index].is_malicious = isMalicious;
            memoryStorage.analyses[index].completed_at = new Date().toISOString();
          }
        }
      } catch (error) {
        logger.error('Failed to complete file analysis', { error: error.message, analysisId });
      }
    }, 2000);

    logger.info('File analysis started', { 
      analysisId: analysis.id, 
      userId, 
      filename,
      fileSize,
      mimeType,
      ip: req.ip 
    });

    res.status(201).json({
      success: true,
      message: 'File analysis started successfully',
      analysis: analysis
    });

  } catch (error) {
    logger.error('Failed to start file analysis', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to start file analysis'
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
        `SELECT * FROM file_scans 
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
        `DELETE FROM file_scans 
         WHERE id = $1 AND user_id = $2`,
        [analysisId, userId]
      );
    } else {
      const index = memoryStorage.analyses.findIndex(a => a.id === analysisId && a.user_id === userId);
      if (index > -1) {
        memoryStorage.analyses.splice(index, 1);
      }
    }

    logger.info('File analysis deleted', { 
      analysisId, 
      userId,
      ip: req.ip 
    });

    res.json({
      success: true,
      message: 'File analysis deleted successfully'
    });

  } catch (error) {
    logger.error('Failed to delete file analysis', { 
      error: error.message, 
      analysisId: req.params.analysisId,
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to delete file analysis'
    });
  }
});

// Get analysis statistics
router.get('/statistics', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    let stats = {
      totalAnalyses: 0,
      completedAnalyses: 0,
      threatsFound: 0,
      maliciousFiles: 0,
      averageAnalysisTime: 0
    };

    if (pool) {
      const result = await pool.query(
        `SELECT status, threats_found, is_malicious, created_at, completed_at
         FROM file_scans 
         WHERE user_id = $1 
         ORDER BY created_at DESC`,
        [userId]
      );
      
      stats.totalAnalyses = result.rows.length;
      stats.completedAnalyses = result.rows.filter(analysis => analysis.status === 'completed').length;
      stats.threatsFound = result.rows.reduce((sum, analysis) => sum + (analysis.threats_found || 0), 0);
      stats.maliciousFiles = result.rows.filter(analysis => analysis.is_malicious).length;
      
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
      stats.threatsFound = userAnalyses.reduce((sum, analysis) => sum + (analysis.threats_found || 0), 0);
      stats.maliciousFiles = userAnalyses.filter(analysis => analysis.is_malicious).length;
    }

    res.json({
      success: true,
      statistics: stats
    });

  } catch (error) {
    logger.error('Failed to get analysis statistics', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load analysis statistics'
    });
  }
});

module.exports = router;
