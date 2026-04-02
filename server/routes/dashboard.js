const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const logger = require('../utils/logger');
const { authenticateToken, setUserContext } = require('../middleware/auth');

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
  console.log('✅ Dashboard analytics database connection configured');
} catch (error) {
  console.log('⚠️  Dashboard analytics using memory storage');
  pool = null;
}

// In-memory storage for development (fallback)
const memoryStorage = {
  userStats: {},
  systemStats: {}
};

// Get user analytics data
router.get('/analytics', authenticateToken, setUserContext, async (req, res) => {
  try {
    const userId = req.user.userId;
    let analytics = {};

    if (pool) {
      // Get user's file scans
      const fileScansResult = await pool.query(
        `SELECT id, original_filename, status, threats_found, is_malicious, created_at, completed_at
         FROM file_scans 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 100`,
        [userId]
      );

      // Get user's network scans
      const networkScansResult = await pool.query(
        `SELECT id, scan_name, status, total_connections_found, threats_detected, created_at, completed_at
         FROM network_scans 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 50`,
        [userId]
      );

      // Get user's email analyses
      const emailAnalysesResult = await pool.query(
        `SELECT id, subject, sender_email, is_phishing, is_spam, is_malicious, created_at, completed_at
         FROM email_analyses 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 50`,
        [userId]
      );

      // Get user's alerts
      const alertsResult = await pool.query(
        `SELECT id, alert_type, severity, title, message, is_read, is_resolved, created_at
         FROM alerts 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT 20`,
        [userId]
      );

      // Calculate analytics
      analytics = {
        overview: {
          totalFileScans: fileScansResult.rows.length,
          totalNetworkScans: networkScansResult.rows.length,
          totalEmailAnalyses: emailAnalysesResult.rows.length,
          totalAlerts: alertsResult.rows.length,
          lastActivity: fileScansResult.rows[0]?.created_at || networkScansResult.rows[0]?.created_at || emailAnalysesResult.rows[0]?.created_at
        },
        fileAnalysis: {
          totalScans: fileScansResult.rows.length,
          threatsFound: fileScansResult.rows.reduce((sum, scan) => sum + scan.threats_found, 0),
          maliciousFiles: fileScansResult.rows.filter(scan => scan.is_malicious).length,
          completedScans: fileScansResult.rows.filter(scan => scan.status === 'completed').length,
          averageScanTime: fileScansResult.rows.length > 0 
            ? fileScansResult.rows.reduce((total, scan) => {
                if (scan.completed_at && scan.created_at) {
                  const duration = new Date(scan.completed_at) - new Date(scan.created_at);
                  return total + duration;
                }
                return total;
              }, 0) / fileScansResult.rows.length / 1000
            : 0
        },
        networkMonitoring: {
          totalScans: networkScansResult.rows.length,
          totalConnections: networkScansResult.rows.reduce((sum, scan) => sum + scan.total_connections_found, 0),
          threatsDetected: networkScansResult.rows.reduce((sum, scan) => sum + scan.threats_detected, 0),
          completedScans: networkScansResult.rows.filter(scan => scan.status === 'completed').length,
          averageDuration: networkScansResult.rows.length > 0
            ? networkScansResult.rows.reduce((total, scan) => {
                if (scan.completed_at && scan.created_at) {
                  const duration = new Date(scan.completed_at) - new Date(scan.created_at);
                  return total + duration;
                }
                return total;
              }, 0) / networkScansResult.rows.length / 1000
            : 0
        },
        emailForensics: {
          totalAnalyses: emailAnalysesResult.rows.length,
          phishingDetected: emailAnalysesResult.rows.filter(email => email.is_phishing).length,
          spamDetected: emailAnalysesResult.rows.filter(email => email.is_spam).length,
          maliciousEmails: emailAnalysesResult.rows.filter(email => email.is_malicious).length,
          completedAnalyses: emailAnalysesResult.rows.filter(email => email.status === 'completed').length,
          averageAnalysisTime: emailAnalysesResult.rows.length > 0
            ? emailAnalysesResult.rows.reduce((total, email) => {
                if (email.completed_at && email.created_at) {
                  const duration = new Date(email.completed_at) - new Date(email.created_at);
                  return total + duration;
                }
                return total;
              }, 0) / emailAnalysesResult.rows.length / 1000
            : 0
        },
        security: {
          criticalAlerts: alertsResult.rows.filter(alert => alert.severity === 'high').length,
          warningAlerts: alertsResult.rows.filter(alert => alert.severity === 'medium').length,
          infoAlerts: alertsResult.rows.filter(alert => alert.severity === 'low').length,
          unresolvedAlerts: alertsResult.rows.filter(alert => !alert.is_resolved).length,
          resolvedAlerts: alertsResult.rows.filter(alert => alert.is_resolved).length
        },
        recentActivity: {
          fileScans: fileScansResult.rows.slice(0, 5).map(scan => ({
            id: scan.id,
            filename: scan.filename,
            status: scan.status,
            threats: scan.threats_found,
            time: scan.created_at
          })),
          networkScans: networkScansResult.rows.slice(0, 5).map(scan => ({
            id: scan.id,
            scanName: scan.scan_name,
            status: scan.status,
            connections: scan.total_connections_found,
            threats: scan.threats_detected,
            time: scan.created_at
          })),
          emailAnalyses: emailAnalysesResult.rows.slice(0, 5).map(email => ({
            id: email.id,
            subject: email.subject,
            status: email.status,
            phishing: email.is_phishing,
            time: email.created_at
          })),
          alerts: alertsResult.rows.slice(0, 5).map(alert => ({
            id: alert.id,
            type: alert.alert_type,
            severity: alert.severity,
            title: alert.title,
            message: alert.message,
            time: alert.created_at
          }))
        }
      };

    } else {
      // Use memory storage fallback
      analytics = memoryStorage.userStats[userId] || {
        overview: {
          totalFileScans: 0,
          totalNetworkScans: 0,
          totalEmailAnalyses: 0,
          totalAlerts: 0,
          lastActivity: new Date().toISOString()
        },
        fileAnalysis: {
          totalScans: 0,
          threatsFound: 0,
          maliciousFiles: 0,
          completedScans: 0,
          averageScanTime: 0
        },
        networkMonitoring: {
          totalScans: 0,
          totalConnections: 0,
          threatsDetected: 0,
          completedScans: 0,
          averageDuration: 0
        },
        emailForensics: {
          totalAnalyses: 0,
          phishingDetected: 0,
          spamDetected: 0,
          maliciousEmails: 0,
          completedAnalyses: 0,
          averageAnalysisTime: 0
        },
        security: {
          criticalAlerts: 0,
          warningAlerts: 0,
          infoAlerts: 0,
          unresolvedAlerts: 0,
          resolvedAlerts: 0
        },
        recentActivity: {
          fileScans: [],
          networkScans: [],
          emailAnalyses: [],
          alerts: []
        }
      };
    }

    res.json({
      success: true,
      analytics
    });

  } catch (error) {
    logger.error('Failed to get dashboard analytics', {
      error: error.message,
      userId: req.user.userId,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load analytics data'
    });
  }
});

// Get system-wide statistics (admin only)
router.get('/system-stats', authenticateToken, setUserContext, async (req, res) => {
  try {
    // Check if user is admin
    if (req.userContext.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    let stats = {};

    if (pool) {
      // Get system-wide statistics
      const totalUsersResult = await pool.query('SELECT COUNT(*) as count FROM users WHERE is_active = true');
      const totalScansResult = await pool.query('SELECT COUNT(*) as count FROM file_scans');
      const totalNetworkScansResult = await pool.query('SELECT COUNT(*) as count FROM network_scans');
      const totalEmailAnalysesResult = await pool.query('SELECT COUNT(*) as count FROM email_analyses');
      const totalAlertsResult = await pool.query('SELECT COUNT(*) as count FROM alerts WHERE is_resolved = false');

      stats = {
        users: {
          totalActive: parseInt(totalUsersResult.rows[0].count),
          totalRegistered: await pool.query('SELECT COUNT(*) as count FROM users').then(result => parseInt(result.rows[0].count)),
          subscriptionBreakdown: await pool.query('SELECT subscription_tier, COUNT(*) as count FROM users WHERE is_active = true GROUP BY subscription_tier')
        },
        system: {
          totalScans: parseInt(totalScansResult.rows[0].count),
          totalNetworkScans: parseInt(totalNetworkScansResult.rows[0].count),
          totalEmailAnalyses: parseInt(totalEmailAnalysesResult.rows[0].count),
          totalAlerts: parseInt(totalAlertsResult.rows[0].count),
          systemHealth: 95, // Could be calculated based on various metrics
          uptime: process.uptime()
        },
        threats: {
          totalThreats: await pool.query('SELECT COUNT(*) as count FROM alerts WHERE is_resolved = false').then(result => parseInt(result.rows[0].count)),
          criticalThreats: await pool.query('SELECT COUNT(*) as count FROM alerts WHERE severity = \'high\' AND is_resolved = false').then(result => parseInt(result.rows[0].count)),
          warningThreats: await pool.query('SELECT COUNT(*) as count FROM alerts WHERE severity = \'medium\' AND is_resolved = false').then(result => parseInt(result.rows[0].count)),
          infoThreats: await pool.query('SELECT COUNT(*) as count FROM alerts WHERE severity = \'low\' AND is_resolved = false').then(result => parseInt(result.rows[0].count))
        }
      };
    } else {
      // Use memory storage fallback
      stats = memoryStorage.systemStats || {
        users: { totalActive: 1, totalRegistered: 1, subscriptionBreakdown: [] },
        system: { totalScans: 0, totalNetworkScans: 0, totalEmailAnalyses: 0, totalAlerts: 0, systemHealth: 95, uptime: 0 },
        threats: { totalThreats: 0, criticalThreats: 0, warningThreats: 0, infoThreats: 0 }
      };
    }

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    logger.error('Failed to get system stats', {
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      error: 'Failed to load system statistics'
    });
  }
});

module.exports = router;
