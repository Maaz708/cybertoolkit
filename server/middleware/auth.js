const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const logger = require('../utils/logger');

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
} catch (error) {
  console.log('⚠️  Auth middleware using memory storage');
  pool = null;
}

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token is required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }

    req.user = decoded;
    next();
  });
};

const setUserContext = async (req, res, next) => {
  try {
    if (pool) {
      const result = await pool.query(
        `SELECT id, email, first_name, last_name, role, subscription_tier, is_active
         FROM users WHERE id = $1`,
        [req.user.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      const user = result.rows[0];
      if (!user.is_active) {
        return res.status(403).json({
          success: false,
          error: 'Account is deactivated'
        });
      }

      req.userContext = {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        subscriptionTier: user.subscription_tier,
        isActive: user.is_active
      };
    } else {
      // Fallback to memory storage
      req.userContext = {
        id: req.user.userId,
        email: req.user.email,
        role: req.user.role || 'user',
        subscriptionTier: req.user.subscriptionTier || 'free',
        isActive: true
      };
    }

    next();
  } catch (error) {
    logger.error('Failed to set user context', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to authenticate user'
    });
  }
};

module.exports = {
  authenticateToken,
  setUserContext
};
