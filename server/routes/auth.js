const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const router = express.Router();
const config = require('../config');
const logger = require('../utils/logger');
const { validate } = require('../utils/validation');

// PostgreSQL connection - with fallback for development
let pool;
try {
  const { Pool } = require('pg');
  pool = new Pool({
    host: config.database.host,
    port: config.database.port,
    database: config.database.name,
    user: config.database.user,
    password: config.database.password,
  });
  console.log('✅ PostgreSQL connection configured');
} catch (error) {
  console.log('⚠️  PostgreSQL not available, using memory storage');
  pool = null;
}

// In-memory storage for development (fallback)
const memoryStorage = {
  users: [],
  sessions: []
};

// Add default admin user for testing
const addDefaultAdmin = async () => {
  if (!pool && memoryStorage.users.length === 0) {
    const adminPassword = await bcrypt.hash('admin123', 12);
    memoryStorage.users.push({
      id: 'admin_default',
      email: 'admin@cybertoolkit.com',
      password_hash: adminPassword,
      first_name: 'Admin',
      last_name: 'User',
      company_name: 'CyberToolkit',
      role: 'admin',
      subscription_tier: 'enterprise',
      is_active: true,
      email_verified: true,
      created_at: new Date().toISOString()
    });
    console.log('✅ Default admin user created (admin@cybertoolkit.com / admin123)');
  }
};

addDefaultAdmin();

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      error: 'Access token required' 
    });
  }

  jwt.verify(token, config.jwt.secret, (err, user) => {
    if (err) {
      logger.warn('Invalid JWT token', { error: err.message });
      return res.status(403).json({ 
        success: false, 
        error: 'Invalid or expired token' 
      });
    }
    req.user = user;
    next();
  });
};

// Set user context for Row Level Security
const setUserContext = async (req, res, next) => {
  try {
    if (req.user && pool) {
      await pool.query('SET app.current_user_id = $1', [req.user.userId]);
    }
  } catch (error) {
    console.log('⚠️ Skipping DB context (no connection)');
  }
  next();
};

// Register new user
router.post('/register', validate('register'), async (req, res) => {
  try {
    const { email, password, firstName, lastName, companyName } = req.body;

    // Hash password
    const passwordHash = await bcrypt.hash(password, config.security.bcryptRounds);

    let user;

    if (pool) {
      // Use PostgreSQL
      try {
        // Check if user already exists
        const existingUser = await pool.query(
          'SELECT id FROM users WHERE email = $1',
          [email.toLowerCase()]
        );

        if (existingUser.rows.length > 0) {
          return res.status(400).json({
            success: false,
            error: 'User with this email already exists'
          });
        }

        // Create user
        const result = await pool.query(
          `INSERT INTO users (email, password_hash, first_name, last_name, company_name, role, subscription_tier, is_active, email_verified) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
           RETURNING id, email, first_name, last_name, company_name, role, subscription_tier, created_at`,
          [email.toLowerCase(), passwordHash, firstName, lastName, companyName, 'user', 'free', true, false]
        );

        user = result.rows[0];
      } catch (dbError) {
        console.log('⚠️  PostgreSQL error, falling back to memory storage');
        pool = null; // Disable PostgreSQL for future requests
      }
    }

    if (!pool) {
      // Use memory storage
      const existingUser = memoryStorage.users.find(u => u.email === email.toLowerCase());
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: 'User with this email already exists'
        });
      }

      user = {
        id: 'user_' + Date.now(),
        email: email.toLowerCase(),
        first_name: firstName,
        last_name: lastName,
        company_name: companyName,
        role: 'user',
        subscription_tier: 'free',
        created_at: new Date().toISOString()
      };

      memoryStorage.users.push({
        ...user,
        password_hash: passwordHash,
        is_active: true,
        email_verified: false
      });
    }

    logger.info('New user registered', { 
      userId: user.id, 
      email: user.email,
      ip: req.ip 
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        companyName: user.company_name,
        role: user.role,
        subscriptionTier: user.subscription_tier,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    logger.error('Registration failed', { 
      error: error.message, 
      email: req.body.email,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Registration failed. Please try again.'
    });
  }
});

// Login user
router.post('/login', validate('login'), async (req, res) => {
  try {
    const { email, password } = req.body;

    let user;

    if (pool) {
      // Use PostgreSQL
      try {
        const result = await pool.query(
          `SELECT id, email, password_hash, first_name, last_name, role, subscription_tier, is_active 
           FROM users WHERE email = $1`,
          [email.toLowerCase()]
        );

        if (result.rows.length === 0) {
          logger.warn('Login attempt with non-existent email', { email, ip: req.ip });
          return res.status(401).json({
            success: false,
            error: 'Invalid email or password'
          });
        }

        user = result.rows[0];
      } catch (dbError) {
        console.log('⚠️  PostgreSQL error, falling back to memory storage');
        pool = null; // Disable PostgreSQL for future requests
      }
    }

    if (!pool) {
      // Use memory storage
      const storedUser = memoryStorage.users.find(u => u.email === email.toLowerCase());
      if (!storedUser) {
        logger.warn('Login attempt with non-existent email', { email, ip: req.ip });
        return res.status(401).json({
          success: false,
          error: 'Invalid email or password'
        });
      }

      user = {
        id: storedUser.id,
        email: storedUser.email,
        password_hash: storedUser.password_hash,
        first_name: storedUser.first_name,
        last_name: storedUser.last_name,
        role: storedUser.role,
        subscription_tier: storedUser.subscription_tier,
        is_active: storedUser.is_active
      };
    }

    if (!user.is_active) {
      logger.warn('Login attempt with inactive account', { userId: user.id, ip: req.ip });
      return res.status(401).json({
        success: false,
        error: 'Account is deactivated'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      logger.warn('Login attempt with invalid password', { userId: user.id, ip: req.ip });
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    // Store session (simplified for memory storage)
    if (pool) {
      await pool.query(
        `INSERT INTO user_sessions (user_id, token_hash, device_info, ip_address, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          user.id,
          require('crypto').createHash('sha256').update(token).digest('hex'),
          JSON.stringify({ userAgent: req.get('User-Agent') }),
          req.ip,
          req.get('User-Agent'),
          new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        ]
      );
    } else {
      memoryStorage.sessions.push({
        user_id: user.id,
        token_hash: require('crypto').createHash('sha256').update(token).digest('hex'),
        device_info: { userAgent: req.get('User-Agent') },
        ip_address: req.ip,
        user_agent: req.get('User-Agent'),
        expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });
    }

    logger.info('User logged in successfully', { 
      userId: user.id, 
      email: user.email,
      ip: req.ip 
    });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        subscriptionTier: user.subscription_tier
      }
    });
  } catch (error) {
    logger.error('Login failed', { 
      error: error.message, 
      email: req.body.email,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Login failed. Please try again.'
    });
  }
});

// Get current user profile
router.get('/profile', authenticateToken, setUserContext, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, email, first_name, last_name, company_name, role, subscription_tier, 
              is_active, email_verified, last_login, created_at 
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

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        companyName: user.company_name,
        role: user.role,
        subscriptionTier: user.subscription_tier,
        isActive: user.is_active,
        emailVerified: user.email_verified,
        lastLogin: user.last_login,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    logger.error('Get profile failed', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Failed to get profile'
    });
  }
});

// Logout user
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const tokenHash = require('crypto').createHash('sha256').update(token).digest('hex');
      await pool.query(
        'UPDATE user_sessions SET is_active = false WHERE token_hash = $1',
        [tokenHash]
      );
    }

    logger.info('User logged out', { userId: req.user.userId });

    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    logger.error('Logout failed', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Logout failed'
    });
  }
});

// Refresh token
router.post('/refresh', authenticateToken, async (req, res) => {
  try {
    // Generate new token
    const token = jwt.sign(
      { userId: req.user.userId, email: req.user.email },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    // Store new session
    await pool.query(
      `INSERT INTO user_sessions (user_id, token_hash, device_info, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        req.user.userId,
        require('crypto').createHash('sha256').update(token).digest('hex'),
        JSON.stringify({ userAgent: req.get('User-Agent') }),
        req.ip,
        req.get('User-Agent'),
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      ]
    );

    res.json({
      success: true,
      token
    });
  } catch (error) {
    logger.error('Token refresh failed', { 
      error: error.message, 
      userId: req.user.userId,
      stack: error.stack 
    });
    res.status(500).json({
      success: false,
      error: 'Token refresh failed'
    });
  }
});

module.exports = router;
