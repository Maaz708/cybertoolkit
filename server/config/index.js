require('dotenv').config();

const config = {
  // Server Configuration
  PORT: process.env.PORT || 5000,
  NODE_ENV: process.env.NODE_ENV || 'development',
  
  // Database Configuration
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    name: process.env.DB_NAME || 'cybertoolkit',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || '',
  },
  
  // Redis Configuration
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || '',
  },
  
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback_secret_change_this',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
  
  // Frontend URLs
  frontend: {
    url: process.env.FRONTEND_URL || 'http://localhost:5173',
    prodUrl: process.env.FRONTEND_URL_PROD || 'https://your-domain.com',
  },
  
  // File Upload Configuration
  upload: {
    maxSize: parseInt(process.env.MAX_FILE_SIZE) || 52428800, // 50MB
    path: process.env.UPLOAD_PATH || './uploads',
  },
  
  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  },
  
  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    file: process.env.LOG_FILE || './logs/app.log',
  },
  
  // WebSocket Configuration
  websocket: {
    port: parseInt(process.env.WS_PORT) || 8080,
  },
  
  // Security
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  },
};

// Validation
if (config.NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.includes('change_this')) {
    throw new Error('JWT_SECRET must be set in production');
  }
  if (!process.env.DB_PASSWORD) {
    throw new Error('DB_PASSWORD must be set in production');
  }
}

module.exports = config;
