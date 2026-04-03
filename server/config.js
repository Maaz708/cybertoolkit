module.exports = {
  server: {
    port: process.env.PORT || 5000,
    host: process.env.HOST || 'localhost'
  },
  database: {
    // Use DATABASE_URL if available (Supabase), otherwise use individual params
    connectionString: process.env.DATABASE_URL,
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5433,
    name: process.env.DB_NAME || 'cybertoolkit',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'your_super_secret_jwt_key_change_this_in_production_12345',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d'
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100 // limit each IP to 100 requests per windowMs
  },
  frontend: {
    url: process.env.FRONTEND_URL || 'http://localhost:5173',
    prodUrl: process.env.FRONTEND_PROD_URL || 'http://localhost:5173',
    // Support multiple origins for production (Netlify, Vercel, etc)
    allowedOrigins: process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',') 
      : ['http://localhost:5173', 'http://localhost:3000']
  },
  upload: {
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedTypes: ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf', 'application/zip']
  },
  websocket: {
    port: process.env.WS_PORT || 8080
  },
  logging: {
    file: process.env.LOG_FILE || './logs/app.log',
    level: process.env.LOG_LEVEL || 'info'
  },
  security: {
    bcryptRounds: 10
  }
};
