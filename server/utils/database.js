const { Pool } = require('pg');

// Centralized database connection
let pool;

const initDatabase = () => {
  try {
    if (process.env.DATABASE_URL) {
      // Use Supabase connection string
      pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: {
          rejectUnauthorized: false
        }
      });
      console.log('✅ Database connected via DATABASE_URL (Supabase)');
    } else {
      // Use individual environment variables (local development)
      pool = new Pool({
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5433,
        database: process.env.DB_NAME || 'cybertoolkit',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD,
      });
      console.log('✅ Database connected via individual params (Local)');
    }
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    pool = null;
  }
};

// Initialize database connection
initDatabase();

const getPool = () => {
  return pool;
};

module.exports = {
  getPool,
  initDatabase
};
