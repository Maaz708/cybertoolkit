const { Pool } = require('pg');

// Centralized database connection - ONLY uses DATABASE_URL
let pool;

const initDatabase = () => {
  try {
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is required');
    }
    
    // Use Supabase connection string ONLY
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: {
        rejectUnauthorized: false
      }
    });
    console.log('✅ Database connected via DATABASE_URL (Supabase)');
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
