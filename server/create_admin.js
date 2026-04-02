#!/usr/bin/env node

require('dotenv').config();
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const logger = require('./utils/logger');

async function createAdminUser() {
  const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5433,
    database: process.env.DB_NAME || 'cybertoolkit',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD,
  });

  try {
    console.log('🔐 Creating admin user...');

    // Check if admin already exists
    const existingAdmin = await pool.query(
      'SELECT id, email FROM users WHERE email = $1',
      ['admin@cybertoolkit.com']
    );

    if (existingAdmin.rows.length > 0) {
      console.log('⚠️  Admin user already exists:', existingAdmin.rows[0].email);
      console.log('🔑 Login credentials: admin@cybertoolkit.com / admin123');
      await pool.end();
      return;
    }

    // Hash the password
    const passwordHash = await bcrypt.hash('admin123', 12);

    // Insert admin user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, role, subscription_tier, is_active, email_verified) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING id, email, role, created_at`,
      ['admin@cybertoolkit.com', passwordHash, 'Admin', 'User', 'admin', 'enterprise', true, true]
    );

    const adminUser = result.rows[0];

    console.log('✅ Admin user created successfully!');
    console.log('📧 Email:', adminUser.email);
    console.log('🔑 Password: admin123');
    console.log('🆔 User ID:', adminUser.id);
    console.log('👤 Role:', adminUser.role);
    console.log('📅 Created:', adminUser.created_at);
    console.log('\n🌐 You can now login at: http://localhost:5173');
    console.log('🔐 Use these credentials to access the admin dashboard.');

  } catch (error) {
    console.error('❌ Failed to create admin user:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n🔧 Make sure PostgreSQL is running:');
      console.log('   docker-compose up -d postgres');
      console.log('   Wait 30 seconds, then run this script again.');
    } else if (error.code === '3D000') {
      console.log('\n🔧 Database does not exist. Make sure to run the schema first:');
      console.log('   docker-compose exec postgres psql -U postgres -d cybertoolkit -f /app/server/database/schema.sql');
    }
    
    process.exit(1);
  } finally {
    await pool.end();
  }
}

// Run the script
if (require.main === module) {
  createAdminUser();
}

module.exports = createAdminUser;
