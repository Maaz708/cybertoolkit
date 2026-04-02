# 🗄️ PostgreSQL Setup Guide for CyberToolkit

## 📋 Option 1: Docker (Recommended for Development)

### Prerequisites
- Docker Desktop installed and running

### Quick Setup
```bash
# Start PostgreSQL with Docker
docker-compose up -d postgres

# Check if it's running
docker-compose ps postgres

# Connect to database
docker-compose exec postgres psql -U postgres -d cybertoolkit
```

### Docker Configuration
Your `docker-compose.yml` already has PostgreSQL configured:
```yaml
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_DB: cybertoolkit
    POSTGRES_USER: postgres
    POSTGRES_PASSWORD: postgres123
  ports:
    - "5432:5432"
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./server/database/schema.sql:/docker-entrypoint-initdb.d/schema.sql
```

---

## 📋 Option 2: Local PostgreSQL Installation

### Windows Installation
1. **Download PostgreSQL**: https://www.postgresql.org/download/windows/
2. **Run Installer**: Choose password `postgres123`
3. **Install pgAdmin** (included in installer)
4. **Note the port** (usually 5432)

### macOS Installation
```bash
# Using Homebrew
brew install postgresql
brew services start postgresql

# Create database and user
createdb cybertoolkit
createuser -s postgres
```

### Linux Installation
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo -u postgres psql

# Create database and user
CREATE DATABASE cybertoolkit;
CREATE USER postgres WITH PASSWORD 'postgres123';
GRANT ALL PRIVILEGES ON DATABASE cybertoolkit TO postgres;
\q
```

---

## 🔧 Step 2: Create Database and Tables

### Method 1: Automatic with Docker
Docker will automatically create the database and run the schema.

### Method 2: Manual Setup
```bash
# Connect to PostgreSQL
psql -U postgres -h localhost -p 5432

# Create database
CREATE DATABASE cybertoolkit;

# Connect to your database
\c cybertoolkit

# Run the schema (copy-paste the content from server/database/schema.sql)
# Or run it from file:
\i /path/to/cybertoolkit/server/database/schema.sql
```

### Method 3: Use Our Setup Script
```bash
# Make executable
chmod +x setup_database.sh

# Run the setup
./setup_database.sh
```

---

## 🎯 Step 3: Update Configuration

### Update .env for PostgreSQL
```bash
# Database Configuration
DB_HOST=localhost          # or 'postgres' for Docker
DB_PORT=5432
DB_NAME=cybertoolkit
DB_USER=postgres
DB_PASSWORD=postgres123    # Use your actual password
```

### For Docker, use:
```bash
DB_HOST=postgres
DB_PASSWORD=postgres123
```

---

## 🚀 Step 4: Test the Connection

### Test Server Connection
```bash
cd server
node index.js
```

You should see:
```
✅ PostgreSQL connection configured
🚀 CyberToolkit Server Started Successfully
```

### Test Database Connection
```bash
# Connect directly
psql -U postgres -h localhost -p 5432 -d cybertoolkit

# Check tables
\dt

# Should show:
# users, network_scans, network_connections, file_scans, email_analyses, alerts, user_sessions, api_usage, system_metrics
```

---

## 🏭 Production Setup

### 1. Secure PostgreSQL
```sql
-- Connect as postgres superuser
psql -U postgres

-- Create dedicated app user
CREATE USER cybertoolkit_app WITH PASSWORD 'your_secure_production_password';

-- Grant necessary permissions
GRANT CONNECT ON DATABASE cybertoolkit TO cybertoolkit_app;
GRANT USAGE ON SCHEMA public TO cybertoolkit_app;
GRANT CREATE ON SCHEMA public TO cybertoolkit_app;

-- Switch to cybertoolkit database
\c cybertoolkit

-- Grant table permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cybertoolkit_app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO cybertoolkit_app;

-- Set default permissions for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO cybertoolkit_app;
```

### 2. Update Production .env
```bash
# Production Database Settings
DB_HOST=your-production-db-host
DB_PORT=5432
DB_NAME=cybertoolkit_prod
DB_USER=cybertoolkit_app
DB_PASSWORD=your_secure_production_password

# Security Settings
NODE_ENV=production
JWT_SECRET=your_super_secure_jwt_secret_for_production
```

### 3. PostgreSQL Performance Tuning
```sql
-- Connect to your database
psql -U postgres -d cybertoolkit

-- Create indexes for performance
CREATE INDEX CONCURRENTLY idx_users_email_active ON users(email, is_active);
CREATE INDEX CONCURRENTLY idx_network_scans_user_created ON network_scans(user_id, created_at);
CREATE INDEX CONCURRENTLY idx_network_connections_scan_time ON network_connections(scan_id, captured_at);

-- Update statistics
ANALYZE;
```

### 4. Backup Strategy
```bash
# Create backup script
cat > backup_db.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="cybertoolkit"

# Create backup
pg_dump -U postgres -h localhost -p 5432 $DB_NAME > $BACKUP_DIR/backup_$DATE.sql

# Compress old backups
find $BACKUP_DIR -name "backup_*.sql" -mtime +7 -exec gzip {} \;

# Keep only last 30 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +30 -delete

echo "Backup completed: backup_$DATE.sql"
EOF

chmod +x backup_db.sh

# Add to crontab for daily backups
crontab -e
# Add: 0 2 * * * /path/to/backup_db.sh
```

---

## 🌐 Production Deployment Options

### Option 1: Self-Hosted
```bash
# Production server setup
sudo apt update
sudo apt install postgresql postgresql-contrib

# Secure PostgreSQL
sudo -u postgres psql
# Follow security steps above

# Deploy with Docker Compose
docker-compose -f docker-compose.prod.yml up -d
```

### Option 2: Cloud PostgreSQL
#### AWS RDS
```bash
# Create RDS instance via AWS Console
# Use these settings:
# Engine: PostgreSQL 15+
# Instance: db.t3.micro (dev) or db.t3.small (prod)
# Storage: 20GB minimum
# VPC: Default or custom
# Security: Add your server IP to inbound rules
```

#### Google Cloud SQL
```bash
# Create Cloud SQL instance
gcloud sql instances create cybertoolkit-db \
    --database-version=POSTGRES_15 \
    --tier=db-custom-2-8192 \
    --region=us-central1 \
    --authorized-networks=YOUR_SERVER_IP
```

#### Azure Database
```bash
# Create via Azure Portal or CLI
az postgres server create \
    --name cybertoolkit-db \
    --resource-group myResourceGroup \
    --sku B_Gen5_1 \
    --admin-user cybertoolkit \
    --admin-password YOUR_SECURE_PASSWORD
```

---

## 🔍 Monitoring and Maintenance

### 1. Connection Monitoring
```sql
-- Check active connections
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;

-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

### 2. Performance Monitoring
```bash
# Install pg_stat_statements
psql -U postgres -d cybertoolkit -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"

# Monitor database size
psql -U postgres -d cybertoolkit -c "
SELECT 
    pg_size_pretty(pg_database_size('cybertoolkit')) as database_size;
"
```

### 3. Health Check Script
```bash
cat > health_check.sh << 'EOF'
#!/bin/bash
# Database health check
if pg_isready -U postgres -h localhost -p 5432; then
    echo "✅ PostgreSQL is ready"
else
    echo "❌ PostgreSQL is not ready"
    exit 1
fi

# Check if tables exist
TABLES=$(psql -U postgres -h localhost -p 5432 -d cybertoolkit -t -c "
    SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
")

if [ "$TABLES" -gt "0" ]; then
    echo "✅ Database tables exist"
else
    echo "❌ No tables found"
    exit 1
fi

echo "✅ Database is healthy"
EOF

chmod +x health_check.sh
```

---

## 🎯 Quick Start Commands

### Development (Docker)
```bash
# Start everything
docker-compose up -d

# Setup database
./setup_database.sh

# Test connection
./health_check.sh
```

### Production
```bash
# Deploy to production
./deploy.sh

# Monitor database
docker-compose logs -f postgres

# Backup database
./backup_db.sh
```

---

## 📞 Troubleshooting

### Common Issues
1. **"Connection refused"** → PostgreSQL not running or wrong port
2. **"Authentication failed"** → Wrong password in .env
3. **"Database does not exist"** → Run schema creation
4. **"Permission denied"** → Check user permissions

### Debug Commands
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check logs
sudo tail -f /var/log/postgresql/postgresql-15-main.log

# Test connection manually
psql -U postgres -h localhost -p 5432 -d cybertoolkit -c "SELECT version();"
```

Your PostgreSQL database is now ready for development and production! 🚀
