#!/bin/bash

# 🚀 Quick PostgreSQL Setup for CyberToolkit
# This script gets you started with PostgreSQL immediately

echo "🗄️  CyberToolkit Quick PostgreSQL Setup"
echo "======================================"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    echo ""
    echo "Alternative: Install PostgreSQL locally:"
    echo "  Windows: https://www.postgresql.org/download/windows/"
    echo "  macOS: brew install postgresql"
    echo "  Linux: sudo apt install postgresql"
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Start PostgreSQL
echo "🐳 Starting PostgreSQL with Docker..."
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        echo "✅ PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ PostgreSQL failed to start within 30 seconds"
        echo "Check logs with: docker-compose logs postgres"
        exit 1
    fi
    echo -n "."
    sleep 1
done

echo ""

# Create database and run schema
echo "🗃️  Creating database and tables..."
docker-compose exec -T postgres psql -U postgres -c "CREATE DATABASE cybertoolkit;" 2>/dev/null || echo "Database might already exist"

# Run the schema
if docker-compose exec -T postgres psql -U postgres -d cybertoolkit -f /app/server/database/schema.sql; then
    echo "✅ Database schema created successfully!"
else
    echo "❌ Failed to create database schema"
    exit 1
fi

# Verify tables
echo "🔍 Verifying database tables..."
TABLES=$(docker-compose exec -T postgres psql -U postgres -d cybertoolkit -t -c "
    SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
" | tr -d ' ')

if [ "$TABLES" -gt 0 ]; then
    echo "✅ Created $TABLES database tables"
else
    echo "❌ No tables were created"
    exit 1
fi

# Create admin user
echo "👤 Creating admin user..."
if docker-compose exec -T backend node create_admin.js; then
    echo "✅ Admin user created successfully!"
else
    echo "⚠️  Admin user creation failed, but you can create it manually later"
fi

echo ""
echo "🎉 PostgreSQL setup completed successfully!"
echo ""
echo "📊 Database Information:"
echo "   Host: localhost"
echo "   Port: 5432"
echo "   Database: cybertoolkit"
echo "   User: postgres"
echo "   Password: postgres123"
echo ""
echo "🔑 Admin Credentials:"
echo "   Email: admin@cybertoolkit.com"
echo "   Password: admin123"
echo ""
echo "🔧 Useful Commands:"
echo "   Connect to database: docker-compose exec postgres psql -U postgres -d cybertoolkit"
echo "   View database logs: docker-compose logs postgres"
echo "   Stop database: docker-compose stop postgres"
echo "   Restart database: docker-compose restart postgres"
echo ""
echo "🌐 Next Steps:"
echo "   1. Your server should automatically connect to PostgreSQL"
echo "   2. If server is running, restart it: cd server && node index.js"
echo "   3. Visit: http://localhost:5173"
echo "   4. Login with admin credentials"
echo ""
