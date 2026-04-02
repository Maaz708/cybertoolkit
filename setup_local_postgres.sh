#!/bin/bash

# 🗄️ Local PostgreSQL Setup for CyberToolkit
# Use this if you have PostgreSQL installed locally

echo "🗄️  CyberToolkit Local PostgreSQL Setup"
echo "======================================"

# Check if PostgreSQL is running
if ! pg_isready >/dev/null 2>&1; then
    echo "❌ PostgreSQL is not running."
    echo ""
    echo "Start PostgreSQL:"
    echo "  Windows: Services > Start postgresql-x64-15"
    echo "  macOS: brew services start postgresql"
    echo "  Linux: sudo systemctl start postgresql"
    exit 1
fi

echo "✅ PostgreSQL is running"
echo ""

# Create database
echo "🗃️  Creating cybertoolkit database..."
createdb cybertoolkit 2>/dev/null || echo "Database might already exist"

# Run the schema
echo "📋 Creating database tables..."
if psql -U postgres -d cybertoolkit -f server/database/schema.sql; then
    echo "✅ Database schema created successfully!"
else
    echo "❌ Failed to create database schema"
    echo "Make sure you can connect to PostgreSQL with: psql -U postgres"
    exit 1
fi

# Verify tables
echo "🔍 Verifying database tables..."
TABLES=$(psql -U postgres -d cybertoolkit -t -c "
    SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
" | tr -d ' ')

if [ "$TABLES" -gt 0 ]; then
    echo "✅ Created $TABLES database tables"
    
    # Show created tables
    echo ""
    echo "📊 Created tables:"
    psql -U postgres -d cybertoolkit -c "
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    " 2>/dev/null | grep -v "table_name" | grep -v "----" | grep -v "(" | sed 's/^/  - /'
else
    echo "❌ No tables were created"
    exit 1
fi

# Create admin user
echo ""
echo "👤 Creating admin user..."
if node server/create_admin.js; then
    echo "✅ Admin user created successfully!"
else
    echo "⚠️  Admin user creation failed, but you can create it manually later"
fi

echo ""
echo "🎉 Local PostgreSQL setup completed successfully!"
echo ""
echo "📊 Database Information:"
echo "   Host: localhost"
echo "   Port: 5432"
echo "   Database: cybertoolkit"
echo "   User: postgres"
echo ""
echo "🔑 Admin Credentials:"
echo "   Email: admin@cybertoolkit.com"
echo "   Password: admin123"
echo ""
echo "🔧 Useful Commands:"
echo "   Connect to database: psql -U postgres -d cybertoolkit"
echo "   View tables: \dt"
echo "   View users: SELECT id, email, role FROM users;"
echo ""
echo "🌐 Next Steps:"
echo "   1. Update .env file: DB_HOST=localhost"
echo "   2. Restart server: cd server && node index.js"
echo "   3. Visit: http://localhost:5173"
echo "   4. Login with admin credentials"
echo ""
