#!/bin/bash

# 🗄️ CyberToolkit Database Setup Script
# This script sets up the PostgreSQL database and creates the schema

set -e

echo "🗄️ Setting up CyberToolkit Database..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker first."
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed."
    exit 1
fi

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found. Creating from template..."
    cp .env.example .env
    print_warning "Please edit .env file with your database configuration!"
    read -p "Press Enter after editing .env file..."
fi

# Start PostgreSQL container
print_status "Starting PostgreSQL container..."
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
print_status "Waiting for PostgreSQL to be ready..."
for i in {1..60}; do
    if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        print_success "PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        print_error "PostgreSQL failed to start within 60 seconds"
        print_error "Check logs with: docker-compose logs postgres"
        exit 1
    fi
    echo -n "."
    sleep 1
done

# Create database if it doesn't exist
print_status "Creating database..."
docker-compose exec -T postgres psql -U postgres -c "
    SELECT 'CREATE DATABASE cybertoolkit'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cybertoolkit')\gexec
" 2>/dev/null || print_warning "Database might already exist"

# Run the schema
print_status "Running database schema..."
if docker-compose exec -T postgres psql -U postgres -d cybertoolkit -f /app/server/database/schema.sql; then
    print_success "Database schema created successfully!"
else
    print_error "Failed to run database schema"
    exit 1
fi

# Verify tables were created
print_status "Verifying database tables..."
TABLES=$(docker-compose exec -T postgres psql -U postgres -d cybertoolkit -t -c "
    SELECT COUNT(*) FROM information_schema.tables 
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
" | tr -d ' ')

if [ "$TABLES" -gt 0 ]; then
    print_success "Database tables created successfully! ($TABLES tables)"
    
    # Show created tables
    echo ""
    print_status "Created tables:"
    docker-compose exec -T postgres psql -U postgres -d cybertoolkit -c "
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    " 2>/dev/null | grep -v "table_name" | grep -v "----" | grep -v "(" | sed 's/^/  - /'
else
    print_error "No tables were created"
    exit 1
fi

# Create admin user
print_status "Creating admin user..."
if docker-compose exec -T backend node create_admin.js; then
    print_success "Admin user created successfully!"
else
    print_warning "Failed to create admin user. You can create it manually later."
fi

# Test database connection
print_status "Testing database connection..."
if docker-compose exec -T postgres psql -U postgres -d cybertoolkit -c "SELECT COUNT(*) FROM users;" >/dev/null 2>&1; then
    print_success "Database connection test passed!"
else
    print_error "Database connection test failed"
    exit 1
fi

echo ""
print_success "🎉 Database setup completed successfully!"
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
echo "   Connect to database: docker-compose exec postgres psql -U postgres -d cybertoolkit"
echo "   View database logs: docker-compose logs postgres"
echo "   Stop database: docker-compose stop postgres"
echo ""
echo "🌐 Next Steps:"
echo "   1. Start the application: ./deploy.sh"
echo "   2. Visit: http://localhost:5173"
echo "   3. Login with admin credentials"
echo ""
