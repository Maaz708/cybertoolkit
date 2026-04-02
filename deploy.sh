#!/bin/bash

# 🚀 CyberToolkit Deployment Script
# This script deploys the entire application

set -e  # Exit on any error

echo "🚀 Starting CyberToolkit Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Check environment file
check_env() {
    if [ ! -f .env ]; then
        print_warning ".env file not found. Creating from template..."
        cp .env.example .env
        print_warning "Please edit .env file with your configuration before continuing!"
        print_warning "Especially set JWT_SECRET, DB_PASSWORD, and REDIS_PASSWORD"
        read -p "Press Enter after editing .env file..."
    fi
    
    # Check if critical values are changed
    if grep -q "your_password_here" .env || grep -q "change_this" .env; then
        print_error "Please update the default passwords and secrets in .env file!"
        exit 1
    fi
    
    print_success "Environment file is configured"
}

# Stop existing services
stop_services() {
    print_status "Stopping existing services..."
    docker-compose down 2>/dev/null || true
    print_success "Services stopped"
}

# Build and start services
start_services() {
    print_status "Building and starting services..."
    docker-compose up -d --build
    
    print_status "Waiting for services to be ready..."
    sleep 30
    
    # Check if services are running
    if ! docker-compose ps | grep -q "Up"; then
        print_error "Services failed to start. Check logs with: docker-compose logs"
        exit 1
    fi
    
    print_success "All services are running"
}

# Initialize database
init_database() {
    print_status "Initializing database..."
    
    # Wait for PostgreSQL to be ready
    print_status "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
            print_success "PostgreSQL is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "PostgreSQL failed to start within 30 seconds"
            exit 1
        fi
        sleep 1
    done
    
    # Run schema
    print_status "Running database schema..."
    docker-compose exec -T postgres psql -U postgres -d cybertoolkit -f /app/server/database/schema.sql
    
    print_success "Database initialized"
}

# Create admin user
create_admin() {
    print_status "Creating admin user..."
    docker-compose exec -T backend node create_admin.js
    print_success "Admin user created"
}

# Verify deployment
verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check backend health
    if curl -s http://localhost:5000/api/network/status >/dev/null; then
        print_success "Backend API is responding"
    else
        print_error "Backend API is not responding"
        return 1
    fi
    
    # Check database connection
    if docker-compose exec -T postgres psql -U postgres -d cybertoolkit -c "SELECT COUNT(*) FROM users;" >/dev/null 2>&1; then
        print_success "Database connection is working"
    else
        print_error "Database connection failed"
        return 1
    fi
    
    print_success "Deployment verification completed"
}

# Show access information
show_access_info() {
    echo ""
    print_success "🎉 CyberToolkit deployed successfully!"
    echo ""
    echo "📱 Access Information:"
    echo "   Frontend: http://localhost:5173"
    echo "   Backend API: http://localhost:5000"
    echo "   WebSocket: ws://localhost:8080"
    echo ""
    echo "🔐 Admin Login:"
    echo "   Email: admin@cybertoolkit.com"
    echo "   Password: admin123"
    echo ""
    echo "🔧 Useful Commands:"
    echo "   View logs: docker-compose logs -f"
    echo "   Stop services: docker-compose down"
    echo "   Restart services: docker-compose restart"
    echo ""
    echo "📊 Database Access:"
    echo "   Connect: docker-compose exec postgres psql -U postgres -d cybertoolkit"
    echo ""
}

# Main deployment function
main() {
    echo "🔍 Starting deployment checks..."
    check_docker
    check_env
    
    echo ""
    echo "🛑 Stopping existing services..."
    stop_services
    
    echo ""
    echo "🚀 Starting services..."
    start_services
    
    echo ""
    echo "🗄️ Setting up database..."
    init_database
    
    echo ""
    echo "👤 Creating admin user..."
    create_admin
    
    echo ""
    echo "✅ Verifying deployment..."
    if verify_deployment; then
        show_access_info
    else
        print_error "Deployment verification failed. Check logs for errors."
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "stop")
        stop_services
        ;;
    "restart")
        stop_services
        start_services
        ;;
    "logs")
        docker-compose logs -f
        ;;
    "status")
        docker-compose ps
        ;;
    "clean")
        print_warning "This will remove all containers, volumes, and images!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down -v --rmi all
            print_success "All resources cleaned up"
        fi
        ;;
    "help"|"-h"|"--help")
        echo "CyberToolkit Deployment Script"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)  Full deployment"
        echo "  stop       Stop all services"
        echo "  restart    Restart all services"
        echo "  logs       Show logs"
        echo "  status     Show service status"
        echo "  clean      Remove all containers, volumes, and images"
        echo "  help       Show this help"
        ;;
    *)
        main
        ;;
esac
