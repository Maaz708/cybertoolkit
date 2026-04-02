# PowerShell script for PostgreSQL setup
Write-Host "🗄️  CyberToolkit Local PostgreSQL Setup" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Check if PostgreSQL is running
try {
    $result = & psql --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL is installed" -ForegroundColor Green
    } else {
        Write-Host "❌ PostgreSQL is not installed or not in PATH" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ PostgreSQL is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Create database
Write-Host "🗃️  Creating cybertoolkit database..." -ForegroundColor Yellow
try {
    & createdb -U postgres cybertoolkit 2>$null
    Write-Host "✅ Database created or already exists" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Database might already exist" -ForegroundColor Yellow
}

# Run the schema
Write-Host "📋 Creating database tables..." -ForegroundColor Yellow
try {
    & psql -U postgres -d cybertoolkit -f server/database/schema.sql
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Database schema created successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to create database schema" -ForegroundColor Red
        Write-Host "Make sure you can connect to PostgreSQL with: psql -U postgres" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Failed to create database schema" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

# Verify tables
Write-Host "🔍 Verifying database tables..." -ForegroundColor Yellow
try {
    $tables = & psql -U postgres -d cybertoolkit -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';"
    $tables = $tables.Trim()
    
    if ([int]$tables -gt 0) {
        Write-Host "✅ Created $tables database tables" -ForegroundColor Green
        
        # Show created tables
        Write-Host "" -ForegroundColor White
        Write-Host "📊 Created tables:" -ForegroundColor Cyan
        $tableList = & psql -U postgres -d cybertoolkit -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name;" 2>$null
        $tableList | Where-Object { $_ -match "^[a-z_]" } | ForEach-Object { Write-Host "  - $_.Trim()" -ForegroundColor White }
    } else {
        Write-Host "❌ No tables were created" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Failed to verify tables" -ForegroundColor Red
    exit 1
}

# Create admin user
Write-Host "" -ForegroundColor White
Write-Host "👤 Creating admin user..." -ForegroundColor Yellow
try {
    & node server/create_admin.js
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Admin user created successfully!" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Admin user creation failed, but you can create it manually later" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️  Admin user creation failed, but you can create it manually later" -ForegroundColor Yellow
}

Write-Host "" -ForegroundColor White
Write-Host "🎉 Local PostgreSQL setup completed successfully!" -ForegroundColor Green
Write-Host "" -ForegroundColor White
Write-Host "📊 Database Information:" -ForegroundColor Cyan
Write-Host "   Host: localhost" -ForegroundColor White
Write-Host "   Port: 5432" -ForegroundColor White
Write-Host "   Database: cybertoolkit" -ForegroundColor White
Write-Host "   User: postgres" -ForegroundColor White
Write-Host "   Password: blogroots" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "🔑 Admin Credentials:" -ForegroundColor Cyan
Write-Host "   Email: admin@cybertoolkit.com" -ForegroundColor White
Write-Host "   Password: admin123" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "🔧 Useful Commands:" -ForegroundColor Cyan
Write-Host "   Connect to database: psql -U postgres -d cybertoolkit" -ForegroundColor White
Write-Host "   View tables: \dt" -ForegroundColor White
Write-Host "   View users: SELECT id, email, role FROM users;" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "🌐 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Restart server: cd server && node index.js" -ForegroundColor White
Write-Host "   2. Visit: http://localhost:5173" -ForegroundColor White
Write-Host "   3. Login with admin credentials" -ForegroundColor White
Write-Host "" -ForegroundColor White
