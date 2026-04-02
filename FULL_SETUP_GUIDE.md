# 🚀 CyberToolkit Complete Setup Guide

## 📋 What You're Getting

A **complete, production-ready Digital Forensics SaaS Platform** with:

✅ **User Authentication** - Login, Register, JWT tokens  
✅ **Multi-Tenant Database** - PostgreSQL with Row Level Security  
✅ **Real-Time Monitoring** - Network monitoring with WebSocket  
✅ **Production Security** - Rate limiting, validation, logging  
✅ **Docker Deployment** - One-command deployment  
✅ **Beautiful UI** - Modern React dashboard with authentication  

---

## 🎯 Quick Start (5 Minutes)

### **Step 1: Clone & Prepare**
```bash
# If you just cloned the repo, you're already here!
cd cybertoolkit

# Make scripts executable (Linux/Mac)
chmod +x deploy.sh setup_database.sh
```

### **Step 2: Configure Environment**
```bash
# Copy environment template
cp .env.example .env

# IMPORTANT: Edit the .env file!
nano .env  # or use any text editor
```

**MUST CHANGE these values in `.env`:**
```bash
JWT_SECRET=your_super_secure_jwt_secret_change_this_now_12345
DB_PASSWORD=your_secure_database_password_12345
REDIS_PASSWORD=your_secure_redis_password_12345
```

### **Step 3: One-Command Deploy**
```bash
# This does EVERYTHING: database, backend, frontend, admin user
./deploy.sh
```

### **Step 4: Access Your Application**
- **Frontend**: http://localhost:5173
- **Login**: admin@cybertoolkit.com / admin123
- **Backend API**: http://localhost:5000

---

## 🔧 Manual Setup (If You Want Control)

### **Option A: Database Only**
```bash
# Setup just the database
./setup_database.sh
```

### **Option B: Full Manual Setup**
```bash
# 1. Start database
docker-compose up -d postgres redis

# 2. Wait 30 seconds, then create schema
docker-compose exec postgres psql -U postgres -d cybertoolkit -f server/database/schema.sql

# 3. Create admin user
docker-compose exec backend node create_admin.js

# 4. Start backend
docker-compose up -d backend

# 5. Start frontend (in new terminal)
cd src
npm install
npm run dev
```

---

## 🗄️ Database Setup Details

### **What Gets Created:**

#### **Tables:**
- `users` - User accounts and authentication
- `network_scans` - Network monitoring sessions
- `network_connections` - Individual connection data
- `file_scans` - File analysis results
- `email_analyses` - Email forensics results
- `alerts` - Security alerts and notifications
- `user_sessions` - JWT session management
- `api_usage` - API usage tracking
- `system_metrics` - System performance metrics

#### **Security Features:**
- **Row Level Security** - Users can only see their own data
- **Password Hashing** - Bcrypt with 12 rounds
- **JWT Authentication** - Secure token-based auth
- **Session Management** - Track active sessions

### **Database Connection:**
```bash
# Connect to database
docker-compose exec postgres psql -U postgres -d cybertoolkit

# View tables
\dt

# View users
SELECT id, email, role, created_at FROM users;

# Check network scans
SELECT * FROM network_scans WHERE user_id = 'your-user-id';
```

---

## 🔐 Authentication System

### **How It Works:**

1. **User Registration**
   ```bash
   # POST /api/auth/register
   {
     "email": "user@example.com",
     "password": "securePassword123",
     "firstName": "John",
     "lastName": "Doe",
     "companyName": "Acme Corp"  # Optional
   }
   ```

2. **User Login**
   ```bash
   # POST /api/auth/login
   {
     "email": "user@example.com",
     "password": "securePassword123"
   }
   # Returns: { token, user }
   ```

3. **Authenticated Requests**
   ```bash
   # All protected endpoints need:
   Authorization: Bearer <jwt-token>
   ```

### **Frontend Authentication:**
- **Login Page**: `/login` - Beautiful login form
- **Register Page**: `/register` - User registration
- **Protected Routes**: All dashboard pages require login
- **Auto-Logout**: When token expires, user is redirected to login

---

## 🌐 Frontend Features

### **Pages:**
- **Dashboard** (`/`) - Main overview with real-time stats
- **Network Monitor** (`/network-monitor`) - Live network monitoring
- **File Analysis** (`/file-analysis`) - File forensic tools
- **Malware Detection** (`/malware-detection`) - Threat scanning
- **Email Forensics** (`/email-forensics`) - Email analysis
- **File Recovery** (`/file-recovery`) - Data recovery tools

### **Authentication UI:**
- **Login Form** - Modern glassmorphism design
- **Register Form** - Complete user registration
- **User Menu** - Profile dropdown with logout
- **Protected Routes** - Automatic redirect to login

---

## 🛡️ Security Features

### **Backend Security:**
- **JWT Authentication** - Secure token-based auth
- **Rate Limiting** - 100 requests per 15 minutes
- **Input Validation** - Joi schemas for all inputs
- **XSS Protection** - Input sanitization
- **CORS Protection** - Configurable allowed origins
- **Security Headers** - Helmet.js protection
- **SQL Injection Protection** - Parameterized queries

### **Database Security:**
- **Row Level Security** - Multi-tenant data isolation
- **Password Hashing** - Bcrypt with 12 rounds
- **Session Management** - JWT token tracking
- **User Isolation** - Each user sees only their data

---

## 📊 Real-Time Monitoring

### **Network Monitoring:**
```bash
# Start monitoring (requires auth)
POST /api/network/start
{
  "interval": 3000  // milliseconds
}

# Stop monitoring
POST /api/network/stop

# Get status
GET /api/network/status
```

### **WebSocket Updates:**
- Real-time network data streaming
- Automatic connection management
- User-specific data streams

---

## 🐳 Docker Deployment

### **Services:**
- **postgres** - PostgreSQL database
- **redis** - Redis caching
- **backend** - Node.js API server
- **nginx** - Load balancer (optional)

### **Commands:**
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Restart services
docker-compose restart

# Clean up everything
docker-compose down -v --rmi all
```

---

## 🔍 Troubleshooting

### **Common Issues:**

#### **"Database connection failed"**
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart database
docker-compose restart postgres
```

#### **"JWT token invalid"**
```bash
# Check your JWT_SECRET in .env
grep JWT_SECRET .env

# Make sure it's the same in backend
docker-compose exec backend printenv | grep JWT_SECRET

# Clear browser localStorage and login again
```

#### **"Port already in use"**
```bash
# Kill existing processes
sudo lsof -ti:5000 | xargs kill -9
sudo lsof -ti:8080 | xargs kill -9

# Restart services
docker-compose down && docker-compose up -d
```

#### **Frontend not loading**
```bash
# Check if frontend is running
cd src
npm run dev

# Or check if backend is accessible
curl http://localhost:5000/api/network/status
```

### **Health Checks:**
```bash
# Backend health
curl http://localhost:5000/api/network/status

# Database health
docker-compose exec postgres pg_isready -U postgres

# Redis health
docker-compose exec redis redis-cli ping
```

---

## 📈 Production Deployment

### **For Production:**

1. **Update .env for production**
   ```bash
   NODE_ENV=production
   FRONTEND_URL=https://your-domain.com
   ```

2. **Get SSL Certificate**
   ```bash
   # Use Let's Encrypt or your provider
   certbot --nginx -d your-domain.com
   ```

3. **Set up Domain DNS**
   - Point your domain to your server IP
   - Configure A records for subdomains

4. **Configure Firewall**
   ```bash
   # Only allow necessary ports
   ufw allow 80/tcp
   ufw allow 443/tcp
   ufw enable
   ```

5. **Set up Backups**
   ```bash
   # Automated database backups
   0 2 * * * docker-compose exec postgres pg_dump -U postgres cybertoolkit > backup_$(date +\%Y\%m\%d).sql
   ```

---

## 🎉 You're Ready!

### **What You Have Now:**
✅ **Complete SaaS Platform** - Ready for millions of users  
✅ **Secure Authentication** - JWT with session management  
✅ **Multi-Tenant Database** - Each user isolated  
✅ **Real-Time Monitoring** - WebSocket updates  
✅ **Production Security** - Multiple layers of protection  
✅ **Scalable Architecture** - Docker ready for cloud deployment  

### **Next Steps:**
1. **Customize the UI** - Add your branding
2. **Add More Features** - File upload, email analysis
3. **Set Up Monitoring** - Add analytics and alerting
4. **Deploy to Cloud** - AWS, DigitalOcean, etc.

### **Need Help?**
- Check logs: `./deploy.sh logs`
- Check status: `./deploy.sh status`
- Restart: `./deploy.sh restart`

**Your Digital Forensics Toolkit is now a production-ready SaaS platform!** 🚀✨
