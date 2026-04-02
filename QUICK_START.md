# 🚀 CyberToolkit Quick Start Guide

## 🎯 What You Need to Deploy

### Prerequisites
- Docker & Docker Compose installed
- A domain name (optional, for SSL)
- Cloud server (AWS EC2, DigitalOcean, etc.) or local machine

---

## 📝 Step 1: Configure Environment

### 1.1 Update your .env file
```bash
# Open the environment file
nano .env
```

**CRITICAL - Update these values:**
```bash
# Change these to SECURE values
JWT_SECRET=your_super_secure_jwt_secret_change_this_now_12345
DB_PASSWORD=your_secure_database_password_12345
REDIS_PASSWORD=your_secure_redis_password_12345

# Your domain (if you have one)
FRONTEND_URL=https://your-domain.com
FRONTEND_URL_PROD=https://your-domain.com

# Production settings
NODE_ENV=production
PORT=5000
```

### 1.2 Create Production .env
```bash
# Copy for production
cp .env .env.production

# Edit production values
nano .env.production
```

---

## 🐳 Step 2: Deploy with Docker

### 2.1 Quick Deploy (Local/Development)
```bash
# Start all services
docker-compose up -d

# Check if everything is running
docker-compose ps

# View logs
docker-compose logs -f
```

### 2.2 Production Deploy
```bash
# Use production environment
docker-compose --env-file .env.production up -d

# Scale if needed
docker-compose --env-file .env.production up -d --scale backend=3
```

---

## 🗄️ Step 3: Setup Database

### 3.1 Initialize Database
```bash
# Wait for PostgreSQL to be ready (30 seconds)
sleep 30

# Connect to database
docker-compose exec postgres psql -U postgres -d cybertoolkit

# Run the schema (inside psql)
\i /app/server/database/schema.sql

# Exit psql
\q
```

### 3.2 Verify Database
```bash
# Check tables were created
docker-compose exec postgres psql -U postgres -d cybertoolkit -c "\dt"

# Should show: users, network_scans, network_connections, etc.
```

---

## 🔐 Step 4: Create Admin User & Authentication

### 4.1 Create Authentication Endpoints
The system needs these endpoints to work:

```javascript
// Add these to your server/index.js

// Register new user
app.post('/api/auth/register', validate('register'), async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// Login user
app.post('/api/auth/login', validate('login'), async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query(
      'SELECT id, email, password_hash FROM users WHERE email = $1',
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, config.jwt.secret);
    
    res.json({ 
      success: true, 
      token, 
      user: { id: user.id, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});
```

### 4.2 Create First Admin User
```bash
# Create a simple script to create admin
cat > create_admin.js << 'EOF'
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const pool = new Pool({
  host: 'localhost',
  port: 5432,
  database: 'cybertoolkit',
  user: 'postgres',
  password: process.env.DB_PASSWORD
});

async function createAdmin() {
  const hashedPassword = await bcrypt.hash('admin123', 12);
  
  await pool.query(
    'INSERT INTO users (email, password_hash, role, is_active) VALUES ($1, $2, $3, $4)',
    ['admin@cybertoolkit.com', hashedPassword, 'admin', true]
  );
  
  console.log('✅ Admin user created: admin@cybertoolkit.com / admin123');
  await pool.end();
}

createAdmin();
EOF

# Run the script
docker-compose exec backend node create_admin.js
```

---

## 🌐 Step 5: Access Your Application

### 5.1 Test the Backend
```bash
# Test if backend is working
curl http://localhost:5000/api/network/status

# Should return: {"isMonitoring":false,"timestamp":"..."}
```

### 5.2 Login & Get Token
```bash
# Login as admin
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cybertoolkit.com","password":"admin123"}'

# You'll get a token like:
# {"success":true,"token":"eyJhbGciOiJIUzI1NiIs...","user":{...}}
```

### 5.3 Use the Application
1. **Frontend**: http://localhost:5173 (or your domain)
2. **Login**: Use admin@cybertoolkit.com / admin123
3. **Backend API**: http://localhost:5000
4. **WebSocket**: ws://localhost:8080

---

## 🔍 Step 6: Verify Everything Works

### 6.1 Check All Services
```bash
# Check all containers are running
docker-compose ps

# Should show:
# cybertoolkit-backend   Up
# cybertoolkit-postgres  Up  
# cybertoolkit-redis     Up
# cybertoolkit-nginx     Up
```

### 6.2 Test Network Monitoring
```bash
# Start monitoring (using your token)
TOKEN="your_jwt_token_here"
curl -X POST http://localhost:5000/api/network/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interval": 3000}'

# Check status
curl http://localhost:5000/api/network/status \
  -H "Authorization: Bearer $TOKEN"

# Should show: {"isMonitoring":true,...}
```

### 6.3 Check Database
```bash
# Check if data is being stored
docker-compose exec postgres psql -U postgres -d cybertoolkit -c "
  SELECT COUNT(*) FROM users;
  SELECT COUNT(*) FROM network_scans;
"
```

---

## 🚨 Common Issues & Solutions

### Issue: "Database connection failed"
```bash
# Solution: Check if PostgreSQL is ready
docker-compose logs postgres

# Wait and retry
sleep 10
docker-compose restart backend
```

### Issue: "JWT token invalid"
```bash
# Solution: Check your JWT_SECRET in .env
grep JWT_SECRET .env

# Make sure it's the same in backend
docker-compose exec backend printenv | grep JWT_SECRET
```

### Issue: "Port already in use"
```bash
# Solution: Kill existing processes
sudo lsof -ti:5000 | xargs kill -9
sudo lsof -ti:8080 | xargs kill -9

# Restart services
docker-compose down && docker-compose up -d
```

---

## 🎯 Next Steps

### For Production:
1. **Get SSL Certificate** (Let's Encrypt)
2. **Set up Domain** (DNS pointing to your server)
3. **Configure Firewall** (only open 80, 443)
4. **Set up Backups** (automated database backups)
5. **Monitor Performance** (set up monitoring tools)

### For Development:
1. **Add More Features** (file upload, email analysis)
2. **Improve UI** (better dashboard, charts)
3. **Add Tests** (unit tests, integration tests)
4. **Documentation** (API docs, user guides)

---

## 📞 Need Help?

If you get stuck:
1. Check logs: `docker-compose logs -f`
2. Verify .env file
3. Check database connection
4. Ensure all ports are available

Your CyberToolkit is now ready for users! 🎉
