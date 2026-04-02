# Digital Forensics Toolkit

A comprehensive digital forensics platform built with React, Node.js, and Material-UI providing File Analysis, Network Monitoring, Malware Detection, Email Forensics, and File Recovery capabilities.

## 🚀 Features

### 🔍 File Analysis
- **Metadata Extraction**: Extract detailed file metadata and properties
- **Content Inspection**: Perform in-depth content analysis
- **Hash Generation**: Generate MD5, SHA-1, and SHA-256 hashes
- **Timeline Analysis**: View file creation, modification, and access times
- **Multi-Format Support**: Analyze various file formats
- **Report Generation**: Generate detailed analysis reports

### 🌐 Network Monitoring
- **Real-time Traffic Analysis**: Monitor network traffic live with WebSocket updates
- **Protocol Analysis**: Analyze network protocol distribution
- **Connection Tracking**: Track active connections and bandwidth usage
- **Security Alerts**: Get real-time security alerts with severity scoring
- **Port Scanning Detection**: Identify port scanning activities
- **Historical Data Analysis**: Review historical network activity with charts
- **Hacker Map**: Visualize attack origins on world map

### 🛡️ Malware Detection
- **Real-time Scanning**: Monitor files continuously
- **Signature Matching**: Detect known malware signatures
- **Behavioral Analysis**: Identify suspicious patterns
- **File Quarantine**: Isolate suspicious files
- **Threat Reports**: Generate detailed threat analysis reports
- **VirusTotal Integration**: Check files against VirusTotal database

### 📧 Email Forensics
- **Header Analysis**: Analyze email headers for authenticity
- **Attachment Scanning**: Check attachments for malware
- **Phishing Detection**: Identify phishing attempts
- **Timeline Reconstruction**: Rebuild email timelines
- **Metadata Extraction**: Extract relevant email metadata
- **SPF/DKIM Verification**: Validate email authentication

### 💾 File Recovery
- **Deleted File Recovery**: Restore accidentally deleted files
- **Corrupted File Repair**: Attempt to repair damaged files
- **Deep Scan**: Perform thorough disk scans
- **Preview Files**: Preview recoverable files before recovery
- **Multiple Formats**: Support for various file types

## 🛠️ Tech Stack

### Frontend
- **React 18** - Modern React with hooks
- **TypeScript** - Type-safe development
- **Material-UI (MUI)** - Modern UI components
- **React Router** - Client-side routing
- **Axios** - HTTP client
- **Recharts** - Data visualization
- **Socket.io Client** - Real-time updates

### Backend
- **Node.js** - JavaScript runtime
- **Express.js** - Web framework
- **Socket.io** - Real-time WebSocket server
- **PostgreSQL** - Primary database
- **Redis** - Caching (with memory fallback)
- **JWT** - Authentication
- **Winston** - Logging
- **Swagger** - API documentation

### DevOps & Deployment
- **Render.com** - Backend hosting (free tier)
- **Netlify** - Frontend hosting (free tier)
- **Supabase** - Database hosting (free tier)
- **Vite** - Build tool
- **Docker** - Containerization support

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux, or macOS
- **RAM**: 8GB minimum (16GB recommended)
- **Disk Space**: 10GB free
- **Node.js**: v18.x or higher
- **Git**: Latest version

### Required Software
1. **Node.js** - [Download here](https://nodejs.org/en/download)
2. **Git** - [Download here](https://git-scm.com/downloads)
3. **VS Code** (Recommended) - [Download here](https://code.visualstudio.com/download)

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/Maaz708/cybertoolkit.git
cd cybertoolkit
```

### 2. Install Dependencies
```bash
# Install all dependencies (frontend + backend)
npm install
```

### 3. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Default values work for local development
```

### 4. Start Development Server
```bash
# Start backend server
npm run start

# In new terminal, start frontend
npm run dev
```

### 5. Access Application
- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:5000
- **API Docs**: http://localhost:5000/api-docs

## 🗄️ Database Setup

### Option 1: PostgreSQL (Recommended)
```bash
# Install PostgreSQL
# Windows: https://www.postgresql.org/download/windows/
# Mac: brew install postgresql
# Linux: sudo apt-get install postgresql postgresql-contrib

# Create database
createdb cybertoolkit

# Run setup script
psql -d cybertoolkit -f server/database/init.sql
```

### Option 2: In-Memory (Development Only)
The app automatically falls back to in-memory storage if PostgreSQL is not available.

## 🔧 Configuration

### Environment Variables
```bash
# Server Configuration
PORT=5000
NODE_ENV=development

# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/cybertoolkit

# JWT
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h

# CORS
FRONTEND_URL=http://localhost:5173
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000

# Redis (Optional - uses memory fallback if not available)
REDIS_URL=redis://localhost:6379
```

## 🚀 Deployment

### Production Deployment (Free Tier)

#### 1. Backend (Render.com)
```bash
# Push to GitHub
git add .
git commit -m "Ready for deployment"
git push origin main

# Deploy to Render
# 1. Go to render.com
# 2. New Web Service → Connect GitHub
# 3. Use render.yaml blueprint
# 4. Add environment variables
```

#### 2. Database (Supabase)
```bash
# 1. Create free project at supabase.com
# 2. Run SQL from server/database/init.sql
# 3. Copy connection string to Render env vars
```

#### 3. Frontend (Netlify)
```bash
# Build and deploy
npm run build
npx netlify-cli deploy --prod --dir=dist
```

### Environment Variables for Production
```bash
DATABASE_URL=postgresql://postgres:password@db.xxxxx.supabase.co:5432/postgres
JWT_SECRET=your-256-bit-secret-key
ALLOWED_ORIGINS=https://your-site.netlify.app
FRONTEND_PROD_URL=https://your-site.netlify.app
```

## 📖 API Documentation

### Authentication
All protected routes require JWT token:
```bash
# Login
POST /api/auth/login
{
  "email": "admin@cybertoolkit.com",
  "password": "admin123"
}

# Get token in response, use in Authorization header
Authorization: Bearer <token>
```

### Key Endpoints
- `GET /api/network/status` - Network monitoring status
- `GET /api/network/analytics` - Network analytics data
- `GET /api/network/alerts` - Security alerts
- `POST /api/malware/scan` - Scan files for malware
- `POST /api/email/analyze` - Analyze email files
- `POST /api/recovery/recover` - Recover files

Full API documentation available at: `/api-docs`

## 🧪 Testing

### Run Tests
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Manual Testing
1. **File Analysis**: Upload test files and verify metadata extraction
2. **Network Monitoring**: Start monitoring and check real-time updates
3. **Malware Detection**: Upload EICAR test file for detection
4. **Email Analysis**: Test with sample .eml files

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Rate Limiting**: Prevent API abuse
- **CORS Protection**: Cross-origin request security
- **Input Validation**: Joi validation for all inputs
- **Helmet.js**: Security headers
- **File Upload Security**: Multer with type restrictions
- **SQL Injection Protection**: Parameterized queries

## 🐛 Troubleshooting

### Common Issues

#### Server Won't Start
```bash
# Check if port is in use
netstat -ano | findstr :5000

# Kill process on Windows
taskkill /PID <PID> /F
```

#### Database Connection Failed
```bash
# Check PostgreSQL is running
pg_isready

# Check database exists
psql -l

# Reset database
dropdb cybertoolkit && createdb cybertoolkit
```

#### Frontend Build Errors
```bash
# Clear cache
rm -rf node_modules package-lock.json
npm install

# Check TypeScript errors
npx tsc --noEmit
```

#### Login Issues
1. Check if backend is running
2. Verify CORS settings
3. Check JWT secret in .env
4. Clear browser localStorage

### Performance Optimization
- Enable Redis caching for better performance
- Use CDN for static assets in production
- Implement database indexing
- Monitor memory usage with PM2

## 📊 Monitoring & Logging

### Application Logs
```bash
# View logs
tail -f logs/app.log

# Error logs only
tail -f logs/error.log
```

### Health Check
```bash
# API health check
curl http://localhost:5000/api/health

# Database health check
curl http://localhost:5000/api/health/db
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

### Development Guidelines
- Follow TypeScript best practices
- Write meaningful commit messages
- Add tests for new features
- Update documentation

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Creator**: Mohd Maaz
- **Email**: maaz7084@gmail.com
- **GitHub**: [@Maaz708](https://github.com/Maaz708)
- **Issues**: [Report on GitHub](https://github.com/Maaz708/cybertoolkit/issues)

## 🗺️ Roadmap

### Upcoming Features
- [ ] Cloud provider integrations (AWS, Azure, GCP)
- [ ] Advanced malware analysis with YARA rules
- [ ] Machine learning for anomaly detection
- [ ] Mobile app version
- [ ] Multi-tenant support
- [ ] Advanced reporting dashboard

### Version History
- **v1.0.0** - Initial release with core forensics features
- **v1.1.0** - Added real-time monitoring and WebSocket support
- **v1.2.0** - Enhanced security and deployment automation

---

**Last updated**: December 2024  
**Built with ❤️ by Mohd Maaz**
