# 🚀 CyberToolkit Production Deployment Guide

## 📋 Prerequisites

- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+
- Node.js 18+
- SSL Certificate (for production)

## 🐳 Quick Start with Docker Compose

### 1. Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Edit production values
nano .env
```

### 2. Deploy
```bash
# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f backend
```

### 3. Initialize Database
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U postgres -d cybertoolkit

# Run schema
docker-compose exec backend psql -U postgres -d cybertoolkit -f /app/server/database/schema.sql
```

## 🏗️ Architecture Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Frontend │    │   Nginx    │    │   Backend   │
│  (Vercel)   │────│   (LB)      │────│  (Docker)   │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    │                     │                     │
            ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
            │ PostgreSQL  │    │    Redis    │    │  WebSocket  │
            │ (Database)  │    │   (Cache)   │    │ (Real-time)  │
            └─────────────┘    └─────────────┘    └─────────────┘
```

## 🔧 Configuration

### Environment Variables
```bash
# Server
NODE_ENV=production
PORT=5000

# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=cybertoolkit
DB_USER=postgres
DB_PASSWORD=your_secure_password

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# Security
JWT_SECRET=your_super_secure_jwt_secret_here
BCRYPT_ROUNDS=12

# Frontend
FRONTEND_URL=https://your-domain.com
```

## 🛡️ Security Checklist

- [ ] Change all default passwords
- [ ] Set strong JWT secret
- [ ] Enable SSL/TLS
- [ ] Configure firewall rules
- [ ] Set up monitoring
- [ ] Backup strategy
- [ ] Rate limiting configured
- [ ] Input validation enabled

## 📊 Monitoring & Logging

### Application Logs
```bash
# View real-time logs
docker-compose logs -f backend

# View error logs
docker-compose exec backend tail -f logs/error.log
```

### Health Checks
```bash
# Backend health
curl http://localhost:5000/api/network/status

# Database health
docker-compose exec postgres pg_isready -U postgres

# Redis health
docker-compose exec redis redis-cli ping
```

## 🔄 CI/CD Pipeline

### GitHub Actions Example
```yaml
name: Deploy to Production
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to server
        run: |
          docker-compose down
          docker-compose pull
          docker-compose up -d
```

## 📈 Scaling Strategy

### Horizontal Scaling
```yaml
# docker-compose.yml (scaled version)
services:
  backend:
    deploy:
      replicas: 3
    environment:
      - NODE_ENV=production
  
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
```

### Database Scaling
- Read replicas for read-heavy operations
- Connection pooling (PgBouncer)
- Partitioning for large tables

## 🔄 Backup & Recovery

### Database Backups
```bash
# Daily backup
docker-compose exec postgres pg_dump -U postgres cybertoolkit > backup_$(date +%Y%m%d).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec postgres pg_dump -U postgres cybertoolkit > $BACKUP_DIR/backup_$DATE.sql
```

### File Backups
```bash
# Backup user uploads
tar -czf uploads_backup_$(date +%Y%m%d).tar.gz uploads/
```

## 🚨 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check if PostgreSQL is running
   docker-compose ps postgres
   
   # Check logs
   docker-compose logs postgres
   ```

2. **High Memory Usage**
   ```bash
   # Monitor resource usage
   docker stats
   
   # Adjust memory limits
   docker-compose up -d --scale backend=2
   ```

3. **WebSocket Connection Issues**
   ```bash
   # Check WebSocket port
   netstat -tulpn | grep 8080
   
   # Verify firewall rules
   ufw status
   ```

## 📞 Support

### Monitoring Tools
- Prometheus + Grafana for metrics
- ELK Stack for logging
- Sentry for error tracking

### Performance Optimization
- Redis caching for frequent queries
- Database query optimization
- CDN for static assets
- Gzip compression

## 🔐 Security Best Practices

1. **Regular Updates**
   ```bash
   # Update dependencies
   npm audit fix
   docker-compose pull
   ```

2. **Access Control**
   - Principle of least privilege
   - Regular security audits
   - Penetration testing

3. **Data Protection**
   - Encryption at rest
   - Encryption in transit
   - GDPR compliance

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [PostgreSQL Performance](https://wiki.postgresql.org/wiki/Tuning_Your_PostgreSQL_Server)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)
- [OWASP Security Guidelines](https://owasp.org/)
