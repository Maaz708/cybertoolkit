require('dotenv').config();
console.log('🔧 Environment variables loaded:', Object.keys(process.env).filter(key => key.includes('PORT') || key.includes('JWT') || key.includes('DB')).length);

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Test required dependencies
try {
  require('pg');
  console.log('✅ PostgreSQL client found');
} catch (e) {
  console.error('❌ PostgreSQL client missing:', e.message);
  process.exit(1);
}

try {
  require('bcryptjs');
  console.log('✅ bcryptjs found');
} catch (e) {
  console.error('❌ bcryptjs missing:', e.message);
  process.exit(1);
}

try {
  require('jsonwebtoken');
  console.log('✅ jsonwebtoken found');
} catch (e) {
  console.error('❌ jsonwebtoken missing:', e.message);
  process.exit(1);
}

// Import configuration and utilities
const config = require('./config');
const logger = require('./utils/logger');
const { validate, validateFile } = require('./utils/validation');

// Import routes
const authRoutes = require('./routes/auth');
const networkRoutes = require('./routes/network');
const malwareDetection = require('./routes/malwareDetection');
const fileAnalysis = require('./routes/fileAnalysis');
const emailForensics = require('./routes/email');
const dashboardRoutes = require('./routes/dashboard');
const { authenticateToken, setUserContext } = require('./middleware/auth');
const multer = require('multer');
const WebSocket = require('ws');
const http = require('http');
const { Pool } = require('pg');

// NEW: Import enhanced services and Socket.io
const RealtimeService = require('./services/realtimeService');
const networkEnhancedRoutes = require('./routes/networkEnhanced');

// NEW: Swagger/OpenAPI setup
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();
const server = http.createServer(app);

// Trust proxy for rate limiting (fixes X-Forwarded-For header error)
app.set('trust proxy', 1);

// Global monitoring state
let monitoringInterval = null;
let isMonitoring = false;

// 🛡️ Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// 🚦 Rate Limiting
const limiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  message: {
    success: false,
    error: 'Too many requests, please try again later.',
    retryAfter: Math.round(config.rateLimit.windowMs / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// 📝 Request Logging
app.use(logger.requestLogger);

// 🌐 CORS Configuration
const corsOrigins = config.frontend.allowedOrigins || [
  config.frontend.url, 
  config.frontend.prodUrl,
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc)
    if (!origin) return callback(null, true);
    
    if (corsOrigins.includes(origin) || origin.includes('netlify.app') || origin.includes('vercel.app')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200
}));

// Body Parser Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 📁 File Upload Middleware
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({ storage: storage });

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/network', networkRoutes);

// NEW: Enhanced network routes with real-time, caching, analytics
app.use('/api/network', networkEnhancedRoutes);

app.use('/api/malware', malwareDetection);
app.use('/api/files', upload.single('file'), fileAnalysis);
app.use('/api/email', emailForensics);
app.use('/api/dashboard', dashboardRoutes);

// NEW: Swagger API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Status API (Public - no auth required for basic status)
app.get('/api/network/status', async (req, res) => {
  try {
    const status = {
      isMonitoring,
      timestamp: new Date().toISOString(),
      data: isMonitoring ? null : {
        connections: [],
        bandwidth: { inbound: 0, outbound: 0 },
        protocols: { TCP: 0, UDP: 0, Other: 0 }
      }
    };

    res.json(status);
  } catch (error) {
    logger.error('Failed to get monitoring status', { error: error.message });
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Create required directories
const dirs = ['uploads', 'uploads/malware_scans', 'tmp', 'storage/recovered', 'logs'];
dirs.forEach(dir => {
  const dirPath = path.join(__dirname, dir);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
});

// 🌐 WebSocket server for real-time updates (attached to HTTP server)
const wss = new WebSocket.Server({ server });

// NEW: Socket.io Real-time Service
const realtimeService = new RealtimeService(server, {
  corsOrigin: [config.frontend.url, config.frontend.prodUrl]
});

// Store in app for access in routes
app.set('realtimeService', realtimeService);
app.set('io', realtimeService.getIO());

wss.on('connection', (ws, req) => {
  logger.info('WebSocket client connected', { 
    ip: req.socket.remoteAddress,
    userAgent: req.headers['user-agent']
  });
  
  const heartbeat = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    }
  }, 30000);

  const interval = setInterval(async () => {
    try {
      // Only send updates if monitoring is active
      if (isMonitoring) {
        // TODO: Define monitor or replace with actual implementation
        // const data = await monitor.getNetworkStatus();
        const data = { status: 'active', timestamp: new Date().toISOString() };
        
        ws.send(JSON.stringify({
          type: "NETWORK_UPDATE",
          payload: data,
          timestamp: new Date().toISOString()
        }));
      }
    } catch (err) {
      logger.error('WebSocket update error', { error: err.message });
    }
  }, 3000);

  ws.on('close', () => {
    logger.info('WebSocket client disconnected');
    clearInterval(interval);
    clearInterval(heartbeat);
  });

});

logger.info(`WebSocket server attached to HTTP server`);

// File Recovery Route
app.post('/api/recovery/recover', upload.single('file'), async (req, res) => {
  try {
    console.log('Recovery request received');
    console.log('Request headers:', req.headers);
    console.log('Request body type:', typeof req.body);
    console.log('Request files:', req.files);
    console.log('Request file:', req.file);

    // Check if file exists in the request
    if (!req.file) {
      console.log('No file in request');
      return res.status(400).json({
        status: 'error',
        message: 'No file uploaded'
      });
    }

    const uploadedFile = req.file;
    console.log('Processing file:', uploadedFile.originalname);

    // Create uploads directory if it doesn't exist
    const uploadsDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    // File is already saved by multer to its destination, just use it directly
    const uploadPath = uploadedFile.path;

    // Process the file (add your recovery logic here)
    console.log('Reading file from:', uploadPath);
    const fileContent = await new Promise((resolve, reject) => {
      fs.readFile(uploadPath, 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading file:', err);
          reject(err);
        } else {
          resolve(data);
        }
      });
    });

    // Save recovered file
    const recoveredDir = path.join(__dirname, 'storage', 'recovered');
    if (!fs.existsSync(recoveredDir)) {
      fs.mkdirSync(recoveredDir, { recursive: true });
    }

    const recoveredPath = path.join(recoveredDir, uploadedFile.originalname);
    await new Promise((resolve, reject) => {
      fs.writeFile(recoveredPath, fileContent, (err) => {
        if (err) {
          console.error('Error writing recovered file:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });

    console.log('File recovered successfully to:', recoveredPath);

    // Return response in the format expected by frontend
    res.json({
      status: 'success',
      data: {
        recoveredPath: `/storage/recovered/${uploadedFile.originalname}`,
        log: {
          steps: ['File uploaded', 'File processed', 'Recovery completed']
        },
        success: true
      }
    });

  } catch (error) {
    console.error('Detailed recovery error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error recovering file'
    });
  }
});

// Download recovered file
app.get('/api/recovery/download/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'storage', 'recovered', filename);

    console.log('Download requested for:', filename);
    console.log('Looking for file at:', filePath);

    if (!fs.existsSync(filePath)) {
      console.log('File not found at:', filePath);
      return res.status(404).json({
        status: 'error',
        message: 'File not found'
      });
    }

    console.log('File found, initiating download');
    res.download(filePath);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Error downloading file',
      error: error.message
    });
  }
});

// Global Error Handling
app.use((err, req, res, next) => {
  logger.error('Unhandled server error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  res.status(500).json({
    success: false,
    error: config.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    timestamp: new Date().toISOString()
  });
});

// Server Startup
const PORT = process.env.PORT || 10000;

// Create directories if they don't exist
const requiredDirs = ['uploads', 'server/storage/recovered'];
requiredDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}, starting graceful shutdown`);
  
  // Stop monitoring
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    monitoringInterval = null;
  }
  isMonitoring = false;
  
  // Close WebSocket server
  wss.close(() => {
    logger.info('WebSocket server closed');
  });
  
  // Close HTTP server
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions (TEMP: Don't exit to see actual error)
process.on('uncaughtException', (error) => {
  logger.error('💥 UNCAUGHT EXCEPTION', { error: error.message, stack: error.stack });
  console.error('💥 UNCAUGHT EXCEPTION:', error);
  // process.exit(1); // TEMP: Commented out for debugging
});

// Handle unhandled promise rejections (TEMP: Don't exit to see actual error)
process.on('unhandledRejection', (reason, promise) => {
  logger.error('💥 UNHANDLED REJECTION', { reason, promise });
  console.error('💥 UNHANDLED REJECTION:', reason);
  // process.exit(1); // TEMP: Commented out for debugging
});

console.log('🔥 About to start server on port:', PORT);

server.listen(PORT, '0.0.0.0', () => {
  console.log('✅ SERVER STARTED SUCCESSFULLY');
  logger.info(`🚀 CyberToolkit Server Started Successfully`, {
    port: PORT,
    nodeEnv: config.NODE_ENV,
    websocketPort: 'Attached to HTTP server',
    timestamp: new Date().toISOString()
  });
});

