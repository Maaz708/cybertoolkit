const express = require('express');
const cors = require('cors');
const fileUpload = require('express-fileupload');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const emailForensics = require('./modules/emailForensics');
const malwareDetection = require('./modules/malwareDetection');
const multer = require('multer');

const app = express();

// CORS configuration
app.use(cors({
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  methods: ['GET', 'POST'],
  credentials: true
}));

// File upload middleware
app.use(fileUpload({
  createParentPath: true,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB
  },
  useTempFiles: true,
  tempFileDir: path.join(__dirname, 'tmp'),
  parseNested: true,
  debug: true
}));

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create required directories
const dirs = ['uploads', 'uploads/malware_scans', 'tmp', 'storage/recovered'];
dirs.forEach(dir => {
  const dirPath = path.join(__dirname, dir);
  if (!fsSync.existsSync(dirPath)) {
    fsSync.mkdirSync(dirPath, { recursive: true });
  }
});

// Create tmp directory if it doesn't exist
const tmpDir = path.join(__dirname, 'tmp');
if (!fsSync.existsSync(tmpDir)) {
  fsSync.mkdirSync(tmpDir);
}

// Routes
app.use('/api/network', require('./modules/networkMonitor'));
app.use('/api/malware', require('./modules/malwareDetection'));
app.use('/api/files', require('./modules/fileAnalysis'));
app.use('/api/email', emailForensics);
app.use('/api/malware-detection', malwareDetection);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname)
  }
});

const upload = multer({ storage: storage });

// File Recovery Route
app.post('/api/recovery/recover', async (req, res) => {
  try {
    console.log('Recovery request received');

    // Check if file exists in the request
    if (!req.files || !req.files.file) {
      console.log('No file in request');
      return res.status(400).json({
        status: 'error',
        message: 'No file uploaded'
      });
    }

    const uploadedFile = req.files.file;
    console.log('Processing file:', uploadedFile.name);

    // Create uploads directory if it doesn't exist
    const uploadsDir = path.join(__dirname, 'uploads');
    if (!fsSync.existsSync(uploadsDir)) {
      fsSync.mkdirSync(uploadsDir, { recursive: true });
    }

    // Save the uploaded file
    const uploadPath = path.join(uploadsDir, uploadedFile.name);
    await uploadedFile.mv(uploadPath);

    // Process the file (add your recovery logic here)
    const fileContent = await fs.readFile(uploadPath, 'utf8');

    // Save recovered file
    const recoveredDir = path.join(__dirname, 'storage', 'recovered');
    if (!fsSync.existsSync(recoveredDir)) {
      fsSync.mkdirSync(recoveredDir, { recursive: true });
    }

    const recoveredPath = path.join(recoveredDir, uploadedFile.name);
    await fs.writeFile(recoveredPath, fileContent);

    console.log('File recovered successfully to:', recoveredPath);

    // Return response in the format expected by frontend
    res.json({
      status: 'success',
      data: {
        recoveredPath: `/storage/recovered/${uploadedFile.name}`,
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
      message: 'Error recovering file',
      error: error.message
    });
  }
});

// Download recovered file route
app.get('/api/recovery/download/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'storage', 'recovered', filename);

    console.log('Download requested for:', filename);
    console.log('Looking for file at:', filePath);

    if (!fsSync.existsSync(filePath)) {
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

// Error handling
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    status: 'error',
    message: err.message || 'Internal server error'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

