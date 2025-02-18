import express, { Request, Response } from 'express';
import fileUpload from 'express-fileupload';
import path from 'path';
import { FileRecoveryService } from '../services/fileRecovery';

const router = express.Router();
const recoveryService = new FileRecoveryService();

// Configure fileUpload
router.use(fileUpload({
    createParentPath: true,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB max file size
    },
    abortOnLimit: true,
    useTempFiles: true,
    tempFileDir: path.join(__dirname, '../tmp')
}));

// Recovery endpoint
router.post('/recover', async (req: Request, res: Response) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).json({
                status: 'error',
                message: 'No file uploaded'
            });
        }

        const uploadedFile = req.files.file;

        if (Array.isArray(uploadedFile)) {
            throw new Error('Multiple files not supported');
        }

        console.log('Processing file:', uploadedFile.name);

        const result = await recoveryService.recoverFile(
            uploadedFile.data,
            uploadedFile.name
        );

        res.json({
            status: 'success',
            data: result
        });

    } catch (error) {
        console.error('Recovery error:', error);
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

// Download endpoint
router.get('/download/:filename', (req, res) => {
    try {
        const filePath = path.join(__dirname, '../storage/recovered', req.params.filename);
        res.download(filePath);
    } catch (error) {
        res.status(404).json({
            status: 'error',
            message: 'File not found'
        });
    }
});

export default router; 