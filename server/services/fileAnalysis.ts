import { FileStorageManager } from '../utils/fileStorage';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

const stat = promisify(fs.stat);

export class FileAnalysisService {
    private storageManager: FileStorageManager;

    constructor() {
        this.storageManager = new FileStorageManager();
    }

    async analyzeFile(file: Buffer, filename: string) {
        try {
            // Store the original file
            const storedPath = await this.storageManager.storeFile(file, filename);

            // Generate and store hashes
            const hashes = await this.storageManager.generateHashes(storedPath);

            // Generate and store timeline
            const stats = await stat(storedPath);
            const timeline = {
                filename,
                created: stats.birthtime,
                modified: stats.mtime,
                accessed: stats.atime,
                analyzed: new Date(),
                path: storedPath
            };
            const timelinePath = await this.storageManager.storeTimeline(
                storedPath,
                timeline
            );

            // Attempt file recovery
            const recovery = await this.storageManager.attemptRecovery(storedPath);

            // Generate and store analysis report
            const analysis = {
                filename,
                timestamp: new Date(),
                fileSize: file.length,
                hashes,
                timeline,
                recovery: {
                    attempted: true,
                    success: recovery.success,
                    recoveredPath: recovery.recoveredPath
                }
            };

            const analysisPath = await this.storageManager.storeAnalysisReport(
                storedPath,
                analysis
            );

            return {
                status: 'success',
                data: {
                    originalFile: storedPath,
                    hashes,
                    timeline,
                    recovery,
                    analysis: analysisPath
                }
            };
        } catch (error) {
            return {
                status: 'error',
                error: error.message
            };
        }
    }
} 