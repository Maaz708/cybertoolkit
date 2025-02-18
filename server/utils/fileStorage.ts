import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { promisify } from 'util';

const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const mkdir = promisify(fs.mkdir);

export class FileStorageManager {
    private baseDir: string;
    private hashesDir: string;
    private timelineDir: string;
    private recoveredDir: string;
    private analysisDir: string;

    constructor() {
        this.baseDir = path.join(__dirname, '../storage/files');
        this.hashesDir = path.join(__dirname, '../storage/hashes');
        this.timelineDir = path.join(__dirname, '../storage/timeline');
        this.recoveredDir = path.join(__dirname, '../storage/recovered');
        this.analysisDir = path.join(__dirname, '../storage/analysis');

        // Ensure directories exist
        this.initializeDirectories();
    }

    private async initializeDirectories() {
        const dirs = [
            this.baseDir,
            this.hashesDir,
            this.timelineDir,
            this.recoveredDir,
            this.analysisDir
        ];

        for (const dir of dirs) {
            await mkdir(dir, { recursive: true });
        }
    }

    async storeFile(file: Buffer, filename: string): Promise<string> {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const safeFilename = filename.replace(/[^a-zA-Z0-9.-]/g, '_');
        const storedPath = path.join(this.baseDir, `${timestamp}_${safeFilename}`);

        await writeFile(storedPath, file);
        return storedPath;
    }

    async generateHashes(filePath: string): Promise<{
        md5: string;
        sha1: string;
        sha256: string;
        filePath: string;
    }> {
        const fileBuffer = await readFile(filePath);
        const hashes = {
            md5: crypto.createHash('md5').update(fileBuffer).digest('hex'),
            sha1: crypto.createHash('sha1').update(fileBuffer).digest('hex'),
            sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex'),
            filePath
        };

        // Store hash information
        const hashPath = path.join(
            this.hashesDir,
            `${path.basename(filePath)}.hash.json`
        );
        await writeFile(hashPath, JSON.stringify(hashes, null, 2));

        return hashes;
    }

    async storeTimeline(filePath: string, timeline: any): Promise<string> {
        const timelinePath = path.join(
            this.timelineDir,
            `${path.basename(filePath)}.timeline.json`
        );

        await writeFile(timelinePath, JSON.stringify(timeline, null, 2));
        return timelinePath;
    }

    async attemptRecovery(filePath: string): Promise<{
        success: boolean;
        recoveredPath?: string;
        error?: string;
    }> {
        try {
            const fileBuffer = await readFile(filePath);
            const recoveredPath = path.join(
                this.recoveredDir,
                `recovered_${path.basename(filePath)}`
            );

            // Implement your file recovery logic here
            // This is a basic example that copies the file
            await writeFile(recoveredPath, fileBuffer);

            return {
                success: true,
                recoveredPath
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async storeAnalysisReport(filePath: string, analysis: any): Promise<string> {
        const analysisPath = path.join(
            this.analysisDir,
            `${path.basename(filePath)}.analysis.json`
        );

        await writeFile(analysisPath, JSON.stringify(analysis, null, 2));
        return analysisPath;
    }
}