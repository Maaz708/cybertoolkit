const express = require('express');
const router = express.Router();
const AWS = require('aws-sdk');
const Azure = require('@azure/storage-blob');
const { GoogleCloud } = require('@google-cloud/storage');
const fs = require('fs');
const path = require('path');

class CloudForensics {
    constructor() {
        this.azureClient = null;
        this.googleCloudStorage = null;
        this.awsS3 = null;
        this.cloudEnabled = false;
    }

    async initializeProviders() {
        if (!this.cloudEnabled) {
            console.log('Cloud storage features are disabled. System will work without cloud functionality.');
            return;
        }

        try {
            const azureConnectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
            if (azureConnectionString) {
                this.azureClient = BlobServiceClient.fromConnectionString(azureConnectionString);
                console.log('Azure Storage initialized successfully');
            }

            if (process.env.GOOGLE_CLOUD_PROJECT) {
                const { Storage } = require('@google-cloud/storage');
                this.googleCloudStorage = new Storage();
                console.log('Google Cloud Storage initialized successfully');
            }
        } catch (error) {
            console.log('Cloud provider initialization skipped - will run without cloud features');
        }
    }

    async analyzeCloudStorage(provider, details) {
        if (!this.cloudEnabled) {
            return {
                status: 'skipped',
                message: 'Cloud storage analysis is not enabled'
            };
        }

        const analysis = {
            id: Date.now().toString(),
            timestamp: new Date(),
            provider,
            summary: {},
            objects: [],
            access_logs: [],
            security_config: {},
            vulnerabilities: []
        };

        try {
            switch (provider) {
                case 'aws':
                    await this.analyzeAWS(analysis, details);
                    break;
                case 'azure':
                    await this.analyzeAzure(analysis, details);
                    break;
                case 'gcloud':
                    await this.analyzeGoogleCloud(analysis, details);
                    break;
                default:
                    throw new Error('Unsupported cloud provider');
            }

            this.analyses.set(analysis.id, analysis);
            return analysis;
        } catch (error) {
            console.error(`Cloud analysis error (${provider}):`, error);
            throw error;
        }
    }

    async analyzeAWS(analysis, credentials) {
        const s3 = new AWS.S3(credentials);

        // List buckets
        const buckets = await s3.listBuckets().promise();
        analysis.summary.buckets = buckets.Buckets.length;

        // Analyze each bucket
        for (const bucket of buckets.Buckets) {
            const bucketAnalysis = {
                name: bucket.Name,
                created: bucket.CreationDate,
                objects: [],
                permissions: {},
                logging: {},
                encryption: {}
            };

            // Get bucket policy
            try {
                const policy = await s3.getBucketPolicy({ Bucket: bucket.Name }).promise();
                bucketAnalysis.permissions.policy = JSON.parse(policy.Policy);
            } catch (error) {
                bucketAnalysis.permissions.policy = null;
            }

            // Get bucket encryption
            try {
                const encryption = await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
                bucketAnalysis.encryption = encryption.ServerSideEncryptionConfiguration;
            } catch (error) {
                bucketAnalysis.encryption = null;
            }

            // List objects
            const objects = await s3.listObjectsV2({ Bucket: bucket.Name }).promise();
            bucketAnalysis.objects = objects.Contents.map(obj => ({
                key: obj.Key,
                size: obj.Size,
                modified: obj.LastModified,
                owner: obj.Owner
            }));

            analysis.objects.push(bucketAnalysis);
        }

        // Get CloudTrail logs
        const cloudTrail = new AWS.CloudTrail(credentials);
        const trails = await cloudTrail.describeTrails().promise();
        analysis.access_logs = trails.trailList;

        // Security assessment
        analysis.vulnerabilities = this.assessAWSSecurityConfig(analysis);
    }

    async analyzeAzure(analysis, credentials) {
        // Implement Azure storage analysis
    }

    async analyzeGoogleCloud(analysis, credentials) {
        // Implement Google Cloud storage analysis
    }

    assessAWSSecurityConfig(analysis) {
        const vulnerabilities = [];

        // Check public access
        analysis.objects.forEach(bucket => {
            if (this.isPubliclyAccessible(bucket.permissions.policy)) {
                vulnerabilities.push({
                    severity: 'HIGH',
                    type: 'PUBLIC_ACCESS',
                    resource: bucket.name,
                    description: 'Bucket is publicly accessible'
                });
            }
        });

        // Check encryption
        analysis.objects.forEach(bucket => {
            if (!bucket.encryption) {
                vulnerabilities.push({
                    severity: 'MEDIUM',
                    type: 'NO_ENCRYPTION',
                    resource: bucket.name,
                    description: 'Bucket is not encrypted'
                });
            }
        });

        return vulnerabilities;
    }

    isPubliclyAccessible(policy) {
        if (!policy) return false;
        // Implement policy analysis logic
        return false;
    }

    getAnalysis(id) {
        return this.analyses.get(id);
    }

    getStatistics() {
        return {
            total_analyses: this.analyses.size,
            by_provider: {
                aws: this.countAnalysesByProvider('aws'),
                azure: this.countAnalysesByProvider('azure'),
                gcloud: this.countAnalysesByProvider('gcloud')
            },
            recent_analyses: Array.from(this.analyses.values()).slice(-10)
        };
    }

    countAnalysesByProvider(provider) {
        return Array.from(this.analyses.values()).filter(a => a.provider === provider).length;
    }

    enableCloud() {
        this.cloudEnabled = true;
        return this.initializeProviders();
    }
}

const cloudForensics = new CloudForensics();

// Routes
router.post('/analyze-cloud', async (req, res) => {
    try {
        if (!cloudForensics.cloudEnabled) {
            return res.json({
                status: 'info',
                message: 'Cloud analysis is not enabled in this instance'
            });
        }
        const { provider, credentials } = req.body;
        if (!provider || !credentials) {
            return res.status(400).json({ error: 'Provider and credentials required' });
        }

        const results = await cloudForensics.analyzeCloudStorage(provider, credentials);
        res.json(results);
    } catch (error) {
        console.error('Cloud forensics error:', error);
        res.status(500).json({ error: 'Cloud forensics analysis failed' });
    }
});

router.get('/analysis/:id', (req, res) => {
    try {
        const analysis = cloudForensics.getAnalysis(req.params.id);
        if (!analysis) {
            return res.status(404).json({ error: 'Analysis not found' });
        }
        res.json(analysis);
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve analysis' });
    }
});

router.get('/statistics', (req, res) => {
    try {
        const stats = cloudForensics.getStatistics();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get statistics' });
    }
});

module.exports = router;
module.exports = router; 