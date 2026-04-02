const { Storage } = require('@google-cloud/storage');

class GCPService {
    constructor() {
        this.storage = new Storage();
        this.projectId = process.env.GCP_PROJECT_ID || '';
    }

    async authenticate(credentials) {
        try {
            // Authenticate with service account key file or ADC
            if (credentials.keyFile) {
                this.storage = new Storage({
                    projectId: credentials.projectId || this.projectId,
                    keyFilename: credentials.keyFile
                });
            } else if (credentials.keyJson) {
                this.storage = new Storage({
                    projectId: credentials.projectId || this.projectId,
                    credentials: credentials.keyJson
                });
            } else {
                // Use Application Default Credentials
                this.storage = new Storage({
                    projectId: credentials.projectId || this.projectId
                });
            }

            // Test authentication by listing buckets
            await this.storage.getBuckets();
            return { authenticated: true, provider: 'gcp' };
        } catch (error) {
            throw new Error(`GCP authentication failed: ${error.message}`);
        }
    }

    async analyzeStorage(credentials, userId) {
        try {
            await this.authenticate(credentials);
            
            const buckets = await this.listBuckets();
            const analysis = {
                provider: 'gcp',
                resources: [],
                vulnerabilities: [],
                summary: {
                    totalBuckets: buckets.length,
                    publicBuckets: 0,
                    unencryptedBuckets: 0,
                    bucketsWithLogging: 0
                }
            };

            for (const bucket of buckets) {
                const bucketAnalysis = await this.analyzeBucket(bucket.name, userId);
                analysis.resources.push(bucketAnalysis);
                
                // Update summary
                if (bucketAnalysis.publicAccess) analysis.summary.publicBuckets++;
                if (!bucketAnalysis.encrypted) analysis.summary.unencryptedBuckets++;
                if (bucketAnalysis.loggingEnabled) analysis.summary.bucketsWithLogging++;
                
                // Add vulnerabilities
                analysis.vulnerabilities.push(...bucketAnalysis.vulnerabilities);
            }

            return analysis;
        } catch (error) {
            throw new Error(`GCP storage analysis failed: ${error.message}`);
        }
    }

    async listBuckets() {
        try {
            const [buckets] = await this.storage.getBuckets();
            return buckets;
        } catch (error) {
            throw new Error(`Failed to list buckets: ${error.message}`);
        }
    }

    async analyzeBucket(bucketName, userId) {
        const analysis = {
            name: bucketName,
            provider: 'gcp',
            type: 'gcs-bucket',
            project: this.projectId,
            publicAccess: false,
            encrypted: false,
            loggingEnabled: false,
            iamPermissions: [],
            objects: [],
            vulnerabilities: [],
            riskScore: 100
        };

        try {
            // Get bucket metadata
            const bucket = this.storage.bucket(bucketName);
            const [metadata] = await bucket.getMetadata();
            
            // Check public access
            analysis.publicAccess = await this.checkPublicAccess(bucketName);
            
            // Check encryption
            analysis.encrypted = await this.checkEncryption(bucketName);
            
            // Check logging
            analysis.loggingEnabled = await this.checkLogging(bucketName);
            
            // Check IAM permissions
            analysis.iamPermissions = await this.getIAMPermissions(bucketName);
            
            // List objects (limited)
            analysis.objects = await this.listObjects(bucketName, 50);
            
            // Detect data exposure
            const dataExposure = this.detectDataExposure(analysis.objects);
            if (dataExposure.length > 0) {
                analysis.vulnerabilities.push(...dataExposure);
            }
            
            // Calculate vulnerabilities
            if (analysis.publicAccess) {
                analysis.vulnerabilities.push({
                    severity: 'critical',
                    type: 'public_access',
                    resource: `gs://${bucketName}`,
                    description: 'Bucket is publicly accessible',
                    recommendation: 'Restrict bucket access to specific service accounts or IAM roles'
                });
                analysis.riskScore -= 30;
            }
            
            if (!analysis.encrypted) {
                analysis.vulnerabilities.push({
                    severity: 'high',
                    type: 'no_encryption',
                    resource: `gs://${bucketName}`,
                    description: 'Bucket does not have encryption enabled',
                    recommendation: 'Enable Google Cloud KMS or Google-managed encryption keys'
                });
                analysis.riskScore -= 20;
            }
            
            if (!analysis.loggingEnabled) {
                analysis.vulnerabilities.push({
                    severity: 'medium',
                    type: 'no_logging',
                    resource: `gs://${bucketName}`,
                    description: 'Bucket access logging is not enabled',
                    recommendation: 'Enable Cloud Audit Logging and Cloud Storage logs'
                });
                analysis.riskScore -= 10;
            }
            
            // Check for weak IAM permissions
            const weakIAM = this.checkWeakIAMPermissions(analysis.iamPermissions);
            if (weakIAM.length > 0) {
                analysis.vulnerabilities.push(...weakIAM);
                analysis.riskScore -= 15;
            }
            
        } catch (error) {
            analysis.vulnerabilities.push({
                severity: 'medium',
                type: 'analysis_error',
                resource: `gs://${bucketName}`,
                description: `Failed to analyze bucket: ${error.message}`,
                recommendation: 'Check IAM permissions and bucket policies'
            });
        }

        return analysis;
    }

    async checkPublicAccess(bucketName) {
        try {
            const bucket = this.storage.bucket(bucketName);
            const [metadata] = await bucket.getMetadata();
            
            // Check if bucket has uniform bucket-level access
            const uniformBucketLevelAccess = metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled;
            
            // Check for public IAM policies
            const [policy] = await bucket.iam.getPolicy();
            const publicBindings = policy.bindings.filter(binding =>
                binding.members.some(member => 
                    member === 'allUsers' || 
                    member === 'allAuthenticatedUsers'
                )
            );
            
            return publicBindings.length > 0;
        } catch (error) {
            // Assume public if we can't check
            return true;
        }
    }

    async checkEncryption(bucketName) {
        try {
            const bucket = this.storage.bucket(bucketName);
            const [metadata] = await bucket.getMetadata();
            
            // Check if encryption is configured
            const encryption = metadata.encryption;
            return encryption && (encryption.defaultKmsKeyName || encryption.defaultEncryptionAlgorithm);
        } catch (error) {
            return false;
        }
    }

    async checkLogging(bucketName) {
        try {
            // Check if Cloud Audit Logging is enabled for the bucket
            // This is a simplified check - in production you'd use Cloud Logging APIs
            const bucket = this.storage.bucket(bucketName);
            const [metadata] = await bucket.getMetadata();
            
            // Placeholder for logging check
            return false;
        } catch (error) {
            return false;
        }
    }

    async getIAMPermissions(bucketName) {
        try {
            const bucket = this.storage.bucket(bucketName);
            const [policy] = await bucket.iam.getPolicy();
            
            const permissions = [];
            policy.bindings.forEach(binding => {
                binding.members.forEach(member => {
                    permissions.push({
                        role: binding.role,
                        member: member,
                        type: this.getMemberType(member)
                    });
                });
            });
            
            return permissions;
        } catch (error) {
            return [];
        }
    }

    getMemberType(member) {
        if (member === 'allUsers' || member === 'allAuthenticatedUsers') {
            return 'public';
        } else if (member.startsWith('serviceAccount:')) {
            return 'serviceAccount';
        } else if (member.startsWith('user:')) {
            return 'user';
        } else if (member.startsWith('group:')) {
            return 'group';
        } else {
            return 'unknown';
        }
    }

    checkWeakIAMPermissions(permissions) {
        const vulnerabilities = [];
        const weakRoles = ['roles/storage.objectViewer', 'roles/storage.objectViewer'];
        
        permissions.forEach(permission => {
            if (permission.type === 'public' && weakRoles.includes(permission.role)) {
                vulnerabilities.push({
                    severity: 'high',
                    type: 'weak_iam',
                    resource: permission.member,
                    description: `Public access with role: ${permission.role}`,
                    recommendation: 'Remove public access or restrict to specific service accounts'
                });
            }
            
            if (permission.type === 'public' && permission.role === 'roles/storage.admin') {
                vulnerabilities.push({
                    severity: 'critical',
                    type: 'weak_iam',
                    resource: permission.member,
                    description: `Public admin access: ${permission.role}`,
                    recommendation: 'Immediately revoke public admin access'
                });
            }
        });
        
        return vulnerabilities;
    }

    async listObjects(bucketName, maxResults = 100) {
        try {
            const bucket = this.storage.bucket(bucketName);
            const [files] = await bucket.getFiles({
                maxResults: maxResults
            });
            
            return files.map(file => ({
                name: file.name,
                size: file.metadata.size,
                timeCreated: file.metadata.timeCreated,
                updated: file.metadata.updated,
                contentType: file.metadata.contentType,
                suspicious: this.isSuspiciousObject(file.name, file.metadata.size)
            }));
        } catch (error) {
            return [];
        }
    }

    isSuspiciousObject(name, size) {
        const suspiciousPatterns = [
            /password/i,
            /backup/i,
            /database/i,
            /secret/i,
            /private/i,
            /key/i,
            /credential/i,
            /config/i,
            /.env$/i,
            /.pem$/i,
            /.key$/i,
            /.p12$/i,
            /.pfx$/i
        ];

        const suspiciousName = suspiciousPatterns.some(pattern => pattern.test(name));
        const suspiciousSize = size > 100 * 1024 * 1024; // > 100MB
        
        return suspiciousName || suspiciousSize;
    }

    detectDataExposure(objects) {
        const vulnerabilities = [];
        
        objects.forEach(obj => {
            if (obj.suspicious) {
                vulnerabilities.push({
                    severity: 'high',
                    type: 'data_exposure',
                    resource: obj.name,
                    description: `Suspicious object detected: ${obj.name} (${this.formatBytes(obj.size)})`,
                    recommendation: 'Review object contents and restrict access if sensitive'
                });
            }
        });
        
        return vulnerabilities;
    }

    async analyzeAuditLogs(credentials, userId, timeRange = 24) {
        try {
            await this.authenticate(credentials);
            
            const logs = {
                provider: 'gcp',
                service: 'cloud-logging',
                timeRange: timeRange,
                events: [],
                summary: {
                    totalEvents: 0,
                    unusualAccess: 0,
                    failedAttempts: 0,
                    unknownRegions: 0
                },
                anomalies: []
            };

            // Get Cloud Logging events (simplified)
            try {
                const endTime = new Date();
                const startTime = new Date(endTime.getTime() - timeRange * 60 * 60 * 1000);

                const events = await this.getCloudLoggingEvents(startTime, endTime);
                logs.events = events;
                logs.summary.totalEvents = events.length;

                // Analyze for anomalies
                events.forEach(event => {
                    if (this.isUnusualAccess(event)) {
                        logs.summary.unusualAccess++;
                        logs.anomalies.push({
                            severity: 'medium',
                            type: 'unusual_access',
                            resource: event.resource,
                            description: `Unusual access from ${event.ipAddress}`,
                            timestamp: event.timestamp,
                            recommendation: 'Investigate source IP and access pattern'
                        });
                    }

                    if (this.isFailedAttempt(event)) {
                        logs.summary.failedAttempts++;
                        logs.anomalies.push({
                            severity: 'low',
                            type: 'failed_attempt',
                            resource: event.methodName,
                            description: `Failed ${event.methodName} attempt`,
                            timestamp: event.timestamp,
                            recommendation: 'Monitor for potential brute force attempts'
                        });
                    }

                    if (this.isUnknownRegion(event)) {
                        logs.summary.unknownRegions++;
                        logs.anomalies.push({
                            severity: 'medium',
                            type: 'unknown_region',
                            resource: event.location,
                            description: `Access from unfamiliar region: ${event.location}`,
                            timestamp: event.timestamp,
                            recommendation: 'Verify if access from this region is expected'
                        });
                    }
                });

            } catch (error) {
                logs.anomalies.push({
                    severity: 'medium',
                    type: 'log_analysis_error',
                    resource: 'cloud-logging',
                    description: `Failed to analyze logs: ${error.message}`,
                    recommendation: 'Check Cloud Logging configuration and permissions'
                });
            }

            return logs;
        } catch (error) {
            throw new Error(`GCP audit log analysis failed: ${error.message}`);
        }
    }

    async getCloudLoggingEvents(startTime, endTime) {
        // Simplified Cloud Logging event retrieval
        // In production, you'd use Cloud Logging API
        return [
            {
                timestamp: new Date(),
                methodName: 'storage.objects.get',
                resource: 'gcs-bucket',
                ipAddress: '203.0.113.1',
                location: 'us-central1',
                protocol: 'JSON API'
            }
        ];
    }

    isUnusualAccess(event) {
        // Check for unusual patterns
        const unusualIPs = ['203.0.113.1', '198.51.100.1'];
        return unusualIPs.includes(event.ipAddress);
    }

    isFailedAttempt(event) {
        return event.methodName && event.methodName.includes('Failed');
    }

    isUnknownRegion(event) {
        const knownRegions = ['us-central1', 'us-east1', 'us-west1', 'europe-west1'];
        return event.location && !knownRegions.includes(event.location);
    }

    async getThreatIntelligence(credentials) {
        try {
            await this.authenticate(credentials);
            
            return {
                provider: 'gcp',
                services: {
                    securityCommandCenter: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Google Cloud Security Command Center'
                    },
                    threatDetection: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Cloud Threat Detection'
                    },
                    webSecurityScanner: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Web Security Scanner'
                    }
                },
                recommendations: [
                    'Enable Security Command Center for comprehensive security monitoring',
                    'Configure Cloud Threat Detection for real-time protection',
                    'Use Web Security Scanner for web application security'
                ]
            };
        } catch (error) {
            throw new Error(`GCP threat intelligence failed: ${error.message}`);
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

module.exports = GCPService;
