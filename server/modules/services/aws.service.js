const AWS = require('aws-sdk');

class AWSService {
    constructor() {
        this.s3 = new AWS.S3();
        this.cloudTrail = new AWS.CloudTrail();
        this.iam = new AWS.IAM();
        this.region = process.env.AWS_REGION || 'us-east-1';
    }

    async authenticate(credentials) {
        try {
            AWS.config.update({
                accessKeyId: credentials.accessKeyId,
                secretAccessKey: credentials.secretAccessKey,
                region: credentials.region || this.region,
                ...(credentials.sessionToken && { sessionToken: credentials.sessionToken })
            });

            // Test authentication by listing buckets
            await this.s3.listBuckets().promise();
            return { authenticated: true, provider: 'aws' };
        } catch (error) {
            throw new Error(`AWS authentication failed: ${error.message}`);
        }
    }

    async analyzeStorage(credentials, userId) {
        try {
            await this.authenticate(credentials);
            
            const buckets = await this.listBuckets();
            const analysis = {
                provider: 'aws',
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
            throw new Error(`AWS storage analysis failed: ${error.message}`);
        }
    }

    async listBuckets() {
        try {
            const response = await this.s3.listBuckets().promise();
            return response.Buckets || [];
        } catch (error) {
            throw new Error(`Failed to list buckets: ${error.message}`);
        }
    }

    async analyzeBucket(bucketName, userId) {
        const analysis = {
            name: bucketName,
            provider: 'aws',
            type: 's3-bucket',
            region: await this.getBucketRegion(bucketName),
            publicAccess: false,
            encrypted: false,
            versioning: false,
            loggingEnabled: false,
            objects: [],
            vulnerabilities: [],
            riskScore: 100
        };

        try {
            // Check public access
            analysis.publicAccess = await this.checkPublicAccess(bucketName);
            
            // Check encryption
            analysis.encrypted = await this.checkEncryption(bucketName);
            
            // Check versioning
            analysis.versioning = await this.checkVersioning(bucketName);
            
            // Check logging
            analysis.loggingEnabled = await this.checkLogging(bucketName);
            
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
                    resource: `s3://${bucketName}`,
                    description: 'Bucket is publicly accessible',
                    recommendation: 'Restrict bucket access to specific IAM roles or IP ranges'
                });
                analysis.riskScore -= 30;
            }
            
            if (!analysis.encrypted) {
                analysis.vulnerabilities.push({
                    severity: 'high',
                    type: 'no_encryption',
                    resource: `s3://${bucketName}`,
                    description: 'Bucket does not have default encryption enabled',
                    recommendation: 'Enable default server-side encryption (AES-256 or AWS-KMS)'
                });
                analysis.riskScore -= 20;
            }
            
            if (!analysis.loggingEnabled) {
                analysis.vulnerabilities.push({
                    severity: 'medium',
                    type: 'no_logging',
                    resource: `s3://${bucketName}`,
                    description: 'Bucket access logging is not enabled',
                    recommendation: 'Enable S3 access logging and CloudTrail data events'
                });
                analysis.riskScore -= 10;
            }
            
            if (!analysis.versioning) {
                analysis.vulnerabilities.push({
                    severity: 'low',
                    type: 'no_versioning',
                    resource: `s3://${bucketName}`,
                    description: 'Bucket versioning is not enabled',
                    recommendation: 'Enable bucket versioning for data protection'
                });
                analysis.riskScore -= 5;
            }
            
        } catch (error) {
            analysis.vulnerabilities.push({
                severity: 'medium',
                type: 'analysis_error',
                resource: `s3://${bucketName}`,
                description: `Failed to analyze bucket: ${error.message}`,
                recommendation: 'Check IAM permissions and bucket policies'
            });
        }

        return analysis;
    }

    async getBucketRegion(bucketName) {
        try {
            const response = await this.s3.getBucketLocation({ Bucket: bucketName }).promise();
            return response.LocationConstraint || 'us-east-1';
        } catch (error) {
            return 'unknown';
        }
    }

    async checkPublicAccess(bucketName) {
        try {
            // Check ACL
            const aclResponse = await this.s3.getBucketAcl({ Bucket: bucketName }).promise();
            const publicGrants = aclResponse.Grants.filter(grant => 
                grant.Grantee.URI === 'http://acs.amazonaws.com/groups/global/AllUsers' ||
                grant.Grantee.URI === 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            );

            if (publicGrants.length > 0) {
                return true;
            }

            // Check bucket policy
            try {
                const policyResponse = await this.s3.getBucketPolicy({ Bucket: bucketName }).promise();
                if (policyResponse.Policy) {
                    const policy = JSON.parse(policyResponse.Policy);
                    const publicStatements = policy.Statement.filter(statement =>
                        statement.Effect === 'Allow' && (
                            statement.Principal === '*' ||
                            (Array.isArray(statement.Principal) && statement.Principal.includes('*')) ||
                            (typeof statement.Principal === 'object' && statement.Principal.AWS === '*')
                        )
                    );
                    return publicStatements.length > 0;
                }
            } catch (policyError) {
                // No policy exists
            }

            // Check block public access settings
            try {
                const configResponse = await this.s3.getPublicAccessBlock({ Bucket: bucketName }).promise();
                const blockPublicAcls = configResponse.BlockPublicAcls;
                const blockPublicPolicy = configResponse.BlockPublicPolicy;
                const ignorePublicAcls = configResponse.IgnorePublicAcls;
                const restrictPublicBuckets = configResponse.RestrictPublicBuckets;

                return !(blockPublicAcls && blockPublicPolicy && ignorePublicAcls && restrictPublicBuckets);
            } catch (configError) {
                // Assume public if we can't check
                return true;
            }

        } catch (error) {
            return false;
        }
    }

    async checkEncryption(bucketName) {
        try {
            const response = await this.s3.getBucketEncryption({ Bucket: bucketName }).promise();
            return response.ServerSideEncryptionRules && response.ServerSideEncryptionRules.length > 0;
        } catch (error) {
            // Check default encryption setting
            try {
                const response = await this.s3.getBucketLocation({ Bucket: bucketName }).promise();
                return false; // No encryption configured
            } catch (locationError) {
                return false;
            }
        }
    }

    async checkVersioning(bucketName) {
        try {
            const response = await this.s3.getBucketVersioning({ Bucket: bucketName }).promise();
            return response.Status === 'Enabled' || response.MFADelete === 'Enabled';
        } catch (error) {
            return false;
        }
    }

    async checkLogging(bucketName) {
        try {
            // Check S3 access logging
            const loggingResponse = await this.s3.getBucketLogging({ Bucket: bucketName }).promise();
            const hasS3Logging = loggingResponse.LoggingEnabled && loggingResponse.LoggingEnabled.TargetBucket;
            
            // Check CloudTrail data events (simplified)
            // In production, you'd check CloudTrail trails for data events on this bucket
            const hasCloudTrailLogging = true; // Placeholder
            
            return hasS3Logging || hasCloudTrailLogging;
        } catch (error) {
            return false;
        }
    }

    async listObjects(bucketName, maxKeys = 100) {
        try {
            const response = await this.s3.listObjectsV2({
                Bucket: bucketName,
                MaxKeys: maxKeys
            }).promise();
            
            return (response.Contents || []).map(obj => ({
                key: obj.Key,
                size: obj.Size,
                lastModified: obj.LastModified,
                storageClass: obj.StorageClass,
                owner: obj.Owner?.DisplayName || 'Unknown',
                suspicious: this.isSuspiciousObject(obj.Key, obj.Size)
            }));
        } catch (error) {
            return [];
        }
    }

    isSuspiciousObject(key, size) {
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

        const suspiciousName = suspiciousPatterns.some(pattern => pattern.test(key));
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
                    resource: obj.key,
                    description: `Suspicious file detected: ${obj.key} (${this.formatBytes(obj.size)})`,
                    recommendation: 'Review file contents and restrict access if sensitive'
                });
            }
        });
        
        return vulnerabilities;
    }

    async analyzeAuditLogs(credentials, userId, timeRange = 24) {
        try {
            await this.authenticate(credentials);
            
            const logs = {
                provider: 'aws',
                service: 'cloudtrail',
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

            // Get CloudTrail events (simplified)
            try {
                const endTime = new Date();
                const startTime = new Date(endTime.getTime() - timeRange * 60 * 60 * 1000);

                const events = await this.getCloudTrailEvents(startTime, endTime);
                logs.events = events;
                logs.summary.totalEvents = events.length;

                // Analyze for anomalies
                events.forEach(event => {
                    if (this.isUnusualAccess(event)) {
                        logs.summary.unusualAccess++;
                        logs.anomalies.push({
                            severity: 'medium',
                            type: 'unusual_access',
                            resource: event.eventSource,
                            description: `Unusual access from ${event.sourceIPAddress}`,
                            timestamp: event.eventTime,
                            recommendation: 'Investigate source IP and access pattern'
                        });
                    }

                    if (this.isFailedAttempt(event)) {
                        logs.summary.failedAttempts++;
                        logs.anomalies.push({
                            severity: 'low',
                            type: 'failed_attempt',
                            resource: event.eventName,
                            description: `Failed ${event.eventName} attempt`,
                            timestamp: event.eventTime,
                            recommendation: 'Monitor for potential brute force attempts'
                        });
                    }

                    if (this.isUnknownRegion(event)) {
                        logs.summary.unknownRegions++;
                        logs.anomalies.push({
                            severity: 'medium',
                            type: 'unknown_region',
                            resource: event.awsRegion,
                            description: `Access from unfamiliar region: ${event.awsRegion}`,
                            timestamp: event.eventTime,
                            recommendation: 'Verify if access from this region is expected'
                        });
                    }
                });

            } catch (error) {
                logs.anomalies.push({
                    severity: 'medium',
                    type: 'log_analysis_error',
                    resource: 'cloudtrail',
                    description: `Failed to analyze logs: ${error.message}`,
                    recommendation: 'Check CloudTrail configuration and permissions'
                });
            }

            return logs;
        } catch (error) {
            throw new Error(`AWS audit log analysis failed: ${error.message}`);
        }
    }

    async getCloudTrailEvents(startTime, endTime) {
        // Simplified CloudTrail event retrieval
        // In production, you'd use CloudTrail lookup events or event history
        return [
            {
                eventTime: new Date(),
                eventName: 'GetObject',
                eventSource: 's3.amazonaws.com',
                sourceIPAddress: '203.0.113.1',
                awsRegion: 'us-east-1',
                userIdentity: {
                    userName: 'test-user'
                }
            }
        ];
    }

    isUnusualAccess(event) {
        // Check for unusual patterns
        const unusualIPs = ['203.0.113.1', '198.51.100.1'];
        return unusualIPs.includes(event.sourceIPAddress);
    }

    isFailedAttempt(event) {
        return event.eventName && event.eventName.includes('Failed');
    }

    isUnknownRegion(event) {
        const knownRegions = ['us-east-1', 'us-west-2', 'eu-west-1'];
        return event.awsRegion && !knownRegions.includes(event.awsRegion);
    }

    async getThreatIntelligence(credentials) {
        try {
            await this.authenticate(credentials);
            
            return {
                provider: 'aws',
                services: {
                    guardduty: {
                        status: 'placeholder',
                        findings: [],
                        description: 'AWS GuardDuty threat detection service'
                    },
                    securityHub: {
                        status: 'placeholder',
                        findings: [],
                        description: 'AWS Security Hub security aggregation service'
                    },
                    macie: {
                        status: 'placeholder',
                        findings: [],
                        description: 'AWS Macie data security service'
                    }
                },
                recommendations: [
                    'Enable AWS GuardDuty for threat detection',
                    'Configure AWS Security Hub for centralized security monitoring',
                    'Use AWS Macie for sensitive data discovery'
                ]
            };
        } catch (error) {
            throw new Error(`AWS threat intelligence failed: ${error.message}`);
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

module.exports = AWSService;
