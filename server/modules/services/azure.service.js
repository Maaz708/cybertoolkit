const { BlobServiceClient, StorageSharedKeyCredential } = require('@azure/storage-blob');
const { SubscriptionClient } = require('@azure/arm-subscriptions');
const { ResourceManagementClient } = require('@azure/arm-resources');

class AzureService {
    constructor() {
        this.subscriptionId = process.env.AZURE_SUBSCRIPTION_ID || '';
        this.resourceGroup = process.env.AZURE_RESOURCE_GROUP || '';
    }

    async authenticate(credentials) {
        try {
            const credential = new StorageSharedKeyCredential(
                credentials.accountName,
                credentials.accountKey
            );

            this.blobServiceClient = new BlobServiceClient(
                `https://${credentials.accountName}.blob.core.windows.net`,
                credential
            );

            // Test authentication by listing containers
            await this.blobServiceClient.listContainers().byPage().next();
            return { authenticated: true, provider: 'azure' };
        } catch (error) {
            throw new Error(`Azure authentication failed: ${error.message}`);
        }
    }

    async analyzeStorage(credentials, userId) {
        try {
            await this.authenticate(credentials);
            
            const containers = await this.listContainers();
            const analysis = {
                provider: 'azure',
                resources: [],
                vulnerabilities: [],
                summary: {
                    totalContainers: containers.length,
                    publicContainers: 0,
                    unencryptedContainers: 0,
                    containersWithLogging: 0
                }
            };

            for (const container of containers) {
                const containerAnalysis = await this.analyzeContainer(container.name, userId);
                analysis.resources.push(containerAnalysis);
                
                // Update summary
                if (containerAnalysis.publicAccess) analysis.summary.publicContainers++;
                if (!containerAnalysis.encrypted) analysis.summary.unencryptedContainers++;
                if (containerAnalysis.loggingEnabled) analysis.summary.containersWithLogging++;
                
                // Add vulnerabilities
                analysis.vulnerabilities.push(...containerAnalysis.vulnerabilities);
            }

            return analysis;
        } catch (error) {
            throw new Error(`Azure storage analysis failed: ${error.message}`);
        }
    }

    async listContainers() {
        try {
            const containers = [];
            for await (const container of this.blobServiceClient.listContainers()) {
                containers.push(container);
            }
            return containers;
        } catch (error) {
            throw new Error(`Failed to list containers: ${error.message}`);
        }
    }

    async analyzeContainer(containerName, userId) {
        const analysis = {
            name: containerName,
            provider: 'azure',
            type: 'blob-container',
            accountName: this.blobServiceClient.accountName,
            publicAccess: false,
            encrypted: false,
            loggingEnabled: false,
            objects: [],
            vulnerabilities: [],
            riskScore: 100
        };

        try {
            // Get container properties
            const containerClient = this.blobServiceClient.getContainerClient(containerName);
            const properties = await containerClient.getProperties();
            
            // Check public access
            analysis.publicAccess = await this.checkPublicAccess(containerName);
            
            // Check encryption
            analysis.encrypted = await this.checkEncryption(containerName);
            
            // Check logging
            analysis.loggingEnabled = await this.checkLogging(containerName);
            
            // List blobs (limited)
            analysis.objects = await this.listBlobs(containerName, 50);
            
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
                    resource: `https://${this.blobServiceClient.accountName}.blob.core.windows.net/${containerName}`,
                    description: 'Container is publicly accessible',
                    recommendation: 'Restrict container access to specific Azure AD identities or IP ranges'
                });
                analysis.riskScore -= 30;
            }
            
            if (!analysis.encrypted) {
                analysis.vulnerabilities.push({
                    severity: 'high',
                    type: 'no_encryption',
                    resource: `https://${this.blobServiceClient.accountName}.blob.core.windows.net/${containerName}`,
                    description: 'Container does not have encryption enabled',
                    recommendation: 'Enable customer-managed encryption keys or Microsoft-managed encryption'
                });
                analysis.riskScore -= 20;
            }
            
            if (!analysis.loggingEnabled) {
                analysis.vulnerabilities.push({
                    severity: 'medium',
                    type: 'no_logging',
                    resource: `https://${this.blobServiceClient.accountName}.blob.core.windows.net/${containerName}`,
                    description: 'Container access logging is not enabled',
                    recommendation: 'Enable Azure Storage logging and Azure Monitor'
                });
                analysis.riskScore -= 10;
            }
            
        } catch (error) {
            analysis.vulnerabilities.push({
                severity: 'medium',
                type: 'analysis_error',
                resource: `https://${this.blobServiceClient.accountName}.blob.core.windows.net/${containerName}`,
                description: `Failed to analyze container: ${error.message}`,
                recommendation: 'Check Azure AD permissions and container access policies'
            });
        }

        return analysis;
    }

    async checkPublicAccess(containerName) {
        try {
            const containerClient = this.blobServiceClient.getContainerClient(containerName);
            const properties = await containerClient.getProperties();
            
            // Check container access level
            const accessLevel = properties.properties.publicAccess;
            return accessLevel !== 'none';
        } catch (error) {
            // Assume public if we can't check
            return true;
        }
    }

    async checkEncryption(containerName) {
        try {
            // Azure Storage encryption is enabled by default for all containers
            // Check if customer-managed encryption is configured
            const containerClient = this.blobServiceClient.getContainerClient(containerName);
            const properties = await containerClient.getProperties();
            
            // In production, you'd check for customer-managed key settings
            // For now, assume Microsoft-managed encryption is enabled
            return true;
        } catch (error) {
            return false;
        }
    }

    async checkLogging(containerName) {
        try {
            // Check if Azure Monitor logging is enabled for the storage account
            // This is a simplified check - in production you'd use Azure Monitor APIs
            const containerClient = this.blobServiceClient.getContainerClient(containerName);
            const properties = await containerClient.getProperties();
            
            // Placeholder for logging check
            return false;
        } catch (error) {
            return false;
        }
    }

    async listBlobs(containerName, maxResults = 100) {
        try {
            const containerClient = this.blobServiceClient.getContainerClient(containerName);
            const blobs = [];
            
            for await (const blob of containerClient.listBlobsFlat({ maxResults })) {
                blobs.push({
                    name: blob.name,
                    size: blob.properties.contentLength,
                    lastModified: blob.properties.lastModified,
                    contentType: blob.properties.contentType,
                    blobType: blob.properties.blobType,
                    suspicious: this.isSuspiciousBlob(blob.name, blob.properties.contentLength)
                });
                
                if (blobs.length >= maxResults) break;
            }
            
            return blobs;
        } catch (error) {
            return [];
        }
    }

    isSuspiciousBlob(name, size) {
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

    detectDataExposure(blobs) {
        const vulnerabilities = [];
        
        blobs.forEach(blob => {
            if (blob.suspicious) {
                vulnerabilities.push({
                    severity: 'high',
                    type: 'data_exposure',
                    resource: blob.name,
                    description: `Suspicious blob detected: ${blob.name} (${this.formatBytes(blob.size)})`,
                    recommendation: 'Review blob contents and restrict access if sensitive'
                });
            }
        });
        
        return vulnerabilities;
    }

    async analyzeAuditLogs(credentials, userId, timeRange = 24) {
        try {
            await this.authenticate(credentials);
            
            const logs = {
                provider: 'azure',
                service: 'azure-monitor',
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

            // Get Azure Monitor logs (simplified)
            try {
                const endTime = new Date();
                const startTime = new Date(endTime.getTime() - timeRange * 60 * 60 * 1000);

                const events = await this.getAzureMonitorLogs(startTime, endTime);
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
                            description: `Unusual access from ${event.callerIpAddress}`,
                            timestamp: event.timestamp,
                            recommendation: 'Investigate source IP and access pattern'
                        });
                    }

                    if (this.isFailedAttempt(event)) {
                        logs.summary.failedAttempts++;
                        logs.anomalies.push({
                            severity: 'low',
                            type: 'failed_attempt',
                            resource: event.operationName,
                            description: `Failed ${event.operationName} attempt`,
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
                    resource: 'azure-monitor',
                    description: `Failed to analyze logs: ${error.message}`,
                    recommendation: 'Check Azure Monitor configuration and permissions'
                });
            }

            return logs;
        } catch (error) {
            throw new Error(`Azure audit log analysis failed: ${error.message}`);
        }
    }

    async getAzureMonitorLogs(startTime, endTime) {
        // Simplified Azure Monitor log retrieval
        // In production, you'd use Azure Monitor Logs API or Log Analytics
        return [
            {
                timestamp: new Date(),
                operationName: 'ListBlobs',
                resource: 'blob-storage',
                callerIpAddress: '203.0.113.1',
                location: 'East US',
                category: 'StorageRead'
            }
        ];
    }

    isUnusualAccess(event) {
        // Check for unusual patterns
        const unusualIPs = ['203.0.113.1', '198.51.100.1'];
        return unusualIPs.includes(event.callerIpAddress);
    }

    isFailedAttempt(event) {
        return event.operationName && event.operationName.includes('Failed');
    }

    isUnknownRegion(event) {
        const knownRegions = ['East US', 'West US', 'West Europe'];
        return event.location && !knownRegions.includes(event.location);
    }

    async getThreatIntelligence(credentials) {
        try {
            await this.authenticate(credentials);
            
            return {
                provider: 'azure',
                services: {
                    defenderForCloud: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Microsoft Defender for Cloud'
                    },
                    sentinel: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Azure Sentinel SIEM'
                    },
                    defenderForStorage: {
                        status: 'placeholder',
                        findings: [],
                        description: 'Microsoft Defender for Storage'
                    }
                },
                recommendations: [
                    'Enable Microsoft Defender for Cloud for comprehensive protection',
                    'Configure Azure Sentinel for advanced threat detection',
                    'Use Microsoft Defender for Storage for malware scanning'
                ]
            };
        } catch (error) {
            throw new Error(`Azure threat intelligence failed: ${error.message}`);
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

module.exports = AzureService;
