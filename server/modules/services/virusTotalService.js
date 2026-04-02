const axios = require('axios');

class VirusTotalService {
    constructor(apiKey) {
        this.apiKey = apiKey;
        this.baseURL = 'https://www.virustotal.com/vtapi/v2';
        this.rateLimitDelay = 1000; // 1 second between requests
    }

    async scanFile(fileBuffer, filename) {
        try {
            await this.delay(this.rateLimitDelay);
            
            const formData = new FormData();
            const blob = new Blob([fileBuffer], { type: 'application/octet-stream' });
            formData.append('file', blob, filename);
            formData.append('apikey', this.apiKey);

            const response = await axios.post(`${this.baseURL}/file/scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            });

            return {
                success: true,
                scanId: response.data.scan_id,
                permalink: response.data.permalink,
                resource: response.data.resource
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message
            };
        }
    }

    async getFileReport(resource) {
        try {
            await this.delay(this.rateLimitDelay);

            const response = await axios.get(`${this.baseURL}/file/report`, {
                params: {
                    apikey: this.apiKey,
                    resource: resource
                }
            });

            const report = response.data;
            return {
                success: true,
                scanId: report.scan_id,
                scanDate: report.scan_date,
                positives: report.positives,
                total: report.total,
                permalink: report.permalink,
                detectedEngines: this.extractDetectedEngines(report.scans),
                fileHash: {
                    md5: report.md5,
                    sha1: report.sha1,
                    sha256: report.sha256
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message
            };
        }
    }

    async scanUrl(url) {
        try {
            await this.delay(this.rateLimitDelay);

            const response = await axios.post(`${this.baseURL}/url/scan`, null, {
                params: {
                    apikey: this.apiKey,
                    url: url
                }
            });

            return {
                success: true,
                scanId: response.data.scan_id,
                permalink: response.data.permalink,
                resource: response.data.resource
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message
            };
        }
    }

    async getUrlReport(resource) {
        try {
            await this.delay(this.rateLimitDelay);

            const response = await axios.get(`${this.baseURL}/url/report`, {
                params: {
                    apikey: this.apiKey,
                    resource: resource
                }
            });

            const report = response.data;
            return {
                success: true,
                scanId: report.scan_id,
                scanDate: report.scan_date,
                positives: report.positives,
                total: report.total,
                permalink: report.permalink,
                url: report.url,
                detectedEngines: this.extractDetectedEngines(report.scans)
            };
        } catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message
            };
        }
    }

    async analyzeAttachment(attachment) {
        if (!this.apiKey) {
            return {
                success: false,
                error: 'VirusTotal API key not configured'
            };
        }

        try {
            // First, scan the file
            const scanResult = await this.scanFile(attachment.content, attachment.filename);
            if (!scanResult.success) {
                return scanResult;
            }

            // Wait a moment for the scan to process
            await this.delay(3000);

            // Get the report
            const reportResult = await this.getFileReport(scanResult.scanId);
            return reportResult;
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    async analyzeUrl(url) {
        if (!this.apiKey) {
            return {
                success: false,
                error: 'VirusTotal API key not configured'
            };
        }

        try {
            // First, scan the URL
            const scanResult = await this.scanUrl(url);
            if (!scanResult.success) {
                return scanResult;
            }

            // Wait a moment for the scan to process
            await this.delay(3000);

            // Get the report
            const reportResult = await this.getUrlReport(scanResult.scanId);
            return reportResult;
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    extractDetectedEngines(scans) {
        if (!scans) return [];
        
        const detected = [];
        for (const [engine, result] of Object.entries(scans)) {
            if (result.detected) {
                detected.push({
                    engine: engine,
                    result: result.result,
                    version: result.version,
                    update: result.update
                });
            }
        }
        return detected;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    isApiKeyValid() {
        return this.apiKey && this.apiKey.length > 0;
    }
}

module.exports = VirusTotalService;
