/**
 * Data Transformation Utilities
 * Converts technical data to user-friendly formats
 * NON-BREAKING: Adds human-readable fields alongside raw values
 */

class DataTransformer {
    /**
     * Convert bytes to human readable format
     * @param {number} bytes - Bytes to convert
     * @param {number} decimals - Decimal places (default: 2)
     * @returns {string} Human readable string (e.g., "1.5 MB")
     */
    static formatBytes(bytes, decimals = 2) {
        if (bytes === 0 || bytes === undefined || bytes === null) return '0 B';
        if (bytes < 0) return '0 B';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        const index = Math.min(i, sizes.length - 1);
        
        return parseFloat((bytes / Math.pow(k, index)).toFixed(dm)) + ' ' + sizes[index];
    }

    /**
     * Format bandwidth speed (bytes/second to human readable)
     * @param {number} bytesPerSecond - Speed in bytes/second
     * @returns {Object} Formatted speed object with raw and human values
     */
    static formatBandwidth(bytesPerSecond) {
        const bps = bytesPerSecond || 0;
        
        return {
            // RAW: Keep original value
            raw: bps,
            
            // NEW: Human readable
            humanReadable: this.formatBytes(bps) + '/s',
            
            // NEW: MB/s for charts
            mbps: parseFloat((bps / 1024 / 1024).toFixed(2)),
            
            // NEW: KB/s for smaller values
            kbps: parseFloat((bps / 1024).toFixed(2))
        };
    }

    /**
     * Format timestamp to various readable formats
     * @param {string|Date} timestamp - ISO string or Date object
     * @returns {Object} Various formatted timestamp strings
     */
    static formatTimestamp(timestamp) {
        const date = timestamp instanceof Date ? timestamp : new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        // Time ago calculation
        let timeAgo;
        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (seconds < 60) timeAgo = `${seconds}s ago`;
        else if (minutes < 60) timeAgo = `${minutes}m ago`;
        else if (hours < 24) timeAgo = `${hours}h ago`;
        else timeAgo = `${days}d ago`;
        
        return {
            // RAW: Keep ISO format
            iso: date.toISOString(),
            
            // NEW: Human readable formats
            formatted: date.toLocaleString(),
            date: date.toLocaleDateString(),
            time: date.toLocaleTimeString(),
            timeAgo,
            
            // NEW: For charts (HH:mm)
            chartTime: date.toLocaleTimeString('en-US', { 
                hour: '2-digit', 
                minute: '2-digit',
                hour12: false 
            })
        };
    }

    /**
     * Enhance network stats with human readable values
     * @param {Object} stats - Raw network stats
     * @returns {Object} Enhanced stats with human readable fields
     */
    static enhanceNetworkStats(stats) {
        if (!stats) return null;
        
        const enhanced = { ...stats };
        
        // Enhance bandwidth
        if (stats.bandwidth) {
            enhanced.bandwidth = {
                // RAW: Keep original
                ...stats.bandwidth,
                
                // NEW: Human readable speed
                humanReadableInbound: this.formatBytes(stats.bandwidth.inbound) + '/s',
                humanReadableOutbound: this.formatBytes(stats.bandwidth.outbound) + '/s',
                
                // NEW: MB/s values for consistency
                inboundMBps: parseFloat((stats.bandwidth.inbound / 1024 / 1024).toFixed(2)),
                outboundMBps: parseFloat((stats.bandwidth.outbound / 1024 / 1024).toFixed(2))
            };
        }
        
        // Enhance total bytes
        if (stats.totalBytesSent !== undefined) {
            enhanced.totalBytesSentFormatted = this.formatBytes(stats.totalBytesSent);
        }
        if (stats.totalBytesReceived !== undefined) {
            enhanced.totalBytesReceivedFormatted = this.formatBytes(stats.totalBytesReceived);
        }
        
        // Enhance timestamp
        if (stats.timestamp) {
            enhanced.timestampFormatted = this.formatTimestamp(stats.timestamp);
        }
        
        return enhanced;
    }

    /**
     * Enhance connection data with location info
     * @param {Array} connections - Connection array
     * @param {Object} geoData - Geolocation data map (ip -> location)
     * @returns {Array} Enhanced connections
     */
    static enhanceConnections(connections, geoData = {}) {
        if (!Array.isArray(connections)) return [];
        
        return connections.map(conn => {
            const remoteIP = conn.remoteAddress || conn.remote?.split(':')[0];
            const geo = geoData[remoteIP] || {};
            
            return {
                // RAW: Keep all original fields
                ...conn,
                
                // NEW: Enhanced location data
                location: {
                    country: geo.country || conn.country || 'Unknown',
                    countryCode: geo.countryCode || conn.country || 'UN',
                    city: geo.city || conn.city || 'Unknown',
                    region: geo.region || 'Unknown',
                    isp: geo.isp || conn.isp || 'Unknown ISP',
                    org: geo.org,
                    
                    // Coordinates
                    lat: geo.lat || conn.lat || 0,
                    lon: geo.lon || conn.lng || conn.lon || 0
                },
                
                // NEW: Human readable bytes
                bytesSentFormatted: this.formatBytes(conn.bytes_sent || conn.bytesSent || 0),
                bytesReceivedFormatted: this.formatBytes(conn.bytes_recv || conn.bytesReceived || 0),
                
                // NEW: Total bytes for this connection
                totalBytes: (conn.bytes_sent || conn.bytesSent || 0) + (conn.bytes_recv || conn.bytesReceived || 0),
                totalBytesFormatted: this.formatBytes(
                    (conn.bytes_sent || conn.bytesSent || 0) + (conn.bytes_recv || conn.bytesReceived || 0)
                )
            };
        });
    }

    /**
     * Enhance hacker map data with better formatting
     * @param {Array} hackerMap - Hacker map data
     * @returns {Array} Enhanced hacker map
     */
    static enhanceHackerMap(hackerMap) {
        if (!Array.isArray(hackerMap)) return [];
        
        return hackerMap.map(entry => ({
            // RAW: Keep original
            ...entry,
            
            // NEW: Enhanced display fields
            display: {
                country: entry.country || 'Unknown',
                city: entry.city || 'Unknown',
                isp: entry.isp || 'Unknown ISP',
                
                // Flag emoji based on country code
                flag: this.getCountryFlag(entry.country_code || entry.country),
                
                // Risk level with icon indicator
                riskIndicator: this.getRiskIndicator(entry.riskLevel || 'normal'),
                
                // Formatted connection count
                connectionText: entry.connectionCount === 1 
                    ? '1 connection' 
                    : `${entry.connectionCount || 0} connections`
            },
            
            // NEW: Formatted bytes
            bytesFormatted: this.formatBytes(entry.bytes || 0),
            
            // NEW: Last seen timestamp
            lastSeen: entry.timestamp ? this.formatTimestamp(entry.timestamp) : null
        }));
    }

    /**
     * Get country flag emoji
     * @param {string} countryCode - Two letter country code
     * @returns {string} Flag emoji
     */
    static getCountryFlag(countryCode) {
        if (!countryCode || countryCode === 'Unknown') return '🌍';
        
        const code = countryCode.toUpperCase();
        // Convert country code to regional indicator symbols
        const base = 127397;
        return String.fromCodePoint(base + code.charCodeAt(0), base + code.charCodeAt(1));
    }

    /**
     * Get risk indicator emoji/text
     * @param {string} riskLevel - Risk level
     * @returns {Object} Risk indicator
     */
    static getRiskIndicator(riskLevel) {
        const indicators = {
            'critical': { emoji: '🔴', color: '#ff0000', text: 'Critical' },
            'high': { emoji: '🟠', color: '#ff6600', text: 'High' },
            'medium': { emoji: '🟡', color: '#ffcc00', text: 'Medium' },
            'low': { emoji: '🟢', color: '#00ff00', text: 'Low' },
            'normal': { emoji: '🔵', color: '#0066ff', text: 'Normal' },
            'info': { emoji: '⚪', color: '#cccccc', text: 'Info' }
        };
        
        return indicators[riskLevel?.toLowerCase()] || indicators.normal;
    }

    /**
     * Create summary cards for frontend
     * @param {Object} data - Network data
     * @returns {Object} Summary cards
     */
    static createSummaryCards(data) {
        const connections = data.connections || [];
        const bandwidth = data.bandwidth || {};
        const alerts = data.alerts || {};
        
        return {
            // NEW: Summary cards for UI
            cards: [
                {
                    id: 'totalConnections',
                    title: 'Total Connections',
                    value: connections.length || data.connectionCount || 0,
                    icon: 'Network',
                    trend: data.connectionTrend || 'stable',
                    change: data.connectionChange || 0
                },
                {
                    id: 'threatLevel',
                    title: 'Threat Level',
                    value: data.threatLevel || 'low',
                    severity: data.threatLevel || 'low',
                    icon: 'Shield',
                    score: data.riskScore || data.securityScore || 85
                },
                {
                    id: 'bandwidthUsage',
                    title: 'Bandwidth Usage',
                    value: this.formatBytes((bandwidth.inbound || 0) + (bandwidth.outbound || 0)) + '/s',
                    raw: {
                        inbound: bandwidth.inbound || 0,
                        outbound: bandwidth.outbound || 0
                    },
                    icon: 'Activity',
                    percentage: data.bandwidthPercentage || 0
                },
                {
                    id: 'riskScore',
                    title: 'Security Score',
                    value: data.riskScore || data.securityScore || 85,
                    max: 100,
                    icon: 'Lock',
                    status: this.getScoreStatus(data.riskScore || data.securityScore || 85)
                }
            ],
            
            // NEW: Quick stats
            quickStats: {
                activeAlerts: alerts.summary?.high || 0,
                suspiciousConnections: data.suspiciousConnections?.length || 0,
                blockedAttempts: data.blockedConnections || 0,
                openPorts: data.open_ports?.length || 0
            }
        };
    }

    /**
     * Get score status text
     * @param {number} score - Security score
     * @returns {string} Status text
     */
    static getScoreStatus(score) {
        if (score >= 90) return 'Excellent';
        if (score >= 75) return 'Good';
        if (score >= 60) return 'Fair';
        if (score >= 40) return 'Poor';
        return 'Critical';
    }

    /**
     * Transform data for charts
     * @param {Array} history - Historical data
     * @returns {Object} Chart-ready data
     */
    static transformForCharts(history) {
        if (!Array.isArray(history)) return { trafficOverTime: [], connectionsOverTime: [] };
        
        return {
            // NEW: Traffic over time
            trafficOverTime: history.map(item => ({
                time: this.formatTimestamp(item.timestamp).chartTime,
                inbound: parseFloat(((item.bandwidth?.inbound || 0) / 1024 / 1024).toFixed(2)),
                outbound: parseFloat(((item.bandwidth?.outbound || 0) / 1024 / 1024).toFixed(2)),
                total: parseFloat((((item.bandwidth?.inbound || 0) + (item.bandwidth?.outbound || 0)) / 1024 / 1024).toFixed(2))
            })),
            
            // NEW: Connections over time
            connectionsOverTime: history.map(item => ({
                time: this.formatTimestamp(item.timestamp).chartTime,
                count: item.connections?.length || item.connectionCount || 0,
                established: item.protocols?.TCP || 0,
                other: (item.protocols?.UDP || 0) + (item.protocols?.Other || 0)
            })),
            
            // NEW: Protocol distribution
            protocolDistribution: history.length > 0 ? {
                tcp: history[history.length - 1].protocols?.TCP || 0,
                udp: history[history.length - 1].protocols?.UDP || 0,
                other: history[history.length - 1].protocols?.Other || 0
            } : { tcp: 0, udp: 0, other: 0 }
        };
    }
}

module.exports = DataTransformer;
