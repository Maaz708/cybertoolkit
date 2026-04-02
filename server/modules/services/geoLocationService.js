const axios = require('axios');

class GeoLocationService {
    constructor() {
        this.cache = new Map(); // Cache results to avoid API limits
        this.cacheTimeout = 5 * 60 * 1000; // 5 minutes
    }

    async getLocation(ip) {
        try {
            // Skip local IPs
            if (
                ip === '127.0.0.1' ||
                ip === '::1' ||
                ip.startsWith('192.168.') ||
                ip.startsWith('10.') ||
                ip.startsWith('172.') ||
                ip.startsWith('169.254.') ||
                ip === '0.0.0.0'
            ) {
                return null;
            }

            // Check cache first
            const cached = this.cache.get(ip);
            if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
                return cached.data;
            }

            // Use ip-api.com (free, no API key required)
            const response = await axios.get(`http://ip-api.com/json/${ip}`, {
                timeout: 5000
            });

            if (response.data.status === 'fail') {
                return null;
            }

            const location = {
                ip,
                country: response.data.country || 'Unknown',
                country_code: response.data.countryCode || 'XX',
                city: response.data.city || 'Unknown',
                region: response.data.regionName || 'Unknown',
                lat: response.data.lat || 0,
                lon: response.data.lon || 0,
                isp: response.data.isp || 'Unknown',
                org: response.data.org || 'Unknown',
                as: response.data.as || 'Unknown',
                timezone: response.data.timezone || 'Unknown'
            };

            // Cache the result
            this.cache.set(ip, {
                data: location,
                timestamp: Date.now()
            });

            return location;

        } catch (error) {
            console.warn(`Failed to get location for IP ${ip}:`, error.message);
            return null;
        }
    }

    async getBatchLocations(ips) {
        const results = [];
        const uniqueIPs = [...new Set(ips)];

        // Process IPs in parallel with a small delay to avoid rate limiting
        const promises = uniqueIPs.map(async (ip, index) => {
            // Add small delay between requests
            await new Promise(resolve => setTimeout(resolve, index * 100));
            return this.getLocation(ip);
        });

        const locations = await Promise.all(promises);
        
        return locations.filter(loc => loc !== null);
    }

    // For testing - add some known public IPs
    async getTestLocations() {
        const testIPs = [
            '8.8.8.8',      // Google DNS (US)
            '1.1.1.1',      // Cloudflare DNS (US)
            '208.67.222.222', // OpenDNS (US)
            '142.250.183.14', // Google (US)
            '151.101.1.69',  // Cloudflare (US)
            '13.107.42.14',  // Microsoft (US)
            '157.240.22.35', // Facebook (US)
            '17.253.144.10', // Apple (US)
            '205.251.192.0', // Amazon (US)
            '31.13.66.35'    // Meta (Ireland)
        ];

        return this.getBatchLocations(testIPs);
    }

    clearCache() {
        this.cache.clear();
    }

    getCacheStats() {
        return {
            size: this.cache.size,
            entries: Array.from(this.cache.keys())
        };
    }
}

module.exports = GeoLocationService;
