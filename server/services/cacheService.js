/**
 * Cache Service
 * Redis-based caching with fallback to in-memory
 */

const logger = require('../utils/logger');

// Track if we've already logged the Redis warning
let redisWarningLogged = false;

class CacheService {
    constructor(options = {}) {
        this.redis = null;
        this.memoryCache = new Map();
        this.isConnected = false;
        this.defaultTTL = options.defaultTTL || 10; // seconds
        
        // Try to initialize Redis
        this.initRedis(options.redis);
    }

    async initRedis(redisConfig = {}) {
        try {
            const Redis = require('ioredis');
            this.redis = new Redis({
                host: redisConfig.host || process.env.REDIS_HOST || 'localhost',
                port: redisConfig.port || process.env.REDIS_PORT || 6379,
                password: redisConfig.password || process.env.REDIS_PASSWORD,
                db: redisConfig.db || 0,
                retryStrategy: (times) => {
                    const delay = Math.min(times * 50, 2000);
                    return delay;
                },
                maxRetriesPerRequest: 3
            });

            this.redis.on('connect', () => {
                logger.info('Redis cache connected');
                this.isConnected = true;
            });

            this.redis.on('error', (err) => {
                if (!redisWarningLogged) {
                    logger.warn('Redis error, using memory cache fallback');
                    redisWarningLogged = true;
                }
                this.isConnected = false;
            });

        } catch (error) {
            if (!redisWarningLogged) {
                logger.warn('Redis not available, using memory cache fallback');
                redisWarningLogged = true;
            }
            this.isConnected = false;
        }
    }

    /**
     * Get value from cache
     * @param {string} key - Cache key
     * @returns {Promise<any>} Cached value or null
     */
    async get(key) {
        try {
            if (this.isConnected && this.redis) {
                const value = await this.redis.get(key);
                if (value) {
                    return JSON.parse(value);
                }
            }
            
            // Fallback to memory cache
            const memValue = this.memoryCache.get(key);
            if (memValue && memValue.expires > Date.now()) {
                return memValue.data;
            }
            
            return null;
        } catch (error) {
            logger.warn('Cache get error', { error: error.message });
            return null;
        }
    }

    /**
     * Set value in cache
     * @param {string} key - Cache key
     * @param {any} value - Value to cache
     * @param {number} ttl - Time to live in seconds
     * @returns {Promise<boolean>} Success status
     */
    async set(key, value, ttl = null) {
        const seconds = ttl || this.defaultTTL;
        
        try {
            if (this.isConnected && this.redis) {
                await this.redis.setex(key, seconds, JSON.stringify(value));
                return true;
            }
            
            // Fallback to memory cache
            this.memoryCache.set(key, {
                data: value,
                expires: Date.now() + (seconds * 1000)
            });
            
            return true;
        } catch (error) {
            logger.warn('Cache set error', { error: error.message });
            return false;
        }
    }

    /**
     * Delete value from cache
     * @param {string} key - Cache key
     * @returns {Promise<boolean>} Success status
     */
    async del(key) {
        try {
            if (this.isConnected && this.redis) {
                await this.redis.del(key);
            }
            
            this.memoryCache.delete(key);
            return true;
        } catch (error) {
            logger.warn('Cache delete error', { error: error.message });
            return false;
        }
    }

    /**
     * Delete keys matching pattern
     * @param {string} pattern - Key pattern (e.g., 'network:*')
     * @returns {Promise<number>} Number of keys deleted
     */
    async delPattern(pattern) {
        try {
            if (this.isConnected && this.redis) {
                const keys = await this.redis.keys(pattern);
                if (keys.length > 0) {
                    await this.redis.del(...keys);
                    return keys.length;
                }
            }
            
            // Memory cache pattern matching
            let deleted = 0;
            const regex = new RegExp(pattern.replace('*', '.*'));
            for (const [key] of this.memoryCache) {
                if (regex.test(key)) {
                    this.memoryCache.delete(key);
                    deleted++;
                }
            }
            
            return deleted;
        } catch (error) {
            logger.warn('Cache pattern delete error', { error: error.message });
            return 0;
        }
    }

    /**
     * Get cache statistics
     * @returns {Object} Cache stats
     */
    getStats() {
        return {
            backend: this.isConnected ? 'redis' : 'memory',
            connected: this.isConnected,
            memoryKeys: this.memoryCache.size
        };
    }

    /**
     * Clean up expired memory cache entries
     */
    cleanup() {
        const now = Date.now();
        for (const [key, value] of this.memoryCache) {
            if (value.expires < now) {
                this.memoryCache.delete(key);
            }
        }
    }
}

// Create singleton
const cache = new CacheService();

// Periodic cleanup for memory cache
setInterval(() => {
    cache.cleanup();
}, 60000); // Every minute

module.exports = cache;
module.exports.CacheService = CacheService;
