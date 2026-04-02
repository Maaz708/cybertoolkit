/**
 * Rate Limiting Middleware
 * Configurable rate limiting with Redis/memory fallback
 */

const logger = require('../utils/logger');

class RateLimiter {
    constructor(options = {}) {
        this.windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
        this.maxRequests = options.maxRequests || 100;
        this.keyPrefix = options.keyPrefix || 'ratelimit:';
        
        // Store for memory fallback
        this.requests = new Map();
        
        // Try Redis
        this.redis = null;
        this.initRedis();
    }

    async initRedis() {
        try {
            const Redis = require('ioredis');
            this.redis = new Redis({
                host: process.env.REDIS_HOST || 'localhost',
                port: process.env.REDIS_PORT || 6379,
                retryStrategy: () => null // Don't retry, use memory fallback
            });
            
            this.redis.on('error', () => {
                this.redis = null;
            });
        } catch {
            this.redis = null;
        }
    }

    /**
     * Create middleware function
     * @returns {Function} Express middleware
     */
    middleware() {
        return async (req, res, next) => {
            try {
                const key = this.getKey(req);
                const result = await this.checkLimit(key);
                
                // Add rate limit headers
                res.setHeader('X-RateLimit-Limit', this.maxRequests);
                res.setHeader('X-RateLimit-Remaining', result.remaining);
                res.setHeader('X-RateLimit-Reset', result.resetTime);
                
                if (result.allowed) {
                    next();
                } else {
                    res.status(429).json({
                        status: 'error',
                        error: 'Too many requests',
                        message: 'Rate limit exceeded. Please try again later.',
                        retryAfter: Math.ceil(this.windowMs / 1000)
                    });
                }
            } catch (error) {
                logger.error('Rate limiter error', { error: error.message });
                next(); // Fail open
            }
        };
    }

    /**
     * Get rate limit key for request
     * @param {Object} req - Express request
     * @returns {string} Rate limit key
     */
    getKey(req) {
        const identifier = req.user?.userId || req.ip || 'unknown';
        const route = req.route?.path || req.path;
        return `${this.keyPrefix}${identifier}:${route}`;
    }

    /**
     * Check if request is within rate limit
     * @param {string} key - Rate limit key
     * @returns {Object} Limit check result
     */
    async checkLimit(key) {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        if (this.redis) {
            try {
                // Use Redis for distributed rate limiting
                const multi = this.redis.multi();
                multi.zremrangebyscore(key, 0, windowStart);
                multi.zcard(key);
                multi.zadd(key, now, `${now}-${Math.random()}`);
                multi.pexpire(key, this.windowMs);
                
                const results = await multi.exec();
                const count = results[1][1];
                
                return {
                    allowed: count < this.maxRequests,
                    remaining: Math.max(0, this.maxRequests - count - 1),
                    resetTime: now + this.windowMs
                };
            } catch {
                // Fall through to memory implementation
            }
        }
        
        // Memory-based rate limiting
        let requests = this.requests.get(key) || [];
        
        // Remove old requests
        requests = requests.filter(time => time > windowStart);
        
        const allowed = requests.length < this.maxRequests;
        
        if (allowed) {
            requests.push(now);
        }
        
        this.requests.set(key, requests);
        
        return {
            allowed,
            remaining: Math.max(0, this.maxRequests - requests.length),
            resetTime: now + this.windowMs
        };
    }
}

// Predefined rate limiters
const strictLimiter = new RateLimiter({
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 10,
    keyPrefix: 'ratelimit:strict:'
});

const standardLimiter = new RateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    keyPrefix: 'ratelimit:standard:'
});

const generousLimiter = new RateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    keyPrefix: 'ratelimit:generous:'
});

module.exports = {
    RateLimiter,
    strict: strictLimiter.middleware(),
    standard: standardLimiter.middleware(),
    generous: generousLimiter.middleware()
};
