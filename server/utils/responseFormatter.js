/**
 * Response Formatter Utility
 * Standardizes API responses with meta information
 * NON-BREAKING: Adds meta/status while keeping existing fields
 */

const crypto = require('crypto');

class ResponseFormatter {
    constructor() {
        this.version = '1.0.0';
    }

    /**
     * Format success response
     * @param {Object} data - Response data
     * @param {Object} options - Additional options
     * @returns {Object} Formatted response
     */
    success(data, options = {}) {
        const startTime = options.startTime || Date.now();
        const responseTime = Date.now() - startTime;

        return {
            // NEW: Status field
            status: 'success',
            
            // NEW: Meta information
            meta: {
                requestId: options.requestId || this.generateRequestId(),
                responseTime: `${responseTime}ms`,
                version: this.version,
                timestamp: new Date().toISOString(),
                ...(options.meta || {})
            },
            
            // SAFE: Keep existing data structure
            ...this.preserveExistingFields(data),
            
            // NEW: Optional pagination
            ...(options.pagination ? { pagination: options.pagination } : {})
        };
    }

    /**
     * Format error response
     * @param {string|Error} error - Error message or Error object
     * @param {Object} options - Additional options
     * @returns {Object} Formatted error response
     */
    error(error, options = {}) {
        const startTime = options.startTime || Date.now();
        const responseTime = Date.now() - startTime;
        const errorMessage = error instanceof Error ? error.message : error;
        const errorCode = options.code || 'INTERNAL_ERROR';

        return {
            // NEW: Status field
            status: 'error',
            
            // NEW: Meta information
            meta: {
                requestId: options.requestId || this.generateRequestId(),
                responseTime: `${responseTime}ms`,
                version: this.version,
                timestamp: new Date().toISOString(),
                errorCode,
                ...(options.meta || {})
            },
            
            // SAFE: Keep existing error structure for compatibility
            success: false,
            error: errorMessage,
            
            // NEW: Enhanced error details (only in non-production)
            ...(process.env.NODE_ENV !== 'production' && error instanceof Error ? {
                stack: error.stack,
                details: options.details || {}
            } : {}),
            
            // NEW: User-friendly message
            message: options.userMessage || 'An error occurred while processing your request'
        };
    }

    /**
     * Format paginated response
     * @param {Array} items - Array of items
     * @param {Object} pagination - Pagination info
     * @param {Object} options - Additional options
     * @returns {Object} Formatted paginated response
     */
    paginated(items, pagination, options = {}) {
        const { page = 1, limit = 20, total = 0 } = pagination;
        
        return this.success(items, {
            ...options,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(total),
                totalPages: Math.ceil(total / limit),
                hasNext: page * limit < total,
                hasPrev: page > 1
            }
        });
    }

    /**
     * Generate unique request ID
     * @returns {string} Request ID
     */
    generateRequestId() {
        return `req_${crypto.randomBytes(8).toString('hex')}_${Date.now()}`;
    }

    /**
     * Preserve existing fields while adding new ones
     * @param {Object} data - Original data
     * @returns {Object} Data with preserved fields
     */
    preserveExistingFields(data) {
        if (typeof data !== 'object' || data === null) {
            return { data };
        }

        // If data already has 'success' field, preserve it
        if ('success' in data) {
            return data;
        }

        // If data is an array, wrap it
        if (Array.isArray(data)) {
            return { data };
        }

        return data;
    }
}

// Create singleton instance
const formatter = new ResponseFormatter();

module.exports = formatter;
module.exports.ResponseFormatter = ResponseFormatter;
