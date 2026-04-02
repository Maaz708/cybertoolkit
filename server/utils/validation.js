const Joi = require('joi');
const logger = require('./logger');

// Common validation schemas
const schemas = {
  // User authentication
  login: Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'Password must be at least 6 characters long',
      'any.required': 'Password is required'
    })
  }),

  register: Joi.object({
    email: Joi.string().email().required().messages({
      'string.email': 'Please provide a valid email address',
      'any.required': 'Email is required'
    }),
    password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])')).required().messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.pattern.base': 'Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character',
      'any.required': 'Password is required'
    }),
    firstName: Joi.string().min(2).max(50).required().messages({
      'string.min': 'First name must be at least 2 characters',
      'string.max': 'First name cannot exceed 50 characters',
      'any.required': 'First name is required'
    }),
    lastName: Joi.string().min(2).max(50).required().messages({
      'string.min': 'Last name must be at least 2 characters',
      'string.max': 'Last name cannot exceed 50 characters',
      'any.required': 'Last name is required'
    }),
    companyName: Joi.string().max(100).optional().messages({
      'string.max': 'Company name cannot exceed 100 characters'
    })
  }),

  // Network monitoring
  startMonitoring: Joi.object({
    interval: Joi.number().integer().min(1000).max(60000).default(3000).messages({
      'number.min': 'Interval must be at least 1000ms',
      'number.max': 'Interval must not exceed 60000ms'
    }),
    duration: Joi.number().integer().min(60000).max(3600000).optional().messages({
      'number.min': 'Duration must be at least 60 seconds',
      'number.max': 'Duration must not exceed 1 hour'
    })
  }),

  // File upload
  fileUpload: Joi.object({
    filename: Joi.string().required(),
    mimetype: Joi.string().valid('application/pdf', 'image/jpeg', 'image/png', 'text/plain', 'application/octet-stream').required().messages({
      'any.only': 'File type not supported'
    }),
    size: Joi.number().max(52428800).messages({
      'number.max': 'File size must not exceed 50MB'
    })
  }),

  // Email analysis
  emailAnalysis: Joi.object({
    emailContent: Joi.string().min(10).max(1000000).required().messages({
      'string.min': 'Email content is too short',
      'string.max': 'Email content is too long',
      'any.required': 'Email content is required'
    }),
    headers: Joi.object().optional(),
    analysisType: Joi.string().valid('phishing', 'spam', 'malware', 'forensic').default('phishing')
  }),

  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sortBy: Joi.string().optional(),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc')
  })
};

// Validation middleware factory
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const { error, value } = schemas[schema].validate(req[source], {
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorDetails = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      logger.warn('Validation Error', {
        url: req.url,
        method: req.method,
        errors: errorDetails
      });

      return res.status(400).json({
        success: false,
        error: 'Validation failed',
        details: errorDetails
      });
    }

    // Replace the request data with validated and sanitized data
    req[source] = value;
    next();
  };
};

// Custom validation functions
const validateFile = (file) => {
  const allowedMimes = [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'text/plain',
    'application/octet-stream',
    'application/zip'
  ];

  const maxSize = 50 * 1024 * 1024; // 50MB

  if (!allowedMimes.includes(file.mimetype)) {
    throw new Error(`File type ${file.mimetype} is not allowed`);
  }

  if (file.size > maxSize) {
    throw new Error('File size exceeds 50MB limit');
  }

  return true;
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  
  // Basic XSS prevention
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .trim();
};

module.exports = {
  schemas,
  validate,
  validateFile,
  sanitizeInput
};
