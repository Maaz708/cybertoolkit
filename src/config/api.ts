// Central API configuration
// Uses environment variable or falls back to localhost

declare const __API_URL__: string;

export const API_BASE_URL = typeof __API_URL__ !== 'undefined' ? __API_URL__ : 'http://localhost:5000';

// Axios default config
export const apiConfig = {
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 seconds
};

// Helper to get auth header
export const getAuthHeader = () => {
  const token = localStorage.getItem('authToken');
  return token ? { Authorization: `Bearer ${token}` } : {};
};
