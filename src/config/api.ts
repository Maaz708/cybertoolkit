// Central API configuration
// Uses Vite environment variable or falls back to localhost

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

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
