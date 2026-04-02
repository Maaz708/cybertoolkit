import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Dashboard from './components/Dashboard';
import FileAnalysis from './components/FileAnalysis';
import NetworkMonitor from './components/NetworkMonitor';
import MalwareDetection from './components/MalwareDetection';
import EmailForensics from './components/EmailForensics';
/*import CloudForensics from './components/CloudForensics';*/
import Layout from './components/Layout';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import FileRecovery from './components/FileRecovery';
import Profile from './pages/Profile';
import Settings from './pages/Settings';

// Authentication components
import { AuthProvider } from './contexts/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import Landing from './pages/Landing';
import ProtectedRoute from './components/ProtectedRoute';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    secondary: {
      main: '#f48fb1',
    },
  },
});

function App() {
  return (
    <LocalizationProvider dateAdapter={AdapterDayjs}>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <AuthProvider>
          <BrowserRouter>
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<Landing />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              
              {/* Protected Routes */}
              <Route path="/dashboard" element={
                <ProtectedRoute>
                  <Layout><Dashboard /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/file-analysis" element={
                <ProtectedRoute>
                  <Layout><FileAnalysis /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/network-monitor" element={
                <ProtectedRoute>
                  <Layout><NetworkMonitor /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/malware-detection" element={
                <ProtectedRoute>
                  <Layout><MalwareDetection /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/email-forensics" element={
                <ProtectedRoute>
                  <Layout><EmailForensics /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/file-recovery" element={
                <ProtectedRoute>
                  <Layout><FileRecovery /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/profile" element={
                <ProtectedRoute>
                  <Layout><Profile /></Layout>
                </ProtectedRoute>
              } />
              <Route path="/settings" element={
                <ProtectedRoute>
                  <Layout><Settings /></Layout>
                </ProtectedRoute>
              } />
              
              {/* Redirect legacy routes */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </ThemeProvider>
    </LocalizationProvider>
  );
}

export default App;