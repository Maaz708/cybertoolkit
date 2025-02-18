import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Dashboard from './components/Dashboard';
import FileAnalysis from './components/FileAnalysis';
import NetworkMonitor from './components/NetworkMonitor';
import MalwareDetection from './components/MalwareDetection';
import EmailForensics from './components/EmailForensics';
import CloudForensics from './components/CloudForensics';
import Navigation from './components/Navigation';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import FileRecovery from './components/FileRecovery';

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
        <BrowserRouter>
          <Navigation />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/file-analysis" element={<FileAnalysis />} />
            <Route path="/network-monitor" element={<NetworkMonitor />} />
            <Route path="/malware-detection" element={<MalwareDetection />} />
            <Route path="/email-forensics" element={<EmailForensics />} />
            <Route path="/cloud-forensics" element={<CloudForensics />} />
            <Route path="/file-recovery" element={<FileRecovery />} />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </LocalizationProvider>
  );
}

export default App;